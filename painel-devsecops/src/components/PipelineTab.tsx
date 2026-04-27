import {
  GitCommit, Search, ShieldAlert, Box, FileCode2, PlaySquare, ShieldCheck,
  CheckCircle2, AlertTriangle, XCircle
} from 'lucide-react';

interface PipelineProps {
  // Vamos receber os dados do gráfico para saber quantas falhas cada etapa teve
  chartData: { categoria: string; antes: number; depois: number }[];
  totalAlta: number;
}

export function PipelineTab({ chartData, totalAlta }: PipelineProps) {
  // Função auxiliar para procurar a quantidade de falhas por etapa
  const getIssuesCount = (categoryName: string) => {
    const stage = chartData.find(c => c.categoria === categoryName);
    return stage ? stage.antes : 0;
  };

  const sastCount = getIssuesCount('SAST');
  const scaCount = getIssuesCount('SCA');
  const dastCount = getIssuesCount('DAST');
  const trivyCount = getIssuesCount('Trivy');

  // Definição das 8 etapas do seu pipeline DevSecOps
  const pipelineStages = [
    {
      id: 1, name: 'Commit & Secrets', tool: 'GitLeaks', icon: GitCommit,
      issues: 0, status: 'pass', desc: 'Verificação de credenciais hardcoded no código.'
    },
    {
      id: 2, name: 'SAST', tool: 'Bandit', icon: Search,
      issues: sastCount, status: sastCount > 0 ? 'fail' : 'pass', desc: 'Análise Estática de falhas lógicas no Python.'
    },
    {
      id: 3, name: 'SCA', tool: 'Safety', icon: ShieldAlert,
      issues: scaCount, status: scaCount > 0 ? 'fail' : 'pass', desc: 'Análise de dependências e bibliotecas vulneráveis.'
    },
    {
      id: 4, name: 'IaC & Container Scan', tool: 'Trivy', icon: Box,
      issues: trivyCount, status: trivyCount > 0 ? 'fail' : 'pass', desc: 'Verificação de vulnerabilidades na imagem Docker.'
    },
    {
      id: 5, name: 'Build', tool: 'Docker Engine', icon: FileCode2,
      issues: 0, status: 'pass', desc: 'Compilação e empacotamento da aplicação.'
    },
    {
      id: 6, name: 'DAST', tool: 'OWASP ZAP', icon: PlaySquare,
      issues: dastCount, status: dastCount > 0 ? 'fail' : 'pass', desc: 'Ataques dinâmicos automatizados contra a API.'
    },
    {
      id: 7, name: 'Contract / OpenAPI', tool: 'Swagger Validator', icon: ShieldCheck,
      issues: 0, status: 'pass', desc: 'Validação do contrato da API RESTful.'
    },
    {
      id: 8, name: 'Security Gate', tool: 'GitHub Actions', icon: CheckCircle2,
      issues: totalAlta, status: totalAlta > 0 ? 'blocked' : 'pass', desc: 'Decisão automatizada de bloqueio do deploy.'
    },
  ];

  const getStatusStyle = (status: string) => {
    switch (status) {
      case 'pass': return 'bg-green-50 border-green-200 text-green-700';
      case 'fail': return 'bg-yellow-50 border-yellow-200 text-yellow-700';
      case 'blocked': return 'bg-red-50 border-red-200 text-red-700';
      default: return 'bg-slate-50 border-slate-200 text-slate-700';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pass': return <CheckCircle2 className="w-5 h-5 text-green-500" />;
      case 'fail': return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'blocked': return <XCircle className="w-5 h-5 text-red-500" />;
      default: return null;
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold">Orquestração do Pipeline CI/CD</h2>
        <span className="text-sm text-slate-500">Fluxo automatizado no GitHub Actions</span>
      </div>

      <div className="py-4">
        <p className="text-slate-600 mb-8 text-center max-w-3xl mx-auto">
          Representação visual do ciclo DevSecOps implementado. As etapas sinalizam alertas quando os testes de segurança detectam falhas, culminando no Security Gate que bloqueia implementações vulneráveis.
        </p>

        <div className="relative max-w-4xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 relative z-10">
            {pipelineStages.map((stage) => {
              const Icon = stage.icon;
              return (
                <div key={stage.id} className={`flex flex-col p-5 rounded-lg border-2 transition-all hover:shadow-md ${getStatusStyle(stage.status)}`}>
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center space-x-3">
                      <div className="p-2 bg-white rounded-md shadow-sm">
                        <Icon className="w-6 h-6 opacity-80" />
                      </div>
                      <div>
                        <h3 className="font-bold text-lg">Etapa {stage.id}: {stage.name}</h3>
                        <span className="text-xs font-semibold uppercase tracking-wider opacity-70">{stage.tool}</span>
                      </div>
                    </div>
                    {getStatusIcon(stage.status)}
                  </div>

                  <p className="text-sm opacity-90 mb-4 flex-grow">{stage.desc}</p>

                  <div className="pt-3 border-t border-black/10 flex justify-between items-center text-sm font-medium">
                    <span>Estado:
                      {stage.status === 'pass' && ' Aprovado'}
                      {stage.status === 'fail' && ' Alertas Detectados'}
                      {stage.status === 'blocked' && ' Deploy Bloqueado'}
                    </span>
                    {stage.issues > 0 && (
                      <span className="px-2 py-1 bg-white rounded-md shadow-sm text-red-600">
                        {stage.issues} achados
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}