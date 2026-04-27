import { useState } from 'react';
import {
  GitCommit, Search, ShieldAlert, Box, FileCode2, PlaySquare, ShieldCheck,
  ChevronDown, ChevronUp, Bug, ExternalLink
} from 'lucide-react';
import sastReport from '../data/sast_report.json';
import scaReport from '../data/sca_report.json';
import trivyReport from '../data/trivy_report.json';
import zapReport from '../data/report_json.json';

interface PipelineProps {
  chartData: { categoria: string; antes: number; depois: number }[];
  totalAlta: number;
}

export function PipelineTab({ chartData, totalAlta }: PipelineProps) {
  const [expandedStage, setExpandedStage] = useState<number | null>(null);

  const allBlockers = [
    ...(sastReport.results?.filter((f: any) => f.issue_severity === 'HIGH') || []),
    ...(scaReport.vulnerabilities?.filter((f: any) => (f.severity || '').toUpperCase() === 'HIGH') || []),
    ...(trivyReport.Results?.flatMap((r: any) => r.Vulnerabilities || []).filter((f: any) => f.Severity === 'HIGH' || f.Severity === 'CRITICAL') || []),
    ...(zapReport.site?.[0]?.alerts?.filter((f: any) => f.riskcode === '3') || [])
  ];

  const getIssuesCount = (categoryName: string) => {
    const stage = chartData.find(c => c.categoria === categoryName);
    return stage ? stage.antes : 0;
  };

  const pipelineStages = [
    { id: 1, name: 'Commit & Secrets', tool: 'GitLeaks', icon: GitCommit, issues: 0, status: 'pass', desc: 'Análise de segredos expostos.', findings: [] },
    { id: 2, name: 'SAST (Static Analysis)', tool: 'Bandit', icon: Search, issues: getIssuesCount('SAST'), status: getIssuesCount('SAST') > 0 ? 'fail' : 'pass', desc: 'Análise estática do código Python.', findings: sastReport.results || [] },
    { id: 3, name: 'SCA (Composition)', tool: 'Safety', icon: ShieldAlert, issues: getIssuesCount('SCA'), status: getIssuesCount('SCA') > 0 ? 'fail' : 'pass', desc: 'Vulnerabilidades em bibliotecas externas.', findings: scaReport.vulnerabilities || [] },
    { id: 4, name: 'Build & Container', tool: 'Docker', icon: Box, issues: 0, status: 'pass', desc: 'Geração da imagem do container.', findings: [] },
    { id: 5, name: 'Image Scanning', tool: 'Trivy', icon: FileCode2, issues: getIssuesCount('Trivy'), status: getIssuesCount('Trivy') > 0 ? 'fail' : 'pass', desc: 'Escaneamento da imagem Docker.', findings: trivyReport.Results?.flatMap((r: any) => r.Vulnerabilities || []) || [] },
    { id: 6, name: 'DAST (Dynamic Analysis)', tool: 'ZAP', icon: PlaySquare, issues: getIssuesCount('DAST'), status: getIssuesCount('DAST') > 0 ? 'fail' : 'pass', desc: 'Testes de intrusão ativos na API.', findings: zapReport.site?.[0]?.alerts || [] },
    { id: 7, name: 'Security Gate', tool: 'Policy Check', icon: ShieldCheck, issues: totalAlta, status: totalAlta > 0 ? 'blocked' : 'pass', desc: 'Bloqueio de deploys inseguros.', findings: allBlockers }
  ];

  const getStatusStyles = (status: string) => {
    switch (status) {
      case 'pass': return 'bg-green-600 text-white border-green-700';
      case 'fail': return 'bg-amber-500 text-white border-amber-600';
      case 'blocked': return 'bg-red-600 text-white border-red-700';
      default: return 'bg-slate-400 text-white border-slate-500';
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold">Orquestração da Esteira DevSecOps</h2>
        <span className="text-sm text-slate-500">Fluxo de inspeção em tempo real</span>
      </div>

      <div className="relative">
        <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-slate-200 hidden md:block"></div>
        <div className="space-y-6">
          {pipelineStages.map((stage) => {
            const Icon = stage.icon;
            const isExpanded = expandedStage === stage.id;
            const hasFindings = stage.findings.length > 0;

            return (
              <div key={stage.id} className="relative md:pl-16">
                <div className={`absolute left-6 top-6 w-4 h-4 rounded-full border-2 border-white shadow-sm z-10 hidden md:block ${stage.status === 'pass' ? 'bg-green-500' : stage.status === 'fail' ? 'bg-amber-500' : 'bg-red-500'
                  }`}></div>

                <div className={`border rounded-lg shadow-sm transition-all overflow-hidden ${isExpanded ? 'ring-2 ring-academico-primary ring-opacity-20' : 'bg-white'}`}>
                  <button
                    onClick={() => hasFindings && setExpandedStage(isExpanded ? null : stage.id)}
                    className={`w-full flex items-center justify-between p-5 focus:outline-none ${hasFindings ? 'cursor-pointer hover:bg-slate-50' : 'cursor-default'}`}
                  >
                    <div className="flex items-center space-x-4">
                      <div className={`p-3 rounded-lg ${getStatusStyles(stage.status)} shadow-sm`}>
                        <Icon className="w-6 h-6" />
                      </div>
                      <div className="text-left">
                        <div className="flex items-center">
                          <h3 className="font-bold text-slate-800">Etapa {stage.id}: {stage.name}</h3>
                          <span className="ml-3 text-[10px] font-bold uppercase px-2 py-0.5 bg-slate-100 text-slate-500 rounded border">{stage.tool}</span>
                        </div>
                        <p className="text-xs text-slate-500 mt-1">{stage.desc}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2 w-36 justify-end">
                      <div className="flex-1 flex justify-end">
                        {stage.issues > 0 && <span className="px-2.5 py-1 text-xs font-bold bg-red-50 text-red-600 rounded-md border border-red-100 whitespace-nowrap shadow-sm">{stage.issues} Alertas</span>}
                      </div>
                      <div className="w-6 flex justify-center flex-shrink-0">
                        {hasFindings ? (isExpanded ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />) : <span className="w-5 h-5"></span>}
                      </div>
                    </div>
                  </button>

                  {isExpanded && hasFindings && (
                    <div className="bg-slate-50 border-t p-5 space-y-3">
                      <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center">
                        <Bug className="w-3 h-3 mr-1" /> Vulnerabilidades Identificadas
                      </h4>
                      <div className="grid gap-3">
                        {stage.findings.map((f: any, idx: number) => {
                          const titulo = f.Title || f.name || f.test_name || (f.vulnerability_id ? `ID: ${f.vulnerability_id}` : null) || f.VulnerabilityID || "Falha Detectada";
                          const desc = f.advisory || f.issue_text || f.Description || f.desc || f.description || "Sem detalhes adicionais.";
                          const severidadeTexto = f.issue_severity || f.severity || f.Severity || (f.riskdesc ? f.riskdesc.split(' ')[0] : 'MEDIUM');
                          const severidadeCor = (severidadeTexto.toUpperCase().includes('HIGH') || severidadeTexto.toUpperCase().includes('CRITICAL'));

                          // Lógica de Link Externo (Baseado em cada ferramenta)
                          // 1. Tenta pegar a URL direta se existir
                          let linkRef = f.more_info || f.PrimaryURL;

                          // 2. Se for ZAP, extrai o primeiro link real de dentro do texto/HTML
                          if (!linkRef && f.reference) {
                            const urlMatch = String(f.reference).match(/https?:\/\/[^\s"'<]+/);
                            if (urlMatch) linkRef = urlMatch[0];
                          }

                          // 3. Fallbacks inteligentes para ferramentas que só enviam o ID
                          if (!linkRef) {
                            if (f.VulnerabilityID) { // Trivy
                              linkRef = `https://avd.aquasec.com/nvd/${f.VulnerabilityID.toLowerCase()}`;
                            } else if (f.vulnerability_id) { // Safety (SCA)
                              // A OSV.dev é a melhor base para pesquisar IDs de bibliotecas Python
                              linkRef = `https://osv.dev/list?q=${f.vulnerability_id}`;
                            } else if (f.test_id) { // Bandit (SAST)
                              linkRef = `https://bandit.readthedocs.io/en/latest/search.html?q=${f.test_id}`;
                            } else {
                              // Último recurso: Gera uma busca direta para o erro no Google
                              linkRef = `https://www.google.com/search?q=${encodeURIComponent('vulnerability ' + titulo)}`;
                            }
                          }

                          return (
                            <div key={idx} className="bg-white p-3 rounded border border-slate-200 shadow-sm flex flex-col space-y-2">
                              <div className="flex justify-between items-start">
                                <div className="text-xs space-y-1">
                                  <p className="font-bold text-slate-700">{titulo}</p>
                                  <p className="text-slate-500 italic leading-relaxed">{desc}</p>
                                </div>
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded text-white shadow-sm uppercase ${severidadeCor ? 'bg-red-500' : 'bg-amber-500'}`}>
                                  {severidadeTexto}
                                </span>
                              </div>

                              <div className="flex items-center justify-between pt-2 border-t border-slate-100">
                                <div className="text-[10px] text-slate-400 font-mono">
                                  {f.file && `Local: ${f.file}:${f.line_number}`}
                                  {f.PkgName && `Pacote: ${f.PkgName}`}
                                </div>
                                {linkRef && (
                                  <a
                                    href={linkRef}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-academico-primary hover:underline flex items-center text-[10px] font-bold"
                                  >
                                    <ExternalLink className="w-3 h-3 mr-1" /> MAIS INFORMAÇÕES
                                  </a>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}