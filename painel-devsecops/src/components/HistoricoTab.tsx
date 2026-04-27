import {
  Clock, Activity, CheckCircle, AlertTriangle
} from 'lucide-react';
import historyData from '../data/history.json';

export function HistoricoTab() {
  // Invertemos o array para mostrar a execução mais recente no topo
  const historicoOrdenado = [...historyData].reverse();

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold flex items-center">
          <Activity className="w-6 h-6 mr-2 text-slate-700" />
          Logs de Auditoria CI/CD
        </h2>
        <span className="text-sm text-slate-500">Histórico de Execuções do Pipeline</span>
      </div>

      <p className="text-slate-600 text-sm">
        Registo contínuo das análises de segurança. Este log garante a rastreabilidade das vulnerabilidades ao longo do ciclo de vida do desenvolvimento.
      </p>

      {historicoOrdenado.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-12 bg-slate-50 rounded-lg border border-dashed border-slate-300">
          <Clock className="w-12 h-12 text-slate-300 mb-3" />
          <p className="text-slate-500 font-medium">Nenhum log de execução registado ainda.</p>
          <p className="text-sm text-slate-400">Faça o primeiro push no repositório para gerar o histórico.</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg border border-slate-200 overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-50 text-slate-600 font-medium border-b border-slate-200">
                <tr>
                  <th className="px-6 py-4 flex items-center">
                    <Clock className="w-4 h-4 mr-2" /> Data e Hora (UTC)
                  </th>
                  <th className="px-6 py-4 text-center" title="Static Application Security Testing">SAST (Código)</th>
                  <th className="px-6 py-4 text-center" title="Software Composition Analysis">SCA (Dependências)</th>
                  <th className="px-6 py-4 text-center" title="Container Scan">IaC (Infra/Docker)</th>
                  <th className="px-6 py-4 text-center" title="Dynamic Application Security Testing">DAST (API Ativa)</th>
                  <th className="px-6 py-4 text-center border-l border-slate-200">Total Detectado</th>
                  <th className="px-6 py-4 text-center">Status do Gate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {historicoOrdenado.map((log: any, idx: number) => {
                  const dataFormatada = new Date(log.date).toLocaleString('pt-BR', {
                    day: '2-digit', month: '2-digit', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', second: '2-digit'
                  });

                  const isVulneravel = log.total > 0;

                  return (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="px-6 py-4 font-mono text-slate-700 whitespace-nowrap">
                        {dataFormatada}
                      </td>

                      <td className="px-6 py-4 text-center font-medium">
                        <span className={log.sast > 0 ? 'text-red-600' : 'text-slate-400'}>{log.sast}</span>
                      </td>
                      <td className="px-6 py-4 text-center font-medium">
                        <span className={log.sca > 0 ? 'text-red-600' : 'text-slate-400'}>{log.sca}</span>
                      </td>
                      <td className="px-6 py-4 text-center font-medium">
                        <span className={log.trivy > 0 ? 'text-red-600' : 'text-slate-400'}>{log.trivy}</span>
                      </td>
                      <td className="px-6 py-4 text-center font-medium">
                        <span className={log.dast > 0 ? 'text-red-600' : 'text-slate-400'}>{log.dast}</span>
                      </td>

                      <td className="px-6 py-4 text-center border-l border-slate-100">
                        <span className={`inline-flex items-center justify-center px-2.5 py-1 rounded-full font-bold text-xs ${isVulneravel ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                          {log.total}
                        </span>
                      </td>

                      <td className="px-6 py-4">
                        <div className="flex items-center justify-center">
                          {isVulneravel ? (
                            <span className="flex items-center text-red-600 text-xs font-semibold bg-red-50 px-2 py-1 rounded border border-red-100">
                              <AlertTriangle className="w-3.5 h-3.5 mr-1" /> BLOQUEADO
                            </span>
                          ) : (
                            <span className="flex items-center text-green-600 text-xs font-semibold bg-green-50 px-2 py-1 rounded border border-green-100">
                              <CheckCircle className="w-3.5 h-3.5 mr-1" /> APROVADO
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}