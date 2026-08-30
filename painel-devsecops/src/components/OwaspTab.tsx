import { useState } from 'react';
import { ChevronDown, ChevronUp, CheckCircle, XCircle, AlertTriangle, CircleHelp, ExternalLink, Lightbulb } from 'lucide-react';
import type { OwaspMapping, OwaspStatus } from '../constants/owsap';

interface OwaspProps {
  categories: { id: string; title: string; desc: string }[];
  mapping: Record<string, OwaspMapping>;
}

const statusLabel: Record<OwaspStatus, string> = {
  vulnerable: 'VULNERÁVEL',
  partially_mitigated: 'MITIGAÇÃO PARCIAL',
  mitigated: 'MITIGADA',
  not_assessed: 'NÃO AVALIADA',
};

export function OwaspTab({ categories, mapping }: OwaspProps) {
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const toggleRow = (id: string) => {
    setExpandedRow(expandedRow === id ? null : id);
  };

  // Função auxiliar para remover tags HTML que o ZAP costuma enviar na "solution"
  const stripHtml = (html: string) => {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    return doc.body.textContent || "";
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold">Mapeamento OWASP API Security Top 10 (2023)</h2>
        <span className="text-sm text-slate-500">Evidências do laboratório e achados ativos do pipeline</span>
      </div>

      <div className="flex flex-col border rounded-md overflow-hidden shadow-sm">
        {categories.map((cat) => {
          const data = mapping[cat.id];
          const isExpanded = expandedRow === cat.id;

          return (
            <div key={cat.id} className="border-b last:border-b-0 bg-white">
              <button
                onClick={() => toggleRow(cat.id)}
                className="w-full flex items-center justify-between p-4 hover:bg-slate-50 transition-colors focus:outline-none"
              >
                <div className="flex items-center space-x-4">
                  {data.status === 'vulnerable' && <XCircle className="w-6 h-6 text-red-500 flex-shrink-0" />}
                  {data.status === 'partially_mitigated' && <AlertTriangle className="w-6 h-6 text-amber-500 flex-shrink-0" />}
                  {data.status === 'mitigated' && <CheckCircle className="w-6 h-6 text-green-500 flex-shrink-0" />}
                  {data.status === 'not_assessed' && <CircleHelp className="w-6 h-6 text-slate-400 flex-shrink-0" />}
                  <div className="text-left">
                    <h3 className={`font-semibold ${data.status === 'vulnerable' ? 'text-red-700' : data.status === 'partially_mitigated' ? 'text-amber-700' : 'text-slate-700'}`}>
                      {cat.title}
                    </h3>
                    <p className="text-sm text-slate-500 mt-0.5">{cat.desc}</p>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  <span className={`px-2.5 py-1 text-xs font-bold rounded-full ${data.status === 'vulnerable' ? 'bg-red-100 text-red-700' : data.status === 'partially_mitigated' ? 'bg-amber-100 text-amber-700' : data.status === 'mitigated' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-600'}`}>
                    {statusLabel[data.status]}
                  </span>
                  {data.evidences.length > 0 && (
                    <span className="px-2.5 py-1 text-xs font-bold bg-slate-100 text-slate-600 rounded-full">
                      {data.evidences.length} Evidências
                    </span>
                  )}
                  {isExpanded ? (
                    <ChevronUp className="w-5 h-5 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-slate-400" />
                  )}
                </div>
              </button>

              {isExpanded && data.evidences.length > 0 && (
                <div className="p-6 bg-slate-50 border-t">
                  <div className="space-y-6">
                    <p className={`text-sm px-3 py-2 rounded-md border ${data.status === 'vulnerable' ? 'text-red-700 bg-red-50 border-red-200' : data.status === 'partially_mitigated' ? 'text-amber-700 bg-amber-50 border-amber-200' : data.status === 'mitigated' ? 'text-green-700 bg-green-50 border-green-200' : 'text-slate-600 bg-white border-slate-200'}`}>
                      {data.status === 'vulnerable' && 'A vulnerabilidade foi confirmada por evidência de laboratório ou achado ativo de scanner.'}
                      {data.status === 'partially_mitigated' && 'Há controles implementados, mas a categoria ainda não foi totalmente mitigada.'}
                      {data.status === 'mitigated' && 'A categoria foi marcada como mitigada conforme os controles e testes registrados.'}
                      {data.status === 'not_assessed' && 'Não há evidência suficiente para concluir o estado desta categoria.'}
                    </p>
                    <p className="text-sm text-slate-700 bg-white inline-block px-3 py-1.5 rounded-md border shadow-sm">
                      <span className="font-semibold text-slate-800">Detetado por:</span> {data.tools.join(' / ')}
                    </p>

                    <div className="space-y-4">
                      {data.evidences.map((ev, idx) => {
                        // 1. Definição do título para fallback de pesquisa
                        const titulo = ev.Title || ev.name || ev.test_name || "Alerta de Segurança";

                        // 2. Geração Inteligente de Link (Mesma lógica do PipelineTab)
                        let linkRef = ev.more_info || ev.PrimaryURL;

                        if (!linkRef && ev.reference) {
                          const urlMatch = String(ev.reference).match(/https?:\/\/[^\s"'<]+/);
                          if (urlMatch) linkRef = urlMatch[0];
                        }

                        if (!linkRef) {
                          if (ev.VulnerabilityID) {
                            linkRef = `https://avd.aquasec.com/nvd/${ev.VulnerabilityID.toLowerCase()}`;
                          } else if (ev.vulnerability_id) {
                            linkRef = `https://osv.dev/list?q=${ev.vulnerability_id}`;
                          } else if (ev.test_id) {
                            linkRef = `https://bandit.readthedocs.io/en/latest/search.html?q=${ev.test_id}`;
                          } else {
                            linkRef = `https://www.google.com/search?q=${encodeURIComponent('vulnerability ' + titulo)}`;
                          }
                        }

                        return (
                          <div key={idx} className="bg-white border rounded-lg shadow-sm overflow-hidden flex flex-col">
                            <div className="bg-red-50 border-b border-red-100 px-4 py-3 flex justify-between items-center">
                              <p className="font-bold text-red-800 text-sm">{titulo}</p>
                              <span className="text-xs font-bold px-2 py-1 bg-white text-red-600 rounded shadow-sm border border-red-100 uppercase">
                                Severidade: {ev.riskdesc || ev.issue_severity || ev.severity || 'HIGH'}
                              </span>
                            </div>

                            <div className="p-4 text-sm space-y-3 flex-grow">
                              {/* Detalhe do Erro (Bandit ou ZAP) */}
                              {ev.issue_text && (
                                <p className="text-slate-700"><span className="font-semibold">Problema:</span> {ev.issue_text}</p>
                              )}
                              {ev.desc && (
                                <p className="text-slate-700"><span className="font-semibold">Descrição:</span> {stripHtml(ev.desc)}</p>
                              )}

                              {/* Solução Sugerida (ZAP) */}
                              {ev.solution && (
                                <div className="bg-blue-50 border border-blue-100 p-3 rounded-md mt-2 flex items-start">
                                  <Lightbulb className="w-5 h-5 text-blue-500 mr-2 flex-shrink-0 mt-0.5" />
                                  <p className="text-blue-800">
                                    <span className="font-semibold">Recomendação:</span> {stripHtml(ev.solution)}
                                  </p>
                                </div>
                              )}

                              {/* Rastreabilidade (Onde está o erro) */}
                              <div className="bg-slate-100 p-2 rounded text-xs font-mono text-slate-600 break-all mt-3">
                                {ev.uri && <div><span className="font-semibold text-slate-500">Endpoint:</span> {ev.uri}</div>}
                                {ev.file && <div><span className="font-semibold text-slate-500">Ficheiro:</span> {ev.file} (Linha {ev.line_number})</div>}
                              </div>
                            </div>

                            {/* Rodapé com Link Externo */}
                            <div className="bg-slate-50 px-4 py-3 border-t flex justify-end">
                              <a
                                href={linkRef}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-academico-primary hover:underline inline-flex items-center text-xs font-bold uppercase tracking-wider"
                              >
                                <ExternalLink className="w-3.5 h-3.5 mr-1.5" /> Documentação Técnica
                              </a>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {isExpanded && data.evidences.length === 0 && (
                <div className="p-6 bg-slate-50 border-t text-center text-slate-600 text-sm">
                  Esta categoria não possui evidência registrada para o ciclo atual e não deve ser considerada mitigada.
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
