import { useState } from 'react';
import { ChevronDown, ChevronUp, CheckCircle, XCircle } from 'lucide-react';

interface OwaspProps {
  categories: { id: string; title: string; desc: string }[];
  mapping: Record<string, { detected: boolean; tools: string[]; evidences: any[] }>;
}

export function OwaspTab({ categories, mapping }: OwaspProps) {
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const toggleRow = (id: string) => {
    setExpandedRow(expandedRow === id ? null : id);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold">Mapeamento OWASP API Security Top 10 (2023)</h2>
        <span className="text-sm text-slate-500">Mapeamento heurístico a partir dos logs de pipeline</span>
      </div>

      <div className="flex flex-col border rounded-md overflow-hidden">
        {categories.map((cat) => {
          const data = mapping[cat.id];
          const isExpanded = expandedRow === cat.id;

          return (
            <div key={cat.id} className="border-b last:border-b-0">
              <button
                onClick={() => toggleRow(cat.id)}
                className="w-full flex items-center justify-between p-4 bg-white hover:bg-slate-50 transition-colors text-left"
              >
                <div className="flex items-center space-x-4 w-2/3">
                  {data.detected ? (
                    <XCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0" />
                  )}
                  <div>
                    <p className={`font-medium ${data.detected ? 'text-slate-900' : 'text-slate-500'}`}>{cat.title}</p>
                    <p className="text-sm text-slate-500 truncate">{cat.desc}</p>
                  </div>
                </div>

                <div className="flex items-center space-x-6">
                  <span className={`text-sm font-semibold px-3 py-1 rounded-full ${data.detected ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                    {data.detected ? 'Detectado' : 'Seguro'}
                  </span>
                  {isExpanded ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </div>
              </button>

              {isExpanded && (
                <div className="p-6 bg-slate-50 border-t border-slate-100">
                  <h4 className="text-sm font-bold text-slate-700 mb-4 uppercase tracking-wider">Evidências de Falha</h4>

                  {!data.detected ? (
                    <p className="text-sm text-slate-500 italic">Nenhuma vulnerabilidade correspondente a esta categoria foi identificada no ciclo atual.</p>
                  ) : (
                    <div className="space-y-4">
                      <p className="text-sm text-slate-700">
                        <span className="font-semibold">Ferramentas que detectaram:</span> {data.tools.join(', ')}
                      </p>

                      <div className="max-h-64 overflow-y-auto bg-white border rounded-md p-4 space-y-3">
                        {data.evidences.map((ev, idx) => (
                          <div key={idx} className="text-sm border-l-4 border-red-400 pl-3 py-1">
                            <p className="font-semibold text-slate-800">{ev.name || ev.test_name || 'Vulnerabilidade Genérica'}</p>
                            <p className="text-slate-600 mt-1">
                              <span className="font-medium text-slate-500">Severidade:</span> {ev.riskdesc || ev.issue_severity || ev.severity || 'HIGH'}
                            </p>
                            {ev.uri && <p className="text-slate-600 font-mono text-xs mt-1 break-all bg-slate-100 p-1 rounded">URL: {ev.uri}</p>}
                            {ev.file && <p className="text-slate-600 font-mono text-xs mt-1 break-all bg-slate-100 p-1 rounded">Arquivo: {ev.file} (Linha {ev.line_number})</p>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}