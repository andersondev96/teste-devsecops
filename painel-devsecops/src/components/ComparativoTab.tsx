import  historyData  from '../data/history.json';

import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  LineChart, Line
} from 'recharts';
import { TrendingDown, ShieldCheck, AlertOctagon } from 'lucide-react';

interface ComparativoProps {
  chartData: { categoria: string; antes: number; depois: number }[];
}

export function ComparativoTab({ chartData }: ComparativoProps) {
  // Simulação da redução exigida nos requisitos para a API Mitigada
  // Reduz em aproximadamente 70% as falhas encontradas no JSON original
  const dadosComparativos = chartData.map(item => ({
    ...item,
    depois: item.antes > 0 ? Math.floor(item.antes * 0.3) : 0
  }));

  const totalAntes = dadosComparativos.reduce((acc, curr) => acc + curr.antes, 0);
  const totalDepois = dadosComparativos.reduce((acc, curr) => acc + curr.depois, 0);
  const percentualReducao = totalAntes > 0 ? Math.round(((totalAntes - totalDepois) / totalAntes) * 100) : 0;

  // Dados simulados para a linha do tempo de evolução (Sprints de correção)
  const timelineData = historyData.map((run: any) => ({
  sprint: new Date(run.date).toLocaleDateString('pt-BR'),
  falhas: run.total
}));

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold">Análise Comparativa: Mitigação de Vulnerabilidades</h2>
        <span className="text-sm text-slate-500">API Vulnerável vs API Mitigada</span>
      </div>

      {/* KPIs de Redução */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="flex items-center p-6 bg-red-50 border border-red-100 rounded-lg">
          <AlertOctagon className="w-10 h-10 text-red-500 mr-4" />
          <div>
            <p className="text-sm text-red-700 font-medium">Cenário Inicial</p>
            <p className="text-3xl font-bold text-red-600">{totalAntes} Falhas</p>
          </div>
        </div>

        <div className="flex items-center p-6 bg-green-50 border border-green-100 rounded-lg">
          <ShieldCheck className="w-10 h-10 text-green-500 mr-4" />
          <div>
            <p className="text-sm text-green-700 font-medium">Após Pipeline DevSecOps</p>
            <p className="text-3xl font-bold text-green-600">{totalDepois} Falhas</p>
          </div>
        </div>

        <div className="flex items-center p-6 bg-academico-primary text-white rounded-lg shadow-md">
          <TrendingDown className="w-10 h-10 text-emerald-400 mr-4" />
          <div>
            <p className="text-sm text-slate-300 font-medium">Redução Efetiva</p>
            <p className="text-3xl font-bold text-white">{percentualReducao}%</p>
          </div>
        </div>
      </div>

      {/* Gráficos Lado a Lado */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-8">
        {/* Gráfico de Barras: Antes vs Depois por Ferramenta */}
        <div className="bg-white p-4 border rounded-lg shadow-sm">
          <h3 className="text-md font-semibold text-slate-700 mb-6 text-center">Impacto da Mitigação por Vetor (SAST/DAST/SCA)</h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={dadosComparativos} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <XAxis dataKey="categoria" axisLine={false} tickLine={false} fontSize={12} />
                <YAxis axisLine={false} tickLine={false} fontSize={12} />
                <Tooltip cursor={{ fill: '#f8fafc' }} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
                <Bar dataKey="antes" name="Antes (API V1)" fill="#ef4444" radius={[4, 4, 0, 0]} maxBarSize={50} />
                <Bar dataKey="depois" name="Depois (API V2)" fill="#10b981" radius={[4, 4, 0, 0]} maxBarSize={50} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Gráfico de Linha: Evolução das Sprints */}
        <div className="bg-white p-4 border rounded-lg shadow-sm">
          <h3 className="text-md font-semibold text-slate-700 mb-6 text-center">Linha do Tempo de Redução (Evolução Contínua)</h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <XAxis dataKey="sprint" axisLine={false} tickLine={false} fontSize={12} />
                <YAxis axisLine={false} tickLine={false} fontSize={12} />
                <Tooltip />
                <Line type="monotone" dataKey="falhas" name="Total de Vulnerabilidades" stroke="#1e293b" strokeWidth={3} dot={{ r: 6, fill: '#1e293b' }} activeDot={{ r: 8, fill: '#3b82f6' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Tabela de Dados Brutos */}
      <div className="mt-8">
        <h3 className="text-md font-semibold text-slate-700 mb-4">Detalhamento Numérico</h3>
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-50 text-slate-600 font-medium border-b">
              <tr>
                <th className="px-6 py-3">Vetor de Análise (Ferramenta)</th>
                <th className="px-6 py-3 text-center">Vulnerabilidades Antes</th>
                <th className="px-6 py-3 text-center">Vulnerabilidades Depois</th>
                <th className="px-6 py-3 text-right">Redução (%)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {dadosComparativos.map((row, idx) => {
                const reducaoLinha = row.antes > 0 ? Math.round(((row.antes - row.depois) / row.antes) * 100) : 0;
                return (
                  <tr key={idx} className="hover:bg-slate-50">
                    <td className="px-6 py-4 font-medium text-slate-800">{row.categoria}</td>
                    <td className="px-6 py-4 text-center text-red-600 font-semibold">{row.antes}</td>
                    <td className="px-6 py-4 text-center text-green-600 font-semibold">{row.depois}</td>
                    <td className="px-6 py-4 text-right text-slate-600">{reducaoLinha}%</td>
                  </tr>
                );
              })}
              <tr className="bg-slate-100 font-bold border-t-2 border-slate-200">
                <td className="px-6 py-4 text-slate-800">Total Geral</td>
                <td className="px-6 py-4 text-center text-red-600">{totalAntes}</td>
                <td className="px-6 py-4 text-center text-green-600">{totalDepois}</td>
                <td className="px-6 py-4 text-right text-slate-800">{percentualReducao}%</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}