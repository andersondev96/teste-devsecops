import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface DashboardProps {
  experimentData: { total: number; alta: number; media: number; baixa: number; taxaMitigacao: number };
  chartData: any[];
}

export function DashboardTab({ experimentData, chartData }: DashboardProps) {
  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <h2 className="text-xl font-semibold border-b pb-2">Métricas do Experimento (API Vulnerável)</h2>

      {/* CARDS DE KPI */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-50 border rounded-md">
          <p className="text-sm text-slate-500 font-medium">Total de Falhas Detectadas</p>
          <p className="text-3xl font-bold text-academico-primary">{experimentData.total}</p>
        </div>
        <div className="p-4 bg-red-50 border border-red-100 rounded-md">
          <p className="text-sm text-red-600 font-medium">Criticidade Alta</p>
          <p className="text-3xl font-bold text-severidade-alta">{experimentData.alta}</p>
        </div>
        <div className="p-4 bg-yellow-50 border border-yellow-100 rounded-md">
          <p className="text-sm text-yellow-600 font-medium">Criticidade Média</p>
          <p className="text-3xl font-bold text-severidade-media">{experimentData.media}</p>
        </div>
        <div className="p-4 bg-slate-100 border border-slate-200 rounded-md">
          <p className="text-sm text-slate-600 font-medium">Taxa de Mitigação (Sucesso)</p>
          <p className="text-3xl font-bold text-slate-400">{experimentData.taxaMitigacao}%</p>
        </div>
      </div>

      {/* GRÁFICO RECHARTS */}
      <div className="h-80 w-full mt-8">
        <h3 className="text-md font-medium text-slate-600 mb-4 text-center">Volume de Vulnerabilidades por Vetor de Análise</h3>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
            <XAxis dataKey="categoria" axisLine={false} tickLine={false} />
            <YAxis axisLine={false} tickLine={false} />
            <Tooltip cursor={{fill: '#f1f5f9'}} />
            <Legend />
            <Bar dataKey="antes" name="Volume Encontrado" fill="#ef4444" radius={[4, 4, 0, 0]} />
            <Bar dataKey="depois" name="Após Mitigação (Pendente)" fill="#cbd5e1" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}