import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell, Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis
} from 'recharts';

interface DashboardProps {
  experimentData: { total: number; alta: number; media: number; baixa: number; taxaMitigacao: number };
  chartData: any[];
}

export function DashboardTab({ experimentData, chartData }: DashboardProps) {
  // Dados para o Gráfico de Pizza
  const pieData = [
    { name: 'Criticidade Alta', value: experimentData.alta },
    { name: 'Criticidade Média', value: experimentData.media },
    { name: 'Criticidade Baixa', value: experimentData.baixa },
  ].filter(d => d.value > 0);

  const PIE_COLORS = ['#ef4444', '#f59e0b', '#94a3b8']; // Vermelho, Amarelo, Cinza

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold">Resumo Executivo de Segurança</h2>
        <span className="text-sm text-slate-500">Visão Geral do Ambiente (Dados Reais)</span>
      </div>

      {/* CARDS DE KPI */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-50 border rounded-md shadow-sm">
          <p className="text-sm text-slate-500 font-medium">Total de Achados</p>
          <p className="text-3xl font-bold text-academico-primary">{experimentData.total}</p>
        </div>
        <div className="p-4 bg-red-50 border border-red-100 rounded-md shadow-sm">
          <p className="text-sm text-red-600 font-medium">Criticidade Alta (Bloqueantes)</p>
          <p className="text-3xl font-bold text-red-600">{experimentData.alta}</p>
        </div>
        <div className="p-4 bg-yellow-50 border border-yellow-100 rounded-md shadow-sm">
          <p className="text-sm text-yellow-600 font-medium">Criticidade Média</p>
          <p className="text-3xl font-bold text-yellow-600">{experimentData.media}</p>
        </div>
        <div className="p-4 bg-emerald-50 border border-emerald-100 rounded-md shadow-sm">
          <p className="text-sm text-emerald-600 font-medium">Taxa de Mitigação Global</p>
          <p className="text-3xl font-bold text-emerald-600">{experimentData.taxaMitigacao}%</p>
        </div>
      </div>

      {/* GRÁFICOS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">

        {/* Gráfico de Barras (Volume por Ferramenta) - Ocupa as duas colunas no topo */}
        <div className="lg:col-span-2 h-80 bg-white p-4 border rounded-lg shadow-sm">
          <h3 className="text-md font-medium text-slate-600 mb-4 text-center">Detecções por Etapa do Pipeline (Antes vs Depois)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
              <XAxis dataKey="categoria" axisLine={false} tickLine={false} fontSize={12} />
              <YAxis axisLine={false} tickLine={false} fontSize={12} />
              <Tooltip cursor={{ fill: '#f8fafc' }} />
              <Legend wrapperStyle={{ bottom: 0, fontSize: '12px' }} />
              <Bar dataKey="antes" name="Antes (Baseline)" fill="#94a3b8" radius={[4, 4, 0, 0]} maxBarSize={50} />
              <Bar dataKey="depois" name="Depois (Atual)" fill="#3b82f6" radius={[4, 4, 0, 0]} maxBarSize={50} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Gráfico de Pizza (Distribuição de Severidade) - Metade inferior esquerda */}
        <div className="h-80 bg-white p-4 border rounded-lg shadow-sm flex flex-col items-center">
          <h3 className="text-md font-medium text-slate-600 mb-2">Proporção de Severidade</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend wrapperStyle={{ fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex-1 flex items-center justify-center text-slate-400 text-sm">
              Nenhuma vulnerabilidade detetada.
            </div>
          )}
        </div>

        {/* Gráfico de Radar (Superfície de Ataque) - Metade inferior direita */}
        <div className="h-80 bg-white p-4 border rounded-lg shadow-sm flex flex-col items-center">
          <h3 className="text-md font-medium text-slate-600 mb-2">Superfície de Ataque por Vetor</h3>
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart cx="50%" cy="50%" outerRadius="70%" data={chartData}>
              <PolarGrid stroke="#e2e8f0" />
              <PolarAngleAxis dataKey="categoria" tick={{ fill: '#475569', fontSize: 12 }} />
              <PolarRadiusAxis angle={30} domain={[0, 'auto']} tick={{ fontSize: 10 }} />
              <Radar name="Antes (Baseline)" dataKey="antes" stroke="#94a3b8" fill="#94a3b8" fillOpacity={0.3} />
              <Radar name="Depois (Atual)" dataKey="depois" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.5} />
              <Tooltip />
              <Legend wrapperStyle={{ fontSize: '12px' }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

      </div>
    </div>
  );
}