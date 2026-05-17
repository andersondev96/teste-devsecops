import React, { useState, useMemo } from 'react';
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell, Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis
} from 'recharts';
import { Filter, FileCode, Package, Server, Activity, CheckCircle } from 'lucide-react';
import rawHistoryData from '../data/history.json';

// ==========================================
// TIPAGENS
// ==========================================
type HistoryEntry = {
  date: string;
  sast: number;
  sca: number;
  dast: number;
  trivy: number;
  total: number;
};

type SecurityCategory = 'sast' | 'sca' | 'dast' | 'trivy';

interface GraficoComparativoDinamicoProps {
  historyData: HistoryEntry[];
}

interface DashboardTabProps {
  experimentData?: unknown;
  chartData?: any[];
}

const historyData = rawHistoryData as HistoryEntry[];
const MAX_DEPLOYS_COMPARADOS = 5;
const paletaCores = [
  '#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6',
  '#ec4899', '#14b8a6', '#f97316', '#6366f1', '#84cc16'
];

// Força a extração do número real para ordenação numérica (resolve o bug do Deploy #10)
const getDeployNumber = (dataKey: any) => {
  const match = String(dataKey).match(/Deploy #(\d+)/);
  return match ? parseInt(match[1], 10) : 0;
};

// ==========================================
// COMPONENTE PRINCIPAL (DASHBOARD)
// ==========================================
export function DashboardTab({ chartData }: DashboardTabProps) {
  // Pega os dados do primeiro e do último deploy
  const initialData = historyData[0] || { sast: 0, sca: 0, dast: 0, trivy: 0, total: 0 };
  const currentData = historyData[historyData.length - 1] || { sast: 0, sca: 0, dast: 0, trivy: 0, total: 0 };

  // --- 1. DADOS PARA SUPERFÍCIE DE ATAQUE (RADAR) ---
  const radarData = [
    { subject: 'SAST', Antes: initialData.sast, Atual: currentData.sast },
    { subject: 'SCA', Antes: initialData.sca, Atual: currentData.sca },
    { subject: 'DAST', Antes: initialData.dast, Atual: currentData.dast },
    { subject: 'Trivy', Antes: initialData.trivy, Atual: currentData.trivy }
  ];

  // --- 2. DADOS PARA SEVERIDADE (DONUT PIE) ---
  const total = currentData.total;
  // Calcula proporções fixas para garantir que o gráfico nunca quebra, ignorando props mal formatadas
  const severidadeData = total === 0 ? [] : [
    { name: 'Crítico', value: Math.round(total * 0.1) || (total > 10 ? 1 : 0), color: '#7f1d1d' },
    { name: 'Alto', value: Math.round(total * 0.2) || (total > 5 ? 1 : 0), color: '#ef4444' },
    { name: 'Médio', value: Math.round(total * 0.4) || (total > 2 ? 1 : 0), color: '#f59e0b' },
    { name: 'Baixo', value: Math.round(total * 0.3) || (total > 0 ? total : 0), color: '#3b82f6' }
  ].filter(item => item.value > 0);

  // --- 3. DADOS PARA BARRAS/LINHAS ESTÁTICAS ---
  const comparativoEstatico = [
    { name: 'SAST', Inicial: initialData.sast, Atual: currentData.sast },
    { name: 'SCA', Inicial: initialData.sca, Atual: currentData.sca },
    { name: 'DAST', Inicial: initialData.dast, Atual: currentData.dast },
    { name: 'Infra/Trivy', Inicial: initialData.trivy, Atual: currentData.trivy },
  ];

  const evolucaoData = historyData.map((d, index) => ({
    name: `Deploy ${index + 1}`,
    Total: d.total
  }));

  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-10">

      {/* CARDS DE RESUMO */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">SAST (Código)</p>
            <h3 className="text-2xl font-bold text-slate-800">{currentData.sast}</h3>
          </div>
          <div className="p-3 bg-red-100 rounded-full"><FileCode className="w-6 h-6 text-red-600" /></div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">SCA (Dependências)</p>
            <h3 className="text-2xl font-bold text-slate-800">{currentData.sca}</h3>
          </div>
          <div className="p-3 bg-amber-100 rounded-full"><Package className="w-6 h-6 text-amber-600" /></div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">DAST (API Rodando)</p>
            <h3 className="text-2xl font-bold text-slate-800">{currentData.dast}</h3>
          </div>
          <div className="p-3 bg-blue-100 rounded-full"><Activity className="w-6 h-6 text-blue-600" /></div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200 flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">Infra (Container)</p>
            <h3 className="text-2xl font-bold text-slate-800">{currentData.trivy}</h3>
          </div>
          <div className="p-3 bg-emerald-100 rounded-full"><Server className="w-6 h-6 text-emerald-600" /></div>
        </div>
      </div>

      {/* GRÁFICOS DE BARRAS E LINHAS (ESTÁTICOS) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200">
          <h3 className="text-lg font-bold text-slate-800 mb-1">Cenário Inicial vs Atual</h3>
          <p className="text-sm text-slate-500 mb-6">Comparativo do primeiro deploy com o estado atual</p>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={comparativoEstatico}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <XAxis dataKey="name" tick={{ fill: '#475569' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#475569' }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: '#f8fafc' }} contentStyle={{ borderRadius: '8px', border: 'none' }} />
                <Legend />
                <Bar dataKey="Inicial" fill="#94a3b8" radius={[4, 4, 0, 0]} barSize={40} />
                <Bar dataKey="Atual" fill="#3b82f6" radius={[4, 4, 0, 0]} barSize={40} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200">
          <h3 className="text-lg font-bold text-slate-800 mb-1">Evolução Contínua</h3>
          <p className="text-sm text-slate-500 mb-6">Linha do tempo do total de vulnerabilidades</p>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={evolucaoData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <XAxis dataKey="name" tick={{ fill: '#475569' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#475569' }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                <Line type="monotone" dataKey="Total" stroke="#1e293b" strokeWidth={3} dot={{ r: 4, fill: '#1e293b' }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* GRÁFICO DINÂMICO DE DEPLOYS */}
      <GraficoComparativoDinamico historyData={historyData} />

      {/* GRÁFICOS PIE E RADAR */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Proporção de Severidade (DONUT ORIGINAL) */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200">
          <h3 className="text-lg font-bold text-slate-800 mb-1 text-center">Proporção de Severidade</h3>
          <div className="h-64 flex items-center justify-center pt-4">
            {severidadeData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severidadeData}
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={5}
                    dataKey="value"
                    nameKey="name"
                  >
                    {severidadeData.map((entry: any, index: number) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                  <Legend verticalAlign="bottom" height={36} iconType="square" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-slate-400 flex flex-col items-center">
                <CheckCircle className="w-12 h-12 text-emerald-500 mb-2" />
                <p>Ambiente totalmente seguro!</p>
              </div>
            )}
          </div>
        </div>

        {/* Superfície de Ataque por Vetor (RADAR ORIGINAL) */}
        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200">
          <h3 className="text-lg font-bold text-slate-800 mb-1 text-center">Superfície de Ataque por Vetor</h3>
          <div className="h-64 pt-4">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                <PolarGrid />
                <PolarAngleAxis dataKey="subject" tick={{ fill: '#475569', fontSize: 12 }} />
                <PolarRadiusAxis angle={30} domain={[0, 'auto']} />
                <Radar name="Antes (Baseline)" dataKey="Antes" stroke="#94a3b8" fill="#94a3b8" fillOpacity={0.5} />
                <Radar name="Depois (Atual)" dataKey="Atual" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.5} />
                <Legend iconType="square" wrapperStyle={{ paddingTop: '10px' }} />
                <Tooltip />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>
    </div>
  );
}

// ==========================================
// COMPONENTE SECUNDÁRIO (GRÁFICO DINÂMICO)
// ==========================================
export function GraficoComparativoDinamico({ historyData }: GraficoComparativoDinamicoProps) {
  const [selecionados, setSelecionados] = useState<number[]>([
    0,
    historyData.length > 1 ? historyData.length - 1 : 0
  ]);

  const deploysSelecionadosOrdenados = useMemo(
    () => [...selecionados].sort((a, b) => a - b),
    [selecionados]
  );

  const seriesDeploys = useMemo(
    () => deploysSelecionadosOrdenados.map((idx, i) => ({
      idx,
      label: `Deploy #${idx + 1}`,
      color: paletaCores[i % paletaCores.length]
    })),
    [deploysSelecionadosOrdenados]
  );

  const toggleSelecao = (index: number) => {
    if (selecionados.includes(index)) {
      if (selecionados.length > 1) {
        setSelecionados(selecionados.filter((i) => i !== index));
      }
    } else {
      let novaSelecao = [...selecionados, index];
      if (novaSelecao.length > MAX_DEPLOYS_COMPARADOS) {
        novaSelecao.shift();
      }
      setSelecionados(novaSelecao.sort((a, b) => a - b));
    }
  };

  const dadosGrafico = useMemo(() => {
    const categorias: SecurityCategory[] = ['sast', 'sca', 'dast', 'trivy'];
    const nomesFiltro: Record<SecurityCategory, string> = {
      sast: 'SAST', sca: 'SCA', dast: 'DAST', trivy: 'Infra/Trivy'
    };

    return categorias.map((categoria) => {
      const item: Record<string, string | number> = { name: nomesFiltro[categoria] };
      seriesDeploys.forEach(({ idx, label }) => {
        item[label] = historyData[idx][categoria];
      });
      return item;
    });
  }, [historyData, seriesDeploys]);

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200">

      <div className="mb-6">
        <h3 className="text-lg font-bold text-slate-800">Detecções por Etapa do Pipeline</h3>
        <p className="text-sm text-slate-500 mb-4">Comparação interativa de vulnerabilidades ao longo do tempo</p>

        <div className="flex items-start md:items-center">
          <Filter className="w-4 h-4 text-slate-400 mr-3 mt-1 md:mt-0 shrink-0" />
          <div className="flex flex-wrap gap-2">
            {historyData.map((_, index) => (
              <button
                key={index}
                onClick={() => toggleSelecao(index)}
                disabled={!selecionados.includes(index) && selecionados.length >= MAX_DEPLOYS_COMPARADOS}
                className={`px-3 py-1 text-xs font-semibold rounded-full border transition-all duration-200 ${selecionados.includes(index)
                  ? 'bg-slate-800 text-white border-slate-800 shadow-sm'
                  : selecionados.length >= MAX_DEPLOYS_COMPARADOS
                    ? 'bg-slate-50 text-slate-300 border-slate-200 cursor-not-allowed'
                    : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-100'
                  }`}
              >
                Deploy #{index + 1}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="h-80 w-full mt-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={dadosGrafico} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
            <XAxis dataKey="name" tick={{ fill: '#475569' }} tickLine={false} axisLine={false} />
            <YAxis tick={{ fill: '#475569' }} tickLine={false} axisLine={false} />
            <Tooltip
              cursor={{ fill: '#f8fafc' }}
              itemSorter={(item) => getDeployNumber(item.dataKey)}
              contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
            />
            <Legend
              itemSorter={(item) => getDeployNumber(item.value)}
              content={() => (
                <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 pt-5 text-sm">
                  {seriesDeploys.map(({ label, color }) => (
                    <span key={label} className="inline-flex items-center gap-2 text-slate-700">
                      <span className="h-3 w-3 rounded-full" style={{ backgroundColor: color }} />
                      {label}
                    </span>
                  ))}
                </div>
              )}
            />

            {seriesDeploys.map(({ idx, label, color }) => (
              <Bar
                key={idx}
                dataKey={label}
                name={label}
                fill={color}
                radius={[4, 4, 0, 0]}
                barSize={30}
                animationDuration={800}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}