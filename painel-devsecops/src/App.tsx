import { useState, useEffect } from 'react';
import { LayoutDashboard, ShieldAlert, GitMerge, BarChart3, FileText, History as HistoryIcon } from 'lucide-react';
import { Header } from './components/Header';
import { ComparativoTab } from './components/ComparativoTab';
import { DashboardTab } from './components/DashboardTab';
import { HistoricoTab } from './components/HistoricoTab';
import { OwaspTab } from './components/OwaspTab';
import { PipelineTab } from './components/PipelineTab';
import { RelatorioTab } from './components/RelatorioTab';
import { useSecurityData } from './hooks/useSecurityData';
import { OWASP_API_2023 } from './constants/owsap';

export default function App() {
  // 1. Inicializa o estado lendo do localStorage (ou usa 'dashboard' como padrão)
  const [activeTab, setActiveTab] = useState(() => {
    return localStorage.getItem('devsecops_active_tab') || 'dashboard';
  });

  // 2. Sempre que a aba mudar, salva a nova escolha no localStorage
  useEffect(() => {
    localStorage.setItem('devsecops_active_tab', activeTab);
  }, [activeTab]);

  const { experimentData, owaspMapping, chartData } = useSecurityData();

  const tabs = [
    { id: 'dashboard', label: 'Resumo Executivo', icon: LayoutDashboard },
    { id: 'owasp', label: 'OWASP Top 10', icon: ShieldAlert },
    { id: 'pipeline', label: 'Pipeline CI/CD', icon: GitMerge },
    { id: 'comparativo', label: 'Análise Comparativa', icon: BarChart3 },
    { id: 'historico', label: 'Logs de Execução', icon: HistoryIcon },
    { id: 'relatorio', label: 'Relatório Acadêmico', icon: FileText },
  ];

  return (
    <div className="min-h-screen bg-academico-bg text-slate-800 font-sans">
      <Header />
      <main className="max-w-7xl mx-auto p-6">
        <div className="flex space-x-1 border-b border-slate-300 mb-8 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center px-6 py-3 text-sm font-medium transition-colors border-b-2 whitespace-nowrap ${activeTab === tab.id ? 'border-academico-primary text-academico-primary bg-slate-100' : 'border-transparent text-slate-500 hover:text-slate-700'
                }`}
            >
              <tab.icon className="w-4 h-4 mr-2" />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-slate-200 min-h-[500px]">
          {activeTab === 'dashboard' && <DashboardTab experimentData={experimentData} chartData={chartData} />}
          {activeTab === 'owasp' && <OwaspTab categories={OWASP_API_2023} mapping={owaspMapping} />}
          {activeTab === 'pipeline' && <PipelineTab chartData={chartData} totalAlta={experimentData.alta} />}
          {activeTab === 'comparativo' && <ComparativoTab chartData={chartData} />}
          {activeTab === 'historico' && <HistoricoTab />}
          {activeTab === 'relatorio' && (
            <RelatorioTab
              totalFalhas={experimentData.total}
              mapping={owaspMapping}
            />
          )}
        </div>
      </main>
    </div>
  );
}