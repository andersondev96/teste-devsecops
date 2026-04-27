import { useMemo } from 'react';
import sastReport from '../data/sast_report.json';
import scaReport from '../data/sca_report.json';
import trivyReport from '../data/trivy_report.json';
import zapReport from '../data/report_json.json';
import rawHistoryData from '../data/history.json';
import { OWASP_API_2023 } from '../constants/owsap';

// Dizemos ao TypeScript exatamente o que esperar, mesmo que o JSON esteja vazio agora.
const historyData = rawHistoryData as Array<{
  date: string;
  sast: number;
  sca: number;
  dast: number;
  trivy: number;
  total: number;
}>;

export function useSecurityData() {
  const experimentData = useMemo(() => {
    let alta = 0, media = 0, baixa = 0, total = 0;

    // SAST
    sastReport.results?.forEach((issue: any) => {
      total++;
      if (issue.issue_severity === 'HIGH') alta++;
      else if (issue.issue_severity === 'MEDIUM') media++;
      else baixa++;
    });

    // DAST
    zapReport.site?.[0]?.alerts?.forEach((alert: any) => {
      total++;
      if (alert.riskcode === '3') alta++;
      else if (alert.riskcode === '2') media++;
      else baixa++;
    });

    // Trivy
    trivyReport.Results?.forEach((result: any) => {
      result.Vulnerabilities?.forEach((vuln: any) => {
        total++;
        if (vuln.Severity === 'CRITICAL' || vuln.Severity === 'HIGH') alta++;
        else if (vuln.Severity === 'MEDIUM') media++;
        else baixa++;
      });
    });

    // SCA
    if (scaReport?.vulnerabilities) {
      scaReport.vulnerabilities.forEach((vuln: any) => {
        total++;
        const severity = (vuln?.severity || 'HIGH').toUpperCase();
        if (severity === 'CRITICAL' || severity === 'HIGH') alta++;
        else if (severity === 'MEDIUM') media++;
        else baixa++;
      });
    }

    // CÁLCULO REAL DA TAXA DE MITIGAÇÃO BASEADO NO HISTÓRICO
    const baseline = historyData.length > 0 ? historyData[0] : null;
    const current = historyData.length > 0 ? historyData[historyData.length - 1] : null;

    let taxaMitigacao = 0;
    if (baseline && current && baseline.total > 0) {
      taxaMitigacao = Math.round(((baseline.total - current.total) / baseline.total) * 100);
    }

    return { total, alta, media, baixa, taxaMitigacao: Math.max(0, taxaMitigacao) };
  }, []);

  const owaspMapping = useMemo(() => {
    const mapping: Record<string, { detected: boolean; tools: string[]; evidences: any[] }> = {};
    OWASP_API_2023.forEach(cat => mapping[cat.id] = { detected: false, tools: [], evidences: [] });

    const markDetected = (id: string, tool: string, evidence: any) => {
      mapping[id].detected = true;
      if (!mapping[id].tools.includes(tool)) mapping[id].tools.push(tool);
      mapping[id].evidences.push(evidence);
    };

    zapReport.site?.[0]?.alerts?.forEach((alert: any) => {
      const name = alert.name.toLowerCase();
      if (name.includes('auth') || name.includes('token')) markDetected('API2', 'OWASP ZAP', alert);
      else if (name.includes('config')) markDetected('API8', 'OWASP ZAP', alert);
      else markDetected('API1', 'OWASP ZAP', alert);
    });

    sastReport.results?.forEach((issue: any) => {
      if (['B105', 'B106'].includes(issue.test_id)) markDetected('API2', 'Bandit', issue);
      else markDetected('API8', 'Bandit', issue);
    });

    return mapping;
  }, []);

  // CÁLCULO REAL DO GRÁFICO COMPARATIVO BASEADO NO HISTÓRICO
  const baseline = historyData.length > 0 ? historyData[0] : null;
  const current = historyData.length > 0 ? historyData[historyData.length - 1] : null;

  const chartData = [
    {
      categoria: 'SAST',
      antes: baseline ? baseline.sast : (sastReport.results?.length || 0),
      depois: current ? current.sast : (sastReport.results?.length || 0)
    },
    {
      categoria: 'SCA',
      antes: baseline ? baseline.sca : (scaReport?.vulnerabilities?.length || 0),
      depois: current ? current.sca : (scaReport?.vulnerabilities?.length || 0)
    },
    {
      categoria: 'DAST',
      antes: baseline ? baseline.dast : (zapReport.site?.[0]?.alerts?.length || 0),
      depois: current ? current.dast : (zapReport.site?.[0]?.alerts?.length || 0)
    },
    {
      categoria: 'Trivy',
      antes: baseline ? baseline.trivy : (trivyReport.Results?.reduce((acc: number, curr: any) => acc + (curr.Vulnerabilities?.length || 0), 0) || 0),
      depois: current ? current.trivy : (trivyReport.Results?.reduce((acc: number, curr: any) => acc + (curr.Vulnerabilities?.length || 0), 0) || 0)
    },
  ];

  return { experimentData, owaspMapping, chartData, historyData };
}