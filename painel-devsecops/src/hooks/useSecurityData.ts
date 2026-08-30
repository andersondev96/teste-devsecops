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

const isTestFile = (filename: unknown) =>
  String(filename || '').replace(/\\/g, '/').includes('/tests/');

const isCurrentZapFinding = (alert: any) => Number(alert?.riskcode) > 0;

const classifyZapFinding = (alert: any): string => {
  const name = String(alert?.name || '').toLowerCase();

  if (/(authentication|login|token|jwt|session)/.test(name)) return 'API2';
  if (/(ssrf|server side request forgery|remote file inclusion)/.test(name)) return 'API7';
  if (/(idor|object level)/.test(name)) return 'API1';
  if (/(function level|authorization|access control)/.test(name)) return 'API5';
  if (/(config|disclosure|header|server error|sql injection)/.test(name)) return 'API8';

  // Um alerta DAST genérico não deve ser apresentado como BOLA.
  return 'API8';
};

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
      // Alertas informativos, como "Authentication Request Identified", não
      // comprovam uma vulnerabilidade e não devem ativar uma categoria OWASP.
      if (isCurrentZapFinding(alert)) {
        markDetected(classifyZapFinding(alert), 'OWASP ZAP', alert);
      }
    });

    sastReport.results?.forEach((issue: any) => {
      if (isTestFile(issue.filename)) return;

      const isEnvironmentVariableName =
        issue.test_id === 'B105' &&
        String(issue.issue_text || '').includes('JWT_SECRET_KEY') &&
        String(issue.filename || '').replace(/\\/g, '/').endsWith('/security.py');

      const isKnownNonCredentialLiteral =
        issue.test_id === 'B105' &&
        /scrypt\$|bearer/.test(String(issue.issue_text || '').toLowerCase());

      if (isEnvironmentVariableName || isKnownNonCredentialLiteral) return;

      if (['B105', 'B106'].includes(issue.test_id)) {
        markDetected('API2', 'Bandit', issue);
      } else {
        markDetected('API8', 'Bandit', issue);
      }
    });

    // O PyJWT pertence ao caminho de autenticação; seus CVEs devem manter a
    // API2 ativa até que a dependência seja atualizada.
    scaReport.vulnerabilities?.forEach((vulnerability: any) => {
      if (String(vulnerability.package_name || '').toLowerCase() === 'pyjwt') {
        markDetected('API2', 'Safety', vulnerability);
      }
    });

    trivyReport.Results?.forEach((result: any) => {
      result.Vulnerabilities?.forEach((vulnerability: any) => {
        if (String(vulnerability.PkgName || '').toLowerCase() === 'pyjwt') {
          markDetected('API2', 'Trivy', vulnerability);
        }
      });
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
