import { useMemo } from 'react';
import sastReport from '../data/sast_report.json';
import scaReport from '../data/sca_report.json';
import trivyReport from '../data/trivy_report.json';
import trivyIacReport from '../data/trivy_iac_report.json';
import zapReport from '../data/report_json.json';
import rawHistoryData from '../data/history.json';
import owaspStatus from '../data/owasp_status.json';
import {
  type OwaspMapping,
  type OwaspStatus,
  type OwaspStatusDocument,
} from '../constants/owsap';

const backendOwaspStatus = owaspStatus as OwaspStatusDocument;
const owaspCategories = backendOwaspStatus.categories.map(({ id, title, desc }) => ({
  id,
  title,
  desc,
}));

// Dizemos ao TypeScript exatamente o que esperar, mesmo que o JSON esteja vazio agora.
const historyData = rawHistoryData as Array<{
  date: string;
  sast: number;
  sca: number;
  dast: number;
  trivy: number;
  iac?: number;
  total: number;
}>;

const currentReportCounts = {
  sast: sastReport.results?.length || 0,
  sca: scaReport?.vulnerabilities?.length || 0,
  dast: zapReport.site?.[0]?.alerts?.length || 0,
  trivy: trivyReport.Results?.reduce(
    (total: number, result: any) => total + (result.Vulnerabilities?.length || 0),
    0,
  ) || 0,
  iac: trivyIacReport.Results?.reduce(
    (total: number, result: any) => total + (
      result.Misconfigurations?.filter((finding: any) => finding.Status === 'FAIL').length || 0
    ),
    0,
  ) || 0,
};

const currentReportTotal = Object.values(currentReportCounts).reduce(
  (total, count) => total + count,
  0,
);

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
    let critica = 0;
    let alta = 0;
    let media = 0;
    let baixa = 0;

    const registerSeverity = (value: unknown) => {
      const severity = String(value || 'LOW').toUpperCase();

      if (severity === 'CRITICAL') {
        critica++;
        // O gate considera CRITICAL junto com HIGH.
        alta++;
      } else if (severity === 'HIGH') {
        alta++;
      } else if (severity === 'MEDIUM') {
        media++;
      } else {
        baixa++;
      }
    };

    // SAST
    sastReport.results?.forEach((issue: any) => {
      registerSeverity(issue.issue_severity);
    });

    // DAST
    zapReport.site?.[0]?.alerts?.forEach((alert: any) => {
      const riskCode = String(alert.riskcode ?? '1');
      registerSeverity(riskCode === '3' ? 'HIGH' : riskCode === '2' ? 'MEDIUM' : 'LOW');
    });

    // Trivy
    trivyReport.Results?.forEach((result: any) => {
      result.Vulnerabilities?.forEach((vuln: any) => {
        registerSeverity(vuln.Severity);
      });
    });

    // IaC/Docker
    trivyIacReport.Results?.forEach((result: any) => {
      result.Misconfigurations?.filter((finding: any) => finding.Status === 'FAIL')
        .forEach((finding: any) => registerSeverity(finding.Severity));
    });

    // SCA
    if (scaReport?.vulnerabilities) {
      scaReport.vulnerabilities.forEach((vuln: any) => {
        registerSeverity(vuln?.severity || 'HIGH');
      });
    }

    // Usa o primeiro deploy como baseline e os relatórios atuais como estado
    // final, mesmo que o histórico ainda não tenha sido persistido.
    const baseline = historyData.length > 0 ? historyData[0] : null;

    let taxaMitigacao = 0;
    if (baseline && baseline.total > 0) {
      taxaMitigacao = Math.round(((baseline.total - currentReportTotal) / baseline.total) * 100);
    }

    return {
      ...currentReportCounts,
      total: currentReportTotal,
      critica,
      alta,
      media,
      baixa,
      taxaMitigacao: Math.max(0, taxaMitigacao),
    };
  }, []);

  const owaspMapping = useMemo(() => {
    const mapping: Record<string, OwaspMapping> = {};
    backendOwaspStatus.categories.forEach((category) => {
      mapping[category.id] = {
        status: category.status,
        tools: ['Testes OWASP da API'],
        evidences: [category.evidence],
      };
    });

    const markDetected = (id: string, tool: string, evidence: any) => {
      mapping[id].status = 'vulnerable';
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

  const owaspMetrics = useMemo(() => {
    const metrics: Record<OwaspStatus, number> = {
      vulnerable: 0,
      partially_mitigated: 0,
      mitigated: 0,
      not_assessed: 0,
    };

    Object.values(owaspMapping).forEach(({ status }) => {
      metrics[status]++;
    });

    return {
      total: Object.keys(owaspMapping).length,
      mitigated: metrics.mitigated,
      partially_mitigated: metrics.partially_mitigated,
      vulnerable: metrics.vulnerable,
      not_assessed: metrics.not_assessed,
    };
  }, [owaspMapping]);

  // O baseline vem do histórico; o estado atual vem dos relatórios deste build.
  const baseline = historyData.length > 0 ? historyData[0] : null;

  const chartData = [
    {
      categoria: 'SAST',
      antes: baseline ? baseline.sast : (sastReport.results?.length || 0),
      depois: currentReportCounts.sast,
    },
    {
      categoria: 'SCA',
      antes: baseline ? baseline.sca : (scaReport?.vulnerabilities?.length || 0),
      depois: currentReportCounts.sca,
    },
    {
      categoria: 'DAST',
      antes: baseline ? baseline.dast : (zapReport.site?.[0]?.alerts?.length || 0),
      depois: currentReportCounts.dast,
    },
    {
      categoria: 'Trivy',
      antes: baseline ? baseline.trivy : (trivyReport.Results?.reduce((acc: number, curr: any) => acc + (curr.Vulnerabilities?.length || 0), 0) || 0),
      depois: currentReportCounts.trivy,
    },
    {
      categoria: 'IaC',
      antes: baseline ? (baseline.iac ?? 0) : currentReportCounts.iac,
      depois: currentReportCounts.iac,
    },
  ];

  return {
    experimentData,
    owaspCategories,
    owaspMapping,
    owaspMetrics,
    chartData,
    historyData,
  };
}
