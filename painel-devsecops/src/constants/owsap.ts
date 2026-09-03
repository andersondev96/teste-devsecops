/**
 * Tipos do contrato OWASP fornecido pelo backend.
 *
 * O catálogo, os status e as evidências não ficam neste arquivo. O pipeline
 * exporta GET /security/owasp para src/data/owasp_status.json antes do build.
 */

export type OwaspStatus =
  | 'vulnerable'
  | 'partially_mitigated'
  | 'mitigated'
  | 'not_assessed';

export type OwaspEvidence = {
  Title: string;
  desc: string;
  solution: string;
  uri: string;
  file: string;
  line_number: number;
};

export type OwaspCategory = {
  id: string;
  title: string;
  desc: string;
  status: OwaspStatus;
  evidence: OwaspEvidence;
};

export type OwaspStatusDocument = {
  schema_version: 1;
  source: 'backend';
  categories: OwaspCategory[];
  metrics: {
    total: number;
    mitigated: number;
    partially_mitigated: number;
    vulnerable: number;
    not_assessed: number;
  };
};

export type OwaspMapping = {
  status: OwaspStatus;
  tools: string[];
  evidences: OwaspEvidence[] | any[];
};
