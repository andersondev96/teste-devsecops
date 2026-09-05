export type GateHistoryEntry = {
  sast?: number;
  sca?: number;
  gate_status?: unknown;
};

/**
 * Regra visual alinhada aos gates finais do workflow.
 *
 * O total da execução reúne achados de todas as ferramentas. Para os registros
 * novos, o workflow persiste gate_status usando as etapas 18.1 e 18.2; DAST
 * nunca altera esse status. Registros antigos não possuem esse campo e usam
 * SAST/SCA como fallback, sem inferir bloqueio pelo total geral.
 */
export function getSastScaGateFindingCount(entry: GateHistoryEntry): number {
  return Math.max(0, Number(entry.sast) || 0) + Math.max(0, Number(entry.sca) || 0);
}

export function getSecurityGateStatus(entry: GateHistoryEntry): 'approved' | 'blocked' {
  if (entry.gate_status === 'approved' || entry.gate_status === 'blocked') {
    return entry.gate_status;
  }

  return getSastScaGateFindingCount(entry) > 0 ? 'blocked' : 'approved';
}
