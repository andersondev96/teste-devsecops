export const OWASP_API_2023 = [
  { id: 'API1', title: 'API1:2023 - Broken Object Level Authorization (BOLA)', desc: 'Falha ao validar permissões de acesso ao objeto.' },
  { id: 'API2', title: 'API2:2023 - Broken Authentication', desc: 'Mecanismos de autenticação incorretos.' },
  { id: 'API3', title: 'API3:2023 - Broken Object Property Level Authorization', desc: 'Acesso indevido a propriedades de objetos.' },
  { id: 'API4', title: 'API4:2023 - Unrestricted Resource Consumption', desc: 'Falta de limites em recursos e rate limit.' },
  { id: 'API5', title: 'API5:2023 - Broken Function Level Authorization', desc: 'Acesso a funções administrativas por utilizadores comuns.' },
  { id: 'API6', title: 'API6:2023 - Unrestricted Access to Sensitive Business Flows', desc: 'Abuso de fluxos de negócio.' },
  { id: 'API7', title: 'API7:2023 - Server Side Request Forgery (SSRF)', desc: 'Requisições do servidor para destinos não validados.' },
  { id: 'API8', title: 'API8:2023 - Security Misconfiguration', desc: 'Configurações inseguras e erros detalhados.' },
  { id: 'API9', title: 'API9:2023 - Improper Inventory Management', desc: 'Falta de documentação e APIs obsoletas expostas.' },
  { id: 'API10', title: 'API10:2023 - Unsafe Consumption of APIs', desc: 'Falta de validação em APIs de terceiros.' },
];

export type OwaspStatus = 'vulnerable' | 'partially_mitigated' | 'mitigated' | 'not_assessed';

export type OwaspMapping = {
  status: OwaspStatus;
  tools: string[];
  evidences: any[];
};

// Estado de referência do laboratório. A ausência de um achado automático
// não é suficiente para alterar uma categoria para "mitigated".
// API2, API4 e API6 ainda possuem controles complementares pendentes; a
// ausência de um achado automático não é suficiente para marcar categorias
// parcialmente mitigadas como totalmente mitigadas.
export const OWASP_LAB_STATUS: Record<string, OwaspStatus> = {
  API1: 'mitigated',
  API2: 'partially_mitigated',
  API3: 'mitigated',
  API4: 'partially_mitigated',
  API5: 'mitigated',
  API6: 'partially_mitigated',
  API7: 'vulnerable',
  API8: 'vulnerable',
  API9: 'vulnerable',
  API10: 'vulnerable',
};

// Evidências do laboratório: os testes documentam o comportamento vulnerável
// remanescente e as regressões dos controles já mitigados. Elas complementam
// os achados automáticos do ZAP/Bandit, que não conseguem identificar todas
// as categorias OWASP apenas por análise genérica dos endpoints.
export const OWASP_LAB_EVIDENCE: Record<string, {
  Title: string;
  desc: string;
  solution: string;
  uri: string;
  file: string;
  line_number: number;
}> = {
  API1: {
    Title: 'Regressão API1 — autorização por objeto',
    desc: 'Os testes confirmam que o JWT define a identidade no servidor e que leitura, alteração de perfil, consulta por ID e checkout de outro usuário são rejeitados.',
    solution: 'Aplicar autorização por objeto antes de ler ou alterar o recurso, permitindo somente o proprietário ou um administrador.',
    uri: 'GET/PUT /profile/{user_id}, GET /users/{user_id}, POST /checkout',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 53,
  },
  API2: {
    Title: 'Teste API2 — regressão da autenticação',
    desc: 'Os testes verificam a rejeição de credenciais inválidas, a emissão de JWT assinado e a rejeição de tokens adulterados.',
    solution: 'Manter a validação de senha com hash forte, tokens assinados e respostas sem credenciais ou dados de depuração.',
    uri: 'POST /login',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 45,
  },
  API3: {
    Title: 'Regressão API3 — autorização por propriedade',
    desc: 'Os testes confirmam que campos extras e privilegiados são rejeitados e que usuários, produtos e pedidos retornam somente propriedades públicas.',
    solution: 'Usar schemas de entrada com allowlist e DTOs de saída explícitos, rejeitando propriedades não autorizadas e filtrando dados internos.',
    uri: 'PUT /profile/{user_id}, GET /users, GET /products, POST /checkout',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 175,
  },
  API4: {
    Title: 'Regressão API4 — limites de consumo',
    desc: 'Os testes confirmam paginação com limite máximo, busca limitada, rate limiting e rejeição de corpos acima do tamanho permitido; controles de infraestrutura ainda permanecem pendentes.',
    solution: 'Aplicar limites server-side de página e payload, rate limiting distribuído e proteção de middleware contra corpos em chunks; complementar com timeouts e circuit breakers.',
    uri: 'GET /products, GET /products/search, GET /users, POST /checkout, POST /login',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 244,
  },
  API5: {
    Title: 'Teste API5 — autorização em nível de função',
    desc: 'Os testes confirmam que chamadas anônimas e de usuários comuns são rejeitadas nas funções de catálogo, enquanto o administrador consegue alterar o preço dentro da faixa permitida.',
    solution: 'Centralizar autorização por função, exigir autenticação em endpoints administrativos, validar entradas e registrar operações para auditoria.',
    uri: 'DELETE /products/{product_id}, PUT /products/{product_id}/price',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 343,
  },
  API6: {
    Title: 'Teste API6 — abuso de fluxo de negócio sensível',
    desc: 'Os testes confirmam allowlist de campos, produto e quantidade válidos, total calculado no servidor, idempotência e limite de tentativas por identidade; controles antifraude externos ainda permanecem pendentes.',
    solution: 'Validar regras de negócio no servidor, recalcular valores, controlar reenvios e complementar com CAPTCHA, antifraude, filas e limites distribuídos.',
    uri: 'POST /checkout',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 373,
  },
  API7: {
    Title: 'Teste API7 — SSRF',
    desc: 'O servidor acessa uma URL fornecida diretamente pelo cliente, inclusive um endereço de metadados da nuvem.',
    solution: 'Aplicar allowlist de destinos, bloquear redes internas e validar o esquema e o destino da URL.',
    uri: 'GET /integrations/fetch-url?url=...',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 99,
  },
  API8: {
    Title: 'Teste API8 — endpoint de debug exposto',
    desc: 'Um endpoint de depuração público expõe segredos, cabeçalhos e informações internas da aplicação.',
    solution: 'Remover endpoints de debug em produção e aplicar autenticação, autorização e configuração segura.',
    uri: 'GET /auth/debug',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 118,
  },
  API9: {
    Title: 'Teste API9 — inventário exposto e endpoint esquecido',
    desc: 'A API mantém e expõe um inventário completo de pedidos por meio de um endpoint de debug não documentado.',
    solution: 'Manter inventário de endpoints, remover APIs obsoletas e restringir endpoints administrativos.',
    uri: 'GET /checkout/debug',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 126,
  },
  API10: {
    Title: 'Teste API10 — consumo inseguro de API externa',
    desc: 'A resposta de um provedor externo é aceita sem validação e influencia diretamente a decisão de negócio.',
    solution: 'Validar, tipar e sanitizar respostas externas; aplicar timeouts, contratos e tratamento de falhas.',
    uri: 'GET /integrations/address/enrich',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 133,
  },
};
