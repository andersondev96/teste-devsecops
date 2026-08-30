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

// Evidências do laboratório: os testes abaixo exercitam intencionalmente
// cada categoria implementada na API vulnerável. Elas complementam os
// achados automáticos do ZAP/Bandit, que não conseguem identificar todas as
// categorias OWASP apenas por análise genérica dos endpoints.
export const OWASP_LAB_EVIDENCE: Record<string, {
  Title: string;
  desc: string;
  solution: string;
  uri: string;
  file: string;
  line_number: number;
}> = {
  API1: {
    Title: 'Teste API1 — acesso ao perfil de outro usuário',
    desc: 'O endpoint aceita um current_user_id informado pelo cliente e permite consultar o perfil de outro usuário.',
    solution: 'Validar a identidade autenticada no servidor e autorizar o acesso ao objeto antes de retorná-lo.',
    uri: 'GET /profile/{user_id}?current_user_id=1',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 38,
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
    Title: 'Teste API3 — mass assignment e exposição de propriedades',
    desc: 'O cliente consegue alterar propriedades privilegiadas e a API devolve campos internos do usuário.',
    solution: 'Usar schemas de entrada e saída explícitos, filtrando propriedades sensíveis e privilegiadas.',
    uri: 'PUT /profile/{user_id}',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 56,
  },
  API4: {
    Title: 'Teste API4 — consumo irrestrito de recursos',
    desc: 'A listagem de produtos não possui paginação, limite de itens ou controle de tamanho da resposta.',
    solution: 'Aplicar paginação, limites de quantidade e rate limiting nos endpoints de leitura.',
    uri: 'GET /products',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 68,
  },
  API5: {
    Title: 'Teste API5 — autorização em nível de função',
    desc: 'Um usuário comum consegue alterar o preço de produtos sem validação de função administrativa.',
    solution: 'Exigir autenticação e verificar a função/permissão antes de executar operações administrativas.',
    uri: 'PUT /products/{product_id}/price',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 75,
  },
  API6: {
    Title: 'Teste API6 — abuso de fluxo de negócio sensível',
    desc: 'O checkout aceita valores manipulados, descontos abusivos e pedidos marcados como pagos sem validação.',
    solution: 'Validar regras de negócio no servidor, recalcular valores e controlar transições de pagamento.',
    uri: 'POST /checkout',
    file: 'broken-api/tests/test_owasp_api_top_10_lab.py',
    line_number: 83,
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
