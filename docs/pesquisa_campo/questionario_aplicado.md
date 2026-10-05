# Questionário Aplicado: Pesquisa TCC - Automação de Segurança em APIs RESTful

## Seção 1: Termo de Consentimento Livre e Esclarecido (TCLE)

Caro(a) participante,

Esta pesquisa é parte integrante do Trabalho de Conclusão de Curso (TCC) do MBA em Engenharia de Software pela USP/ESALQ, intitulado: **"Integração do OWASP API Top 10 em Pipelines DevSecOps: Mitigação de Vulnerabilidades em APIs RESTful"**.

O objetivo deste estudo é analisar a percepção de profissionais da área de tecnologia sobre a integração de testes de segurança automatizados em pipelines de CI/CD. O foco está na mitigação das vulnerabilidades listadas no **OWASP API Security Top 10 (2023)** e na otimização da detecção de falhas durante o ciclo de desenvolvimento de software.

Os resultados obtidos através deste questionário serão utilizados para enriquecer a análise comparativa entre métodos de validação manuais e automatizados e fundamentar as conclusões acadêmicas sobre a criticidade das falhas detectadas em ambientes de integração contínua.

### Privacidade e Confidencialidade

A sua participação é voluntária e as respostas são estritamente anônimas. Não serão coletados nomes, endereços de e-mail ou dados sensíveis de identificação pessoal. As informações fornecidas serão tratadas de forma agregada para fins exclusivamente acadêmicos e profissionais. O participante tem o direito de recusar a participação ou desistir de responder a qualquer momento, fechando o questionário, sem qualquer tipo de prejuízo.

Agradecemos imensamente sua colaboração para o avanço das práticas de segurança em nossa área.

Ao clicar na opção abaixo, você confirma que leu as informações acima e concorda em participar voluntariamente desta pesquisa, autorizando o uso de suas respostas anônimas para os fins acadêmicos descritos.

- [ ] Sim, compreendo os objetivos e aceito participar desta pesquisa.
- [ ] Não aceito participar.

## Seção 2: Perfil Profissional

### Pergunta 1
Qual é a sua área de atuação principal? (Múltipla escolha)

- [ ] Desenvolvimento de Software (Backend, Frontend, Fullstack)
- [ ] DevOps/SRE (Engenharia de Confiabilidade do Site)
- [ ] Segurança da Informação / Application Security (AppSec)
- [ ] QA (Garantia de Qualidade / Testes)
- [ ] Arquitetura de Software
- [ ] Gerenciamento de Projetos / Liderança Técnica
- [ ] Outra (Especifique)

### Pergunta 2
Qual é o seu tempo de experiência profissional na área de Tecnologia (Desenvolvimento, Operações ou Segurança)? (Múltipla escolha)

- [ ] Menos de 1 ano
- [ ] 1 a 3 anos
- [ ] 4 a 6 anos
- [ ] 7 a 9 anos
- [ ] Mais de 10 anos

### Pergunta 3
Qual é o papel das APIs RESTful no ecossistema de desenvolvimento da sua empresa/equipe atual? (Múltipla escolha)

- [ ] Essencial: São a base principal dos nossos produtos e integrações.
- [ ] Complementar: Utilizamos APIs RESTful, mas convivem com outras arquiteturas (gRPC, SOAP, Mensageria).
- [ ] Mínimo ou Inexistente: Utilizamos outras arquiteturas predominantemente ou não trabalhamos com APIs.
- [ ] Não se aplica: Não atuo diretamente com desenvolvimento ou manutenção de software.

## Seção 3: Conhecimento Técnico e Ferramental

### Pergunta 4
Como você descreveria a maturidade da cultura DevSecOps (integração de segurança no CI/CD) na sua rotina profissional? (Múltipla escolha)

- [ ] Alta: Implemento e gerencio ferramentas de segurança automatizadas em pipelines de forma contínua.
- [ ] Média: Compreendo os conceitos e utilizo algumas ferramentas, mas a segurança ainda não está totalmente integrada ao ciclo de automação.
- [ ] Baixa: Conheço o conceito teoricamente, mas não aplico práticas de segurança automatizada no meu fluxo de trabalho.
- [ ] Inexistente: Não estou familiarizado com o conceito ou não o aplicamos.

### Pergunta 5
Em sua organização, qual é o nível de maturidade da Automação de Testes de Segurança no Pipeline de CI/CD? (Escala Linear)

1 (Inexistente/Manual) a 7 (Totalmente Automatizada e Integrada - DevSecOps)

- [ ] 1
- [ ] 2
- [ ] 3
- [ ] 4
- [ ] 5
- [ ] 6
- [ ] 7

### Pergunta 6
Quais tipos de testes de segurança automatizados vocês utilizam para APIs RESTful? (Caixas de seleção - Selecione todos que se aplicam)

- [ ] SAST (Static Application Security Testing): Varredura de segurança diretamente no código-fonte ou binários antes da execução.
- [ ] DAST (Dynamic Application Security Testing): Testes de "caixa-preta" que simulam ataques em tempo de execução.
- [ ] SCA (Software Composition Analysis): Identificação de vulnerabilidades em dependências, frameworks e bibliotecas de terceiros.
- [ ] IAST (Interactive Application Security Testing): Análise híbrida que monitora a execução da aplicação internamente durante os testes.
- [ ] API Fuzzing / Schema Validation: Testes que enviam dados inválidos ou inesperados para os endpoints para testar a resiliência da API.
- [ ] Testes de Contrato / Integração com foco em Segurança: Scripts customizados para validar lógica de negócio.
- [ ] Não utilizamos testes de segurança automatizados.

## Seção 4: Percepção de Vulnerabilidades

### Pergunta 7
Com que frequência você realiza testes de segurança antes do deploy? (Múltipla escolha)

- [ ] Sempre
- [ ] Frequentemente
- [ ] Raramente
- [ ] Nunca

### Pergunta 8
Qual o seu nível de familiaridade e aplicação do Projeto OWASP API Security Top 10 (2023) nas suas atividades? (Múltipla escolha)

- [ ] Referência Base: Utilizo como diretriz fundamental para o design e testes de segurança das APIs.
- [ ] Conhecimento Prático: Conheço as vulnerabilidades e tento mitigá-las, mas não sigo a metodologia de forma rigorosa no meu fluxo de trabalho atual.
- [ ] Conhecimento Teórico: Conheço a lista, mas ela não influencia diretamente.
- [ ] Conhecimento Geral: Conheço o OWASP Top 10 (Web), mas não a versão específica para APIs.
- [ ] Não estou familiarizado com o projeto.

### Pergunta 9
Na sua experiência, com que frequência ocorrem as seguintes vulnerabilidades de segurança em suas APIs? (Escala de 1 - Nunca Ocorre até 5 - Ocorre Constantemente)

| Vulnerabilidade | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- |
| Acesso Indevido: Um usuário consegue acessar dados de outro usuário mudando o ID na URL. | [ ] | [ ] | [ ] | [ ] | [ ] |
| Falhas de Login: Problemas em tokens (JWT), senhas fracas ou falta de expiração de sessão (Auth). | [ ] | [ ] | [ ] | [ ] | [ ] |
| Exposição de Dados: A API retorna mais informações do que o necessário no JSON. | [ ] | [ ] | [ ] | [ ] | [ ] |
| Falta de Limites: A API fica lenta ou cai por excesso de requisições ou falta de Rate Limit. | [ ] | [ ] | [ ] | [ ] | [ ] |
| Acesso Administrativo: Um usuário comum consegue acessar funções de administrador. | [ ] | [ ] | [ ] | [ ] | [ ] |
| Injeção / SSRF: A API aceita comandos maliciosos ou faz requisições internas indevidas. | [ ] | [ ] | [ ] | [ ] | [ ] |

## Seção 5: Desafios e Valor da Solução

### Pergunta 10
Na sua visão, quais são os principais desafios ao tentar implementar a automação de testes de segurança em APIs RESTful na sua organização? (Caixas de seleção - Selecione até 3 opções)

- [ ] Custo e Ferramental: Alto custo de licenciamento de ferramentas comerciais ou falta de ferramentas open-source adequadas.
- [ ] Déficit de Skill: Falta de conhecimento técnico ou expertise da equipe em segurança de APIs (AppSec).
- [ ] Complexidade de Integração: Dificuldade técnica para integrar ferramentas de segurança (SAST/DAST/SCA) ao pipeline de CI/CD atual.
- [ ] Cultura e Priorização: Baixa prioridade estratégica ou falta de apoio da liderança para iniciativas de segurança.
- [ ] Impacto na Performance: Lentidão excessiva dos testes de segurança, gerando atrasos (delay) indesejados no fluxo de entrega.
- [ ] Ruído e Manutenção: Volume elevado de falsos-positivos e necessidade constante de tuning das ferramentas.
- [ ] Definição de Processos: Falta de uma metodologia clara (como o OWASP API Top 10) para guiar o que deve ser testado.
- [ ] Não há desafios: Já possuímos uma arquitetura DevSecOps madura e implementada com sucesso.

### Pergunta 11
Como você avalia a importância de ter relatórios de vulnerabilidades automáticos e centralizados após a execução do pipeline CI/CD? (Escala Linear)

1 (Irrelevante) a 7 (Indispensável)

- [ ] 1
- [ ] 2
- [ ] 3
- [ ] 4
- [ ] 5
- [ ] 6
- [ ] 7

### Pergunta 12
Em sua opinião, qual é a maior barreira para a adoção plena do DevSecOps na sua equipe? (Resposta Curta / Parágrafo)

> Resposta:
