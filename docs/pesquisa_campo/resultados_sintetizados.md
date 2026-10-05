# Resultados Sintetizados da Pesquisa de Campo

- **Projeto:** Automação de Segurança em APIs RESTful no Pipeline DevSecOps
- **Período de Recolha:** 30 de abril a 27 de maio de 2026
- **Amostra:** 17 profissionais de tecnologia (MBA em Engenharia de Software - USP/Esalq)
- **Nota Ética:** Todos os dados foram recolhidos de forma anónima, mediante aceitação do Termo de Consentimento Livre e Esclarecido (TCLE). Nenhuma informação de identificação pessoal foi registada.

## 1. Perfil Profissional

### 1.1. Área de Atuação Principal

- 52,9% (9 respostas): Desenvolvimento de Software (Backend, Frontend, Fullstack)
- 23,5% (4 respostas): Gestão de Projetos / Liderança Técnica
- 11,8% (2 respostas): Arquitetura de Software
- 11,8% (2 respostas): Outras áreas

### 1.2. Tempo de Experiência na Área de Tecnologia

- 47,1% (8 respostas): Mais de 10 anos
- 41,2% (7 respostas): 4 a 6 anos
- 11,8% (2 respostas): 1 a 3 anos

Nota: 88,2% da amostra possui nível pleno/sénior de experiência.

## 2. Contexto e Maturidade Organizacional

### 2.1. Papel das APIs RESTful no ecossistema da empresa

- 88,2% classificaram as APIs como Essenciais (base principal dos produtos) ou Complementares (convivem com outras arquiteturas).
- 11,8% indicaram papel mínimo/inexistente ou não atuam diretamente com desenvolvimento.

### 2.2. Maturidade da cultura DevSecOps (integração de segurança no CI/CD)

- 43,8%: Média — compreendem os conceitos e utilizam algumas ferramentas, mas sem integração total.
- 31,3%: Alta — implementam e gerem ferramentas automatizadas de forma contínua.
- 25,0%: Baixa — conhecem a teoria, mas não aplicam práticas automatizadas.

### 2.3. Nível de maturidade da Automação de Testes de Segurança no CI/CD

Numa escala de 1 (Muito Baixo) a 7 (Muito Alto), as respostas apresentaram grande dispersão, confirmando a heterogeneidade das organizações, com concentração moderada entre os níveis 3 e 5.

## 3. Práticas e Ferramentas de Segurança

### 3.1. Frequência de testes de segurança antes do deploy (n=16)

- 31,3% (5 respostas): Sempre
- 31,3% (5 respostas): Frequentemente
- 31,3% (5 respostas): Raramente
- 6,3% (1 resposta): Nunca

### 3.2. Ferramentas e Testes Utilizados (Múltipla Escolha)

A maioria das equipas que realizam testes adota abordagens de SAST (Static Application Security Testing) e SCA (Software Composition Analysis).

DAST (Dynamic Application Security Testing) e Testes de Contrato/Integração aparecem como ferramentas complementares em ambientes de maior maturidade.

- 12,5% indicaram não utilizar testes automatizados de segurança.

### 3.3. Familiaridade e aplicação do OWASP API Security Top 10 (2023)

- 37,5%: Não estão familiarizados com o projeto.
- 25,0%: Conhecimento Prático (conhecem e tentam mitigar, mas sem rigor metodológico).
- 18,8%: Conhecimento Geral (conhecem o OWASP Web, mas não o específico de APIs).
- 12,5%: Conhecimento Teórico (não influencia o fluxo atual).
- 6,3%: Referência Base (utilizam como diretriz fundamental).

## 4. Perceção de Vulnerabilidades (Escala de 1 a 5)

(1 = Nunca Ocorre / 5 = Ocorre Constantemente)

Os respondentes avaliaram a frequência das seguintes vulnerabilidades no seu dia a dia:

- Falta de Limites (Rate Limit / Consumo de Recursos): apresentou a maior taxa de recorrência (concentração em níveis 3, 4 e 5).
- Exposição Excessiva de Dados (JSON): segunda vulnerabilidade mais reportada.
- Falhas de Login/Autenticação (Tokens, Sessões): relatada com recorrência moderada a alta.
- Acesso Indevido (BOLA), Acesso Administrativo e Injeção/SSRF: relatados predominantemente como incidentes de baixa ocorrência (níveis 1 e 2).

## 5. Desafios e Barreiras para o DevSecOps

### 5.1. Principais desafios para implementar automação de segurança (até 3 opções)

- Déficit de Skill (62,5%): falta de conhecimento técnico ou expertise (AppSec).
- Impacto na Performance (50,0%): lentidão nos testes a gerar atrasos no pipeline.
- Definição de Processos (43,8%): falta de uma metodologia clara (ex.: OWASP).
- Cultura e Priorização (31,3%): baixa prioridade estratégica.
- Complexidade de Integração (25,0%): dificuldade técnica no CI/CD.
- Ruído e Manutenção (18,8%): excesso de falsos positivos.

### 5.2. Importância de Relatórios Automáticos e Centralizados no CI/CD

Média de 5,94 numa escala de 1 (Irrelevante) a 7 (Indispensável).

- 87,5% atribuíram notas de alta importância (entre 5 e 7), indicando forte procura por visibilidade de métricas.

### 5.3. Maior barreira para a adoção plena do DevSecOps (respostas abertas sintetizadas)

As respostas dissertativas foram consolidadas nos seguintes eixos temáticos principais:

- Fator Tempo e Prazos: pressão por entregas rápidas (time-to-market) que inviabiliza o tempo útil para estudo e configuração de ferramentas de segurança.
- Fator Cultural e Gerencial: falta de consciencialização da alta gestão sobre o valor acrescentado da segurança, dificultando a priorização do tema e a justificativa de investimentos.
- Fator Capacitação: necessidade de equalização de conhecimentos técnicos e práticas de segurança entre todos os membros das equipas de desenvolvimento.
