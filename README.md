# Pesquisa TCC - Automação de Segurança em APIs RESTful

## Visão geral

Este repositório reúne os materiais do Trabalho de Conclusão de Curso (TCC) do MBA em Engenharia de Software da USP/Esalq, com foco em automação de segurança em APIs RESTful no pipeline DevSecOps.

O projeto combina três blocos principais:

1. documentação acadêmica e artefatos da pesquisa de campo;
2. laboratório de API vulnerável para demonstração e mitigação de riscos OWASP API Top 10;
3. painel de visualização dos resultados de segurança e do status da aplicação.

## Estrutura do repositório

```text
.
├── .github/
│   └── workflows/
│       └── devsecops.yml
├── .gitignore
├── .gitleaksignore
├── README.md
├── broken-api/
│   ├── .venv/
│   ├── controllers/
│   ├── models/
│   ├── routes/
│   ├── tests/
│   ├── .dockerignore
│   ├── .python-version
│   ├── config.py
│   ├── database.db
│   ├── Dockerfile
│   ├── limits.py
│   ├── main.py
│   ├── owasp_status.json
│   ├── requirements-dev.txt
│   ├── requirements.txt
│   ├── run.py
│   ├── security.py
│   ├── security_headers.py
│   ├── users_db.py
│   └── VULNERABILITY_MITIGATION.md
├── docs/
│   ├── imagens_graficos/
│   │   ├── 01_termo_de_consentimento_livre_esclarecido.png
│   │   ├── 02_area_de_atuacao.png
│   │   ├── 03_tempo_experiencia.png
│   │   ├── 04_papel_das_apis_restful.png
│   │   ├── 05_maturidade_da_cultura_devsecops.png
│   │   ├── 06_maturidade_automacao_de_testes.png
│   │   ├── 07_tipos_de_testes_de_seguranca_automatizados.png
│   │   ├── 08_frequencia_de_testes_de_seguranca.png
│   │   ├── 09_familiaridade_owasp.png
│   │   ├── 10_frequencia_de_vulnerabilidades.png
│   │   ├── 11_desafios_automacao_de_testes_de_seguranca.png
│   │   ├── 12_importancia_relatorios_vulnerabilidade.png
│   │   └── 13_maiores_bairreiras_devsecops.png
│   ├── pesquisa_campo/
│   │   ├── questionario_aplicado.md
│   │   └── resultados_sintetizados.md
│   └── raw_data/
│       └── dados.csv
├── historico-security-gate.txt
├── painel-devsecops/
│   ├── dist/
│   ├── node_modules/
│   ├── public/
│   ├── src/
│   ├── .gitignore
│   ├── README.md
│   ├── eslint.config.js
│   ├── index.html
│   ├── package-lock.json
│   ├── package.json
│   ├── postcss.config.js
│   ├── tailwind.config.js
│   ├── tsconfig.app.json
│   ├── tsconfig.json
│   ├── tsconfig.node.json
│   └── vite.config.ts
└── ...
```

## Diretórios e responsabilidades

### `broken-api`

Diretório central do laboratório de aplicação vulnerável e segura. Ele simula uma API RESTful com falhas e mitigação de vulnerabilidades conforme o OWASP API Security Top 10 2023.

Principais elementos:

- `main.py`: ponto de entrada da API.
- `config.py`: configuração do ambiente e variáveis de segurança.
- `security.py`: mecanismos de autenticação, autorização e validações relevantes.
- `security_headers.py`: controle de headers HTTP e segurança de resposta.
- `limits.py`: limites de consumo e proteção contra abuso.
- `users_db.py`: armazenamento e lógica de usuários.
- `VULNERABILITY_MITIGATION.md`: documentação detalhada dos riscos e das ações de mitigação.
- `tests/`: suíte de testes automatizados para validação das vulnerabilidades e das correções.
- `owasp_status.json`: catálogo de status das vulnerabilidades e evidências do laboratório.

Esse módulo foi construído para demonstrar, testar e documentar falhas e mitigação em cenário educativo/controlado, e não deve ser usado em produção.

### `painel-devsecops`

Diretório do frontend em React + TypeScript + Vite, utilizado para visualizar o status de segurança, vulnerabilidades e indicadores do pipeline DevSecOps.

Principais elementos:

- `src/`: código-fonte da interface.
- `public/`: assets públicos.
- `dist/`: build final gerado para deploy.
- `package.json`: dependências e scripts do projeto.
- `vite.config.ts`: configuração do Vite.

Esse painel serve como camada de apresentação dos dados e resultados de segurança para monitoramento e visualização.

### `docs`

Diretório acadêmico da pesquisa. Armazena os instrumentos, resultados e a base de dados da pesquisa de campo.

- `pesquisa_campo/`: questionário e síntese dos resultados.
- `imagens_graficos/`: gráficos relativos às respostas da pesquisa.
- `raw_data/`: dados brutos anonimizados.

### `.github` e pipeline

A pasta `.github/workflows` contém a automação do pipeline DevSecOps, responsável por executar validações estáticas, análise de dependências, testes, scans de container e gates de segurança.

## Documentos de pesquisa

### Questionário aplicado

- `docs/pesquisa_campo/questionario_aplicado.md`
- Instrumento de coleta utilizado na pesquisa.
- Contém o TCLE, perguntas estruturadas, escalas de resposta e opções de avaliação aplicadas aos participantes.

### Resultados sintetizados

- `docs/pesquisa_campo/resultados_sintetizados.md`
- Consolida os principais achados da pesquisa: perfil profissional, maturidade DevSecOps, frequência de testes e barreiras de adoção.

### Dados brutos

- `docs/raw_data/dados.csv`
- Base de dados anonimizados utilizada para análise de tendências e geração de gráficos.

## Observações éticas e de privacidade

- A pesquisa foi conduzida com consentimento informado e anonimato.
- Não houve coleta de dados pessoais sensíveis ou identificáveis.
- Todos os arquivos foram organizados para respeitar as diretrizes de proteção da informação e o uso acadêmico.

## Execução e uso

A estrutura do repositório não exige um processo de build global para leitura dos documentos acadêmicos. Para uso prático:

1. Abra o repositório em um editor como VS Code.
2. Consulte os materiais em `docs/pesquisa_campo/` para leitura do questionário e resultados.
3. Analise os dados em `docs/raw_data/dados.csv` em planilha ou CSV.
4. Visualize os gráficos em `docs/imagens_graficos/` para suporte à interpretação.
5. Para o laboratório `broken-api`, utilize o ambiente virtual Python e execute os testes conforme descrito no arquivo `broken-api/VULNERABILITY_MITIGATION.md`.
6. Para o painel `painel-devsecops`, execute os comandos do Node/Vite normalmente presentes em `package.json`.

## Contexto acadêmico e objetivo geral

A pesquisa e os artefatos do repositório abordam a integração de segurança em pipelines de CI/CD e a automação de testes para reduzir riscos em APIs RESTful. O principal objetivo é demonstrar como a cultura DevSecOps, a integração de ferramentas e a adoção de boas práticas impactam diretamente a resiliência e a segurança de aplicações web e APIs.

## Observações relevantes

- O projeto combina pesquisa, laboratório e visualização.
- O material foi organizado para facilitar uso acadêmico, revisão e publicação.
- O repositório funciona como base documental e experimental para o TCC e para demonstração de práticas de segurança contínua.

## Licenciamento e uso

Os materiais contidos neste repositório são destinados ao uso acadêmico e de demonstração técnica. Caso sejam reutilizados em outros contextos, recomenda-se manter a atribuição ao projeto e ao contexto de pesquisa original.
