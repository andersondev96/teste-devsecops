import { BookOpen, AlertTriangle, CheckCircle, Target, FileText } from 'lucide-react';

interface RelatorioProps {
  totalFalhas: number;
}

export function RelatorioTab({ totalFalhas }: RelatorioProps) {
  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-slate-800">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold flex items-center">
          <FileText className="w-6 h-6 mr-2 text-academico-primary" />
          Relatório Consolidado do Ciclo Experimental
        </h2>
        <span className="text-sm text-slate-500">MBA USP/Esalq - Engenharia de Software</span>
      </div>

      <div className="bg-white border rounded-lg p-8 shadow-sm space-y-8 max-w-5xl mx-auto">

        {/* Resumo do Ciclo */}
        <section>
          <h3 className="text-lg font-bold text-academico-primary flex items-center mb-3">
            <BookOpen className="w-5 h-5 mr-2" />
            1. Resumo Executivo
          </h3>
          <p className="text-slate-600 leading-relaxed text-justify">
            O ciclo experimental inicial focado na avaliação de uma API RESTful vulnerável foi concluído com sucesso através da execução automatizada de um pipeline DevSecOps. A orquestração das ferramentas de segurança (Bandit, Safety, Trivy e OWASP ZAP) operou conforme a metodologia proposta, identificando um total de <strong className="text-red-600">{totalFalhas} vulnerabilidades</strong> no código-fonte, dependências, infraestrutura e durante a análise dinâmica. Este volume de achados valida a hipótese de que a ausência de verificações automatizadas de segurança (Security Gates) permite a promoção de código crítico para o ambiente de produção.
          </p>
        </section>

        {/* Proposição de Ações Corretivas */}
        <section>
          <h3 className="text-lg font-bold text-academico-primary flex items-center mb-3">
            <AlertTriangle className="w-5 h-5 mr-2" />
            2. Proposição de Ações Corretivas (Mitigação)
          </h3>
          <p className="text-slate-600 leading-relaxed mb-4">
            Com base no mapeamento realizado contra o framework <strong>OWASP API Security Top 10 (2023)</strong>, as seguintes ações corretivas foram desenhadas para aplicação no segundo ciclo de desenvolvimento (API Mitigada):
          </p>

          <div className="space-y-4">
            <div className="bg-slate-50 p-4 rounded-md border border-slate-200 border-l-4 border-l-academico-primary">
              <h4 className="font-bold text-slate-800">API1:2023 - Broken Object Level Authorization (BOLA)</h4>
              <p className="text-sm text-slate-600 mt-1">
                <strong>Ação Proposta:</strong> Implementar validação rigorosa de propriedade (ownership) no nível de acesso a dados. O endpoint deve extrair a identidade do utilizador através do token JWT validado e garantir que o recurso solicitado (ex: ID do utilizador) pertence exclusivamente a essa identidade.
              </p>
            </div>

            <div className="bg-slate-50 p-4 rounded-md border border-slate-200 border-l-4 border-l-academico-primary">
              <h4 className="font-bold text-slate-800">API2:2023 - Broken Authentication</h4>
              <p className="text-sm text-slate-600 mt-1">
                <strong>Ação Proposta:</strong> Substituição da codificação simples (Base64) por um mecanismo robusto de tokens estruturados (JSON Web Tokens - JWT) com assinaturas criptográficas adequadas e expiração de curto prazo. Adição de políticas de Rate Limiting para prevenir ataques de força bruta.
              </p>
            </div>

            <div className="bg-slate-50 p-4 rounded-md border border-slate-200 border-l-4 border-l-academico-primary">
              <h4 className="font-bold text-slate-800">API3:2023 - Broken Object Property Level Authorization</h4>
              <p className="text-sm text-slate-600 mt-1">
                <strong>Ação Proposta:</strong> Utilização de Data Transfer Objects (DTOs) com validação estrita através da biblioteca Pydantic no FastAPI. Remoção de mapeamentos dinâmicos não filtrados para impedir a elevação de privilégios via Mass Assignment (ex: injeção de <code>is_admin: true</code>).
              </p>
            </div>

            <div className="bg-slate-50 p-4 rounded-md border border-slate-200 border-l-4 border-l-academico-primary">
              <h4 className="font-bold text-slate-800">API8:2023 - Security Misconfiguration</h4>
              <p className="text-sm text-slate-600 mt-1">
                <strong>Ação Proposta:</strong> Tratamento global de exceções para impedir o vazamento de stack traces na resposta da API. Atualização de todas as bibliotecas assinaladas pela ferramenta SCA (ex: pacote <code>requests</code>) para versões sem CVEs conhecidas.
              </p>
            </div>
          </div>
        </section>

        {/* Conclusão */}
        <section>
          <h3 className="text-lg font-bold text-academico-primary flex items-center mb-3">
            <Target className="w-5 h-5 mr-2" />
            3. Conclusão do Experimento
          </h3>
          <p className="text-slate-600 leading-relaxed text-justify">
            A implementação da arquitetura DevSecOps mostrou-se altamente eficaz na deteção precoce (Shift-Left) de vulnerabilidades críticas. A automação assegura que o esforço de revisão de segurança seja contínuo e escalável. Após a aplicação das ações corretivas propostas nesta secção, espera-se que o reprocessamento do código pela esteira CI/CD demonstre uma taxa de mitigação substancial, reduzindo drasticamente a superfície de ataque da API e validando plenamente os objetivos práticos desta pesquisa.
          </p>
        </section>

        {/* Assinatura */}
        <div className="mt-8 pt-6 border-t border-slate-200 text-center">
          <p className="text-sm font-medium text-slate-800">Anderson Fernandes Ferreira</p>
          <p className="text-xs text-slate-500">Mestrando em Engenharia de Software - USP/Esalq</p>
          <div className="flex justify-center items-center mt-2 text-green-600 text-sm font-semibold">
            <CheckCircle className="w-4 h-4 mr-1" />
            Documento gerado automaticamente pelo Pipeline de Segurança
          </div>
        </div>

      </div>
    </div>
  );
}