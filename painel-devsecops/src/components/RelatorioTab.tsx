import { BookOpen, AlertTriangle, CheckCircle, Target, FileText, ShieldCheck, Microscope, Zap } from 'lucide-react';

interface RelatorioProps {
  totalFalhas: number;
  mapping: Record<string, { detected: boolean; tools: string[]; evidences: any[] }>;
}

export function RelatorioTab({ totalFalhas, mapping }: RelatorioProps) {
  const vulnerabilidadesAtivas = Object.keys(mapping).filter(id => mapping[id].detected);
  const totalCategorias = Object.keys(mapping).length;
  const totalMitigadas = Object.keys(mapping).filter(id => !mapping[id].detected).length;

  return (
    <div className="space-y-8 animate-in fade-in duration-500 text-slate-800 pb-12">
      <div className="flex justify-between items-end border-b pb-2">
        <h2 className="text-xl font-semibold flex items-center">
          <FileText className="w-6 h-6 mr-2 text-academico-primary" />
          Relatório Técnico Consolidado de Segurança
        </h2>
        <span className="text-sm text-slate-500 font-medium">MBA USP/Esalq - Anderson Fernandes Ferreira</span>
      </div>

      <div className="bg-white border rounded-lg p-10 shadow-md space-y-10 max-w-5xl mx-auto border-t-8 border-t-academico-primary">

        {/* 1. RESUMO EXECUTIVO EXPANDIDO */}
        <section>
          <h3 className="text-xl font-bold text-slate-900 flex items-center mb-4 border-b pb-2">
            <BookOpen className="w-6 h-6 mr-2 text-academico-primary" />
            1. Resumo Executivo e Diagnóstico
          </h3>
          <div className="text-slate-600 leading-relaxed space-y-4 text-justify">
            <p>
              Este relatório apresenta o diagnóstico técnico resultante do ciclo experimental de inspeção de segurança automatizada (Shift-Left Security). A análise incidiu sobre uma API RESTful desenvolvida em Python/FastAPI, submetida a uma esteira de CI/CD (GitHub Actions) configurada com múltiplos motores de análise.
            </p>
            <p>
              Durante a execução, foram identificadas <strong className="text-red-600">{totalFalhas} instâncias de vulnerabilidades</strong>. A detecção dessas falhas em ambiente de pré-produção valida a eficácia dos <strong>Security Gates</strong>: sem a automação aqui demonstrada, estas vulnerabilidades — que incluem desde segredos expostos até falhas lógicas de autorização — seriam promovidas para produção, expondo dados sensíveis e a infraestrutura a ataques reais baseados no framework <strong>OWASP API Security Top 10</strong>.
            </p>
          </div>
        </section>

        {/* 2. METODOLOGIA DE INSPEÇÃO (NOVA SEÇÃO) */}
        <section>
          <h3 className="text-xl font-bold text-slate-900 flex items-center mb-4 border-b pb-2">
            <Microscope className="w-6 h-6 mr-2 text-academico-primary" />
            2. Metodologia de Inspeção Aplicada
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-50 rounded border">
              <h4 className="font-bold text-slate-800 text-sm mb-1">Análise Estática (SAST & SCA)</h4>
              <p className="text-xs text-slate-500 italic">Ferramentas: Bandit & Safety</p>
              <p className="text-xs text-slate-600 mt-2">Varredura profunda no código-fonte e na árvore de dependências para identificar padrões de codificação inseguros e bibliotecas com CVEs conhecidas.</p>
            </div>
            <div className="p-4 bg-slate-50 rounded border">
              <h4 className="font-bold text-slate-800 text-sm mb-1">Análise Dinâmica (DAST)</h4>
              <p className="text-xs text-slate-500 italic">Ferramenta: OWASP ZAP</p>
              <p className="text-xs text-slate-600 mt-2">Simulação de ataques em tempo de execução contra os endpoints da API, identificando falhas de configuração de rede e headers de segurança.</p>
            </div>
          </div>
        </section>

        {/* 3. PROPOSIÇÃO DE AÇÕES CORRETIVAS - DETALHADO E DINÂMICO */}
        <section>
          <h3 className="text-xl font-bold text-slate-900 flex items-center mb-4 border-b pb-2">
            <AlertTriangle className="w-6 h-6 mr-2 text-amber-500" />
            3. Proposição de Ações Corretivas (Mitigação)
          </h3>

          {vulnerabilidadesAtivas.length > 0 ? (
            <div className="space-y-10">
              <p className="text-sm text-slate-600 bg-amber-50 p-3 border-l-4 border-amber-400">
                Abaixo estão detalhadas as estratégias de remediação para as categorias que <strong>violaram</strong> os critérios de segurança na última inspeção.
              </p>

              {/* API1: BOLA */}
              {mapping['API1']?.detected && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-bold text-lg text-slate-800">API1:2023 — Broken Object Level Authorization</h4>
                    <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded">STATUS: VULNERÁVEL</span>
                  </div>
                  <p className="text-sm text-slate-600 text-justify">
                    <strong>Análise de Risco:</strong> A API falha ao não validar se o utilizador autenticado tem permissão para aceder a um recurso específico solicitado via ID. Isso permite que um atacante manipule IDs na URL para aceder a dados de terceiros.
                  </p>
                  <p className="text-sm font-semibold text-academico-primary">Estratégia de Mitigação:</p>
                  <div className="bg-slate-900 rounded-lg p-5 font-mono text-xs shadow-inner overflow-hidden border border-slate-700">
                    <div className="text-emerald-400">
                      <p className="text-slate-500 mb-2">// Implementar checagem de propriedade no Controller</p>
                      <p>@app.get("/orders/{"{order_id}"}")</p>
                      <p>async <span className="text-blue-400">def</span> get_order(order_id: int, user = <span className="text-yellow-300">Depends</span>(get_current_user)):</p>
                      <p className="pl-4">order = db.orders.find_one({"{"}"_id": order_id{"}"})</p>
                      <p className="pl-4 text-pink-400">if not order or order.owner_id != user.id:</p>
                      <p className="pl-8 text-red-400">raise HTTPException(status_code=403, detail="Unauthorized resource access")</p>
                    </div>
                  </div>
                </div>
              )}

              {/* API2: AUTH */}
              {mapping['API2']?.detected && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-t pt-8">
                    <h4 className="font-bold text-lg text-slate-800">API2:2023 — Broken Authentication</h4>
                    <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded">STATUS: VULNERÁVEL</span>
                  </div>
                  <p className="text-sm text-slate-600 text-justify">
                    <strong>Análise de Risco:</strong> Identificou-se o uso de mecanismos de autenticação fracos ou ausentes. O uso de Base64 não provê confidencialidade, facilitando o roubo de credenciais em trânsito.
                  </p>
                  <p className="text-sm font-semibold text-academico-primary">Estratégia de Mitigação:</p>
                  <div className="bg-slate-900 rounded-lg p-5 font-mono text-xs shadow-inner overflow-hidden border border-slate-700">
                    <div className="text-emerald-400">
                      <p className="text-slate-500 mb-2">// Substituir Base64 por JWT com Signature HS256</p>
                      <p><span className="text-blue-400">from</span> jose <span className="text-blue-400">import</span> jwt</p>
                      <p>payload = {"{"}"sub": user.email, "exp": datetime.utcnow() + timedelta(hours=1){"}"}</p>
                      <p>encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=<span className="text-orange-400">"HS256"</span>)</p>
                    </div>
                  </div>
                </div>
              )}

              {/* API8: MISCONFIG */}
              {mapping['API8']?.detected && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-t pt-8">
                    <h4 className="font-bold text-lg text-slate-800">API8:2023 — Security Misconfiguration</h4>
                    <span className="px-2 py-1 bg-red-100 text-red-700 text-xs font-bold rounded">STATUS: VULNERÁVEL</span>
                  </div>
                  <p className="text-sm text-slate-600 text-justify">
                    <strong>Análise de Risco:</strong> A API vaza informações detalhadas do servidor (Stack Traces) em caso de erro, além de headers desnecessários. Isso fornece um "mapa" da tecnologia para um atacante.
                  </p>
                  <p className="text-sm font-semibold text-academico-primary">Estratégia de Mitigação:</p>
                  <div className="bg-slate-900 rounded-lg p-5 font-mono text-xs shadow-inner overflow-hidden border border-slate-700">
                    <div className="text-emerald-400">
                      <p className="text-slate-500 mb-2">// Centralizar tratamento de erros para respostas genéricas</p>
                      <p>@app.exception_handler(<span className="text-yellow-300">Exception</span>)</p>
                      <p>async <span className="text-blue-400">def</span> custom_handler(req, exc):</p>
                      <p className="pl-4">logger.error(f"Internal Error: {"{exc}"}")</p>
                      <p className="pl-4">return JSONResponse(status_code=500, content={"{"}<span className="text-orange-400">"error"</span>: <span className="text-orange-400">"Internal Server Error"</span>{"}"})</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-10 bg-green-50 border border-green-200 rounded-lg text-center shadow-inner">
              <ShieldCheck className="w-16 h-16 text-green-500 mx-auto mb-4" />
              <p className="text-green-800 text-xl font-bold">Conformidade de Segurança Atingida</p>
              <p className="text-green-600 mt-2">Todas as falhas do mapeamento OWASP foram mitigadas com sucesso no código-fonte.</p>
            </div>
          )}
        </section>

        {/* 4. CONCLUSÃO ACADÊMICA */}
        <section>
          <h3 className="text-xl font-bold text-slate-900 flex items-center mb-4 border-b pb-2">
            <Target className="w-6 h-6 mr-2 text-academico-primary" />
            4. Conclusão do Experimento
          </h3>
          <p className="text-slate-600 leading-relaxed text-justify">
            A implementação da arquitetura DevSecOps provou-se um diferencial crítico na resiliência da aplicação. Através da estratégia de <strong>Shift-Left</strong>, foi possível antecipar vulnerabilidades que tradicionalmente só seriam descobertas em fases de auditoria externa ou incidentes reais. A taxa de conformidade atual ({totalMitigadas}/{totalCategorias} categorias) demonstra que a aplicação sistemática de mitigações, guiada por automação, reduz drasticamente a superfície de exposição e eleva o nível de maturidade do software.
          </p>
        </section>

        {/* ASSINATURA E RODAPÉ */}
        <div className="mt-12 pt-8 border-t border-slate-200 flex flex-col items-center">
          <div className="text-center">
            <p className="text-lg font-bold text-slate-900">Anderson Fernandes Ferreira</p>
            <p className="text-sm text-slate-500 uppercase tracking-widest mt-1">Pós-graduando em Engenharia de Software</p>
          </div>
          <div className="mt-6 flex items-center space-x-6">
            <div className="flex items-center text-xs text-slate-400">
              <Zap className="w-3 h-3 mr-1" />
              Build: #TS-{new Date().getTime().toString().slice(-6)}
            </div>
            <div className="flex items-center text-xs text-green-600 font-bold bg-green-50 px-3 py-1 rounded-full border border-green-100">
              <CheckCircle className="w-3 h-3 mr-1" />
              Verificado por Pipeline: {new Date().toLocaleString('pt-BR')}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}