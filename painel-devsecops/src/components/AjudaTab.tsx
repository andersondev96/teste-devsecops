import { BookOpen, Shield, Server, Code, Terminal, Layers, ArrowRight, Lock, FileJson } from 'lucide-react';

export function AjudaTab() {
    return (
        <div className="space-y-8 animate-in fade-in duration-500 text-slate-800 pb-12">

            {/* Cabeçalho */}
            <div className="flex justify-between items-end border-b pb-2">
                <h2 className="text-2xl font-bold flex items-center text-slate-800">
                    <BookOpen className="w-7 h-7 mr-3 text-academico-primary" />
                    Documentação do Projeto & Glossário DevSecOps
                </h2>
                <span className="text-sm text-slate-500 font-medium">Guia de Arquitetura - TCC</span>
            </div>

            <div className="space-y-10 max-w-6xl mx-auto">

                {/* 1. Visão Geral da Arquitetura */}
                <section className="bg-white p-8 rounded-lg shadow-sm border border-slate-200">
                    <h3 className="text-xl font-bold text-slate-800 flex items-center mb-6">
                        <Layers className="w-6 h-6 mr-2 text-blue-600" />
                        1. Arquitetura da Aplicação
                    </h3>
                    <p className="text-slate-600 mb-6 text-justify">
                        Este projeto simula um ecossistema real de engenharia de software onde uma aplicação moderna é submetida a um ciclo rigoroso de integração e entrega contínuas (CI/CD) com testes de segurança automatizados (Shift-Left Security).
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
                        <div className="bg-slate-50 p-6 rounded-lg border border-slate-200 shadow-inner">
                            <Server className="w-10 h-10 text-emerald-600 mx-auto mb-3" />
                            <h4 className="font-bold text-slate-800">Backend (A Vítima)</h4>
                            <p className="text-xs text-slate-500 mt-2">API RESTful desenvolvida em <strong>Python (FastAPI)</strong>. Inicialmente projetada com falhas estruturais (BOLA, Auth fraca, etc.), foi posteriormente mitigada com JWT e Middlewares.</p>
                        </div>
                        <div className="hidden md:flex items-center justify-center">
                            <ArrowRight className="w-8 h-8 text-slate-300" />
                        </div>
                        <div className="bg-slate-50 p-6 rounded-lg border border-slate-200 shadow-inner">
                            <Terminal className="w-10 h-10 text-orange-600 mx-auto mb-3" />
                            <h4 className="font-bold text-slate-800">Pipeline (O Inspetor)</h4>
                            <p className="text-xs text-slate-500 mt-2">Orquestrado via <strong>GitHub Actions</strong>. Executa ferramentas de auditoria no código fonte, dependências, imagem Docker e na aplicação em tempo real.</p>
                        </div>
                        <div className="hidden md:flex items-center justify-center">
                            <ArrowRight className="w-8 h-8 text-slate-300" />
                        </div>
                        <div className="bg-slate-50 p-6 rounded-lg border border-slate-200 shadow-inner">
                            <Code className="w-10 h-10 text-blue-600 mx-auto mb-3" />
                            <h4 className="font-bold text-slate-800">Frontend (O Relatório)</h4>
                            <p className="text-xs text-slate-500 mt-2">SPA desenvolvida em <strong>React + TypeScript + Tailwind</strong>. Consome os JSONs gerados pela pipeline e transforma-os em inteligência visual e gerencial.</p>
                        </div>
                    </div>
                </section>

                {/* 2. Glossário DevSecOps */}
                <section className="bg-white p-8 rounded-lg shadow-sm border border-slate-200">
                    <h3 className="text-xl font-bold text-slate-800 flex items-center mb-6">
                        <Shield className="w-6 h-6 mr-2 text-red-600" />
                        2. O Que é DevSecOps? (Glossário)
                    </h3>

                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm border-collapse">
                            <thead>
                                <tr className="bg-slate-100 text-slate-700">
                                    <th className="p-3 border-b font-bold w-1/4">Sigla / Conceito</th>
                                    <th className="p-3 border-b font-bold w-1/4">Ferramenta Usada</th>
                                    <th className="p-3 border-b font-bold">Definição Acadêmica</th>
                                </tr>
                            </thead>
                            <tbody className="text-slate-600">
                                <tr className="border-b hover:bg-slate-50 transition-colors">
                                    <td className="p-3 font-semibold text-slate-800">SAST</td>
                                    <td className="p-3"><span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded font-mono text-xs">Bandit</span></td>
                                    <td className="p-3"><strong>Static Application Security Testing:</strong> Analisa o código-fonte (White-box) sem executá-lo. Procura padrões inseguros, como senhas hardcoded ou queries SQL perigosas.</td>
                                </tr>
                                <tr className="border-b hover:bg-slate-50 transition-colors">
                                    <td className="p-3 font-semibold text-slate-800">SCA</td>
                                    <td className="p-3"><span className="px-2 py-1 bg-emerald-100 text-emerald-800 rounded font-mono text-xs">Safety</span></td>
                                    <td className="p-3"><strong>Software Composition Analysis:</strong> Inspeciona as bibliotecas de terceiros (ex: <i>requirements.txt</i>) cruzando as suas versões com bases de dados de CVEs conhecidas.</td>
                                </tr>
                                <tr className="border-b hover:bg-slate-50 transition-colors">
                                    <td className="p-3 font-semibold text-slate-800">DAST</td>
                                    <td className="p-3"><span className="px-2 py-1 bg-blue-100 text-blue-800 rounded font-mono text-xs">OWASP ZAP</span></td>
                                    <td className="p-3"><strong>Dynamic Application Security Testing:</strong> Analisa a aplicação em tempo de execução (Black-box). Tenta ativamente "invadir" a API testando falhas de autenticação e injeção.</td>
                                </tr>
                                <tr className="border-b hover:bg-slate-50 transition-colors">
                                    <td className="p-3 font-semibold text-slate-800">Container Security</td>
                                    <td className="p-3"><span className="px-2 py-1 bg-purple-100 text-purple-800 rounded font-mono text-xs">Trivy</span></td>
                                    <td className="p-3">Verifica o sistema operativo da imagem Docker e seus pacotes de infraestrutura em busca de vulnerabilidades antes do deploy.</td>
                                </tr>
                                <tr className="hover:bg-slate-50 transition-colors">
                                    <td className="p-3 font-semibold text-slate-800">Shift-Left</td>
                                    <td className="p-3 text-slate-400 italic">Conceito</td>
                                    <td className="p-3">Prática de mover a preocupação com a segurança para as fases mais iniciais do desenvolvimento ("para a esquerda" no cronograma), em vez de testar apenas no final.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                {/* 3. Vulnerabilidades Mitigadas */}
                <section className="bg-white p-8 rounded-lg shadow-sm border border-slate-200">
                    <h3 className="text-xl font-bold text-slate-800 flex items-center mb-6">
                        <Lock className="w-6 h-6 mr-2 text-slate-600" />
                        3. Estudo de Caso: Mitigações Aplicadas
                    </h3>
                    <p className="text-sm text-slate-600 mb-6">
                        Abaixo estão exemplos das principais correções aplicadas no backend (FastAPI) que resultaram na queda das métricas de vulnerabilidade do painel.
                    </p>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Bloco JWT */}
                        <div className="bg-slate-900 rounded-lg p-5 border border-slate-700 shadow-lg">
                            <div className="flex items-center text-slate-300 text-xs mb-3 border-b border-slate-700 pb-2">
                                <FileJson className="w-4 h-4 mr-2 text-yellow-400" />
                                <span>API2:2023 - Broken Authentication (Mitigação)</span>
                            </div>
                            <div className="font-mono text-xs text-emerald-400 space-y-1">
                                <p className="text-slate-400"># Substituição do Base64 por JWT Criptografado</p>
                                <p><span className="text-blue-400">def</span> create_access_token(data: dict):</p>
                                <p className="pl-4">expire = datetime.utcnow() + timedelta(minutes=30)</p>
                                <p className="pl-4">to_encode.update({"{"}<span className="text-orange-400">"exp"</span>: expire{"}"})</p>
                                <p className="pl-4">return jwt.<span className="text-blue-400">encode</span>(to_encode, SECRET_KEY, algorithm=<span className="text-orange-400">"HS256"</span>)</p>
                            </div>
                        </div>

                        {/* Bloco BOLA */}
                        <div className="bg-slate-900 rounded-lg p-5 border border-slate-700 shadow-lg">
                            <div className="flex items-center text-slate-300 text-xs mb-3 border-b border-slate-700 pb-2">
                                <FileJson className="w-4 h-4 mr-2 text-yellow-400" />
                                <span>API1:2023 - BOLA (Mitigação)</span>
                            </div>
                            <div className="font-mono text-xs text-emerald-400 space-y-1">
                                <p className="text-slate-400"># Validação de Propriedade do Recurso (Ownership)</p>
                                <p>@app.get(<span className="text-orange-400">"/users/{"{user_id}"}"</span>)</p>
                                <p><span className="text-blue-400">def</span> get_user(user_id: int, current_user = Depends(get_current_user)):</p>
                                <p className="pl-4 text-pink-400">if current_user["id"] != user_id:</p>
                                <p className="pl-8 text-red-400">raise HTTPException(status_code=403, detail="Acesso negado")</p>
                            </div>
                        </div>
                    </div>
                </section>

            </div>
        </div>
    );
}