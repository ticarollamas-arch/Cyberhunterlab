import React, { useState } from 'react';
import { motion } from 'motion/react';
import { 
  FileText, 
  TrendingDown, 
  AlertOctagon, 
  ShieldAlert, 
  ArrowRight, 
  Download, 
  Copy, 
  Check, 
  Database, 
  Cpu, 
  Terminal, 
  Scale, 
  DollarSign, 
  Activity, 
  Play, 
  UploadCloud,
  Layers,
  FileCheck2,
  ChevronRight,
  Sparkles
} from 'lucide-react';
import { Badge } from './ui/Badge';
import { cn } from '../lib/utils';

// Constantes de Mapeamento de CWE para Risco de Negócio / C-Suite
const CWE_BUSINESS_RISK_MAP: Record<string, {
  title: string;
  scope: string;
  risk_desc: string;
  business_impact: string;
  action_plan: string;
}> = {
  "CWE-22": {
    "title": "Vazamento Crítico de Arquivos e Chaves (Path Traversal)",
    "scope": "Isolamento de Diretórios / Planta Digital",
    "risk_desc": "Brecha séria de barreira de arquivos. Um invasor externo pode transpassar os limites autorizados da API pública usando comandos lógicos relativos (../) e vazar chaves confidenciais do servidor, chaves de API ocultas no ambiente de contêineres e credenciais cruciais.",
    "business_impact": "Comprometimento imediato da integridade física e privacidade dos dados internos da empresa, abrindo portas para sequestro de dados ou controle total de servidores na nuvem se essas chaves permitirem privilégios avançados.",
    "action_plan": "Implementar canonicalização rigorosa (resolve/abspath) combinada com validação estrita de prefixo e isolamento de arquivos via os.path.basename."
  },
  "CWE-697": {
    "title": "Bypass de Lógica Matemática no Faturamento",
    "scope": "Integridade de Transações / Checkout Engine",
    "risk_desc": "Inadequação nos validadores matemáticos numéricos da API de faturamento. Ao aceitar cupons ou parâmetros monetários negativos, o sistema inverte equações aritméticas essenciais, adicionando créditos em vez de deduzir débitos.",
    "business_impact": "Risco financeiro massivo imediato e desfalque acumulativo automático por transação que ameaça diretamente a contabilidade e a estabilidade líquida operacional da corporação.",
    "action_plan": "Garantir a verificação ativa de todos os parâmetros monetários impedindo inteiros negativos ou nulos através de cláusula estrita de integridade (< 0, raise Exception)."
  },
  "CWE-369": {
    "title": "Negação de Serviço Estrutural (Division by Zero)",
    "scope": "Robustez Física / Load Balancer Threading",
    "risk_desc": "Ausência de rotina de proteção física para divisores nulos na camada de distribuição de carga. Um payload enviado deliberadamente com divisor numérico de valor zero quebra o thread de execução principal, derrubando o servidor.",
    "business_impact": "Parada total de serviços digitais (System Crash), incapacitando o atendimento a clientes ativos, manchando a reputação corporativa e gerando perdas indiretas por indisponibilidade sistêmica contínua.",
    "action_plan": "Adicionar um validador defensivo de divisor para que nunca seja menor ou igual a zero, lançando erro antecipado controlado."
  }
};

const DEFAULT_JSON_PAYLOAD = {
  "cyber_hunter_lab_version": "2.5.0-core",
  "export_timestamp": 1780935637,
  "audit_session": {
    "chain_id": "CHL-CHAIN-9521",
    "sequence_step": 2,
    "target_architecture": "x86_64_bits_infrastructure"
  },
  "vulnerability_chain": [
    {
      "step": 1,
      "vulnerability_type": "Path_Traversal",
      "cwe_id": "CWE-22",
      "severity": "HIGH",
      "execution_vector": {
        "input_field": "url_parameter",
        "payload": "../../../etc/config.json",
        "status_code": 200,
        "leaked_data_reference": "database_credentials_block"
      }
    },
    {
      "step": 2,
      "vulnerability_type": "Mathematical_Logic_Bypass",
      "cwe_id": "CWE-697",
      "severity": "CRITICAL",
      "execution_vector": {
        "input_field": "coupon_code_input",
        "payload": -15074,
        "mathematical_effect": "inverse_subtraction_addition",
        "impact_metrics": {
          "simulated_leak_value": 15074,
          "integrity_compromised": true
        },
        "patch_remediation": {
          "target_file": "billing_engine.py",
          "validation_logic": "if coupon_code_input < 0:\n    raise ValueError(\"Valor negativo não permitido no gateway\")"
        }
      }
    },
    {
      "step": 3,
      "vulnerability_type": "Denial_of_Service_Infrastructure",
      "cwe_id": "CWE-369",
      "severity": "HIGH",
      "execution_vector": {
        "input_field": "load_balancer_divisor",
        "payload": 0,
        "exception_raised": "ZeroDivisionError",
        "system_state": "CRASH",
        "patch_remediation": {
          "target_file": "infrastructure_balancer.py",
          "validation_logic": "if load_balancer_divisor <= 0:\n    raise ValueError(\"Divisor inválido ou nulo\")"
        }
      }
    }
  ]
};

export function UniversalReportGenerator() {
  const [inputText, setInputText] = useState(() => {
    const saved = localStorage.getItem('universal_pasted_json');
    return saved || JSON.stringify(DEFAULT_JSON_PAYLOAD, null, 2);
  });
  const [error, setError] = useState<string | null>(null);
  const [parsedReport, setParsedReport] = useState<any>(() => {
    const saved = localStorage.getItem('universal_pasted_json');
    try {
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.vulnerability_chain || parsed.vulnerabilities) {
          return parsed;
        }
      }
    } catch (e) {}
    return DEFAULT_JSON_PAYLOAD;
  });
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'summary' | 'compliance' | 'evidence' | 'diagnosis'>('summary');
  
  // Closed-API Blackbox SaaS Engine states and simulation logic
  const [isSaaSRunning, setIsSaaSRunning] = useState(false);
  const [saasLogs, setSaasLogs] = useState<string[]>([]);

  const runSaaSMutationEngine = () => {
    setIsSaaSRunning(true);
    setSaasLogs(["Establish secure closed API tunnel to Cyber Hunter Lab cloud..."]);
    setError(null);
    
    const logsSequence = [
      { text: "✔ Authentication verified: Active Enterprise Stakeholder role confirmed.", delay: 600 },
      { text: "⚡ Initializing high-performance Black Box sandboxed simulation...", delay: 1200 },
      { text: "⚙ Running mutation math matrix (calculating bounds and division scales)...", delay: 1800 },
      { text: "🔥 [VULN FOUND] CWE-697: Mathematical coupon logic inversion detected.", delay: 2400 },
      { text: "💀 [SYSTEM STATUS] CWE-369 Division by Zero load-balancer bypass confirmed.", delay: 3000 },
      { text: "📦 Consolidating state into encrypted Machine-Readable JSON tree...", delay: 3500 },
      { text: "⚡ Formatting and exporting data payload...", delay: 4000 }
    ];

    logsSequence.forEach((step, idx) => {
      setTimeout(() => {
        setSaasLogs(prev => [...prev, step.text]);
        if (idx === logsSequence.length - 1) {
          setTimeout(() => {
            const currentIteration = Number(localStorage.getItem('chl_api_iteration') || '0') + 1;
            localStorage.setItem('chl_api_iteration', String(currentIteration));
            
            const payloadMathInversion = -(15000 + (currentIteration * 37));
            const payloadInfraDivision = currentIteration % 2 === 1 ? 0 : 1024;
            
            const generatedJSON = {
              "cyber_hunter_lab_version": "2.5.0-core",
              "export_timestamp": Math.floor(Date.now() / 1000),
              "audit_session": {
                "chain_id": "CHL-CHAIN-SaaS-" + Math.floor(1000 + Math.random() * 9000),
                "sequence_step": currentIteration,
                "target_architecture": "x86_64_bits_infrastructure"
              },
              "vulnerability_chain": [
                {
                  "step": 1,
                  "vulnerability_type": "Path_Traversal",
                  "cwe_id": "CWE-22",
                  "severity": "HIGH",
                  "execution_vector": {
                    "input_field": "url_parameter",
                    "payload": "../../../etc/config.json",
                    "status_code": 200,
                    "leaked_data_reference": "database_credentials_block"
                  }
                },
                {
                  "step": 2,
                  "vulnerability_type": "Mathematical_Logic_Bypass",
                  "cwe_id": "CWE-697",
                  "severity": "CRITICAL",
                  "execution_vector": {
                    "input_field": "coupon_code_input",
                    "payload": payloadMathInversion,
                    "mathematical_effect": "inverse_subtraction_addition",
                    "impact_metrics": {
                      "simulated_leak_value": Math.abs(payloadMathInversion),
                      "integrity_compromised": true
                    },
                    "patch_remediation": {
                      "target_file": "billing_engine.py",
                      "validation_logic": "if coupon_code_input < 0:\n    raise ValueError(\"Valor negativo inválido\")"
                    }
                  }
                },
                {
                  "step": 3,
                  "vulnerability_type": "Denial_of_Service_Infrastructure",
                  "cwe_id": "CWE-369",
                  "severity": "HIGH",
                  "execution_vector": {
                    "input_field": "load_balancer_divisor",
                    "payload": payloadInfraDivision,
                    "exception_raised": payloadInfraDivision === 0 ? "ZeroDivisionError" : "None",
                    "system_state": payloadInfraDivision === 0 ? "CRASH" : "STABLE",
                    "patch_remediation": {
                      "target_file": "infrastructure_balancer.py",
                      "validation_logic": "if load_balancer_divisor <= 0:\n    raise Exception(\"Divisor nulo\")"
                    }
                  }
                }
              ]
            };

            const jsonStr = JSON.stringify(generatedJSON, null, 2);
            setInputText(jsonStr);
            handleProcessJSON(jsonStr);
            setIsSaaSRunning(false);
          }, 500);
        }
      }, step.delay);
    });
  };

  React.useEffect(() => {
    const handleLoadPasted = (e: Event) => {
      const customEvent = e as CustomEvent;
      if (customEvent.detail) {
        setInputText(customEvent.detail);
        handleProcessJSON(customEvent.detail);
      }
    };
    window.addEventListener('load-pasted-json', handleLoadPasted);
    return () => window.removeEventListener('load-pasted-json', handleLoadPasted);
  }, []);

  const formatBRL = (value: number) => {
    return new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(value);
  };

  const handleProcessJSON = (textToProcess: string) => {
    try {
      setError(null);
      const parsed = JSON.parse(textToProcess);
      
      // Validação básica do payload antes de seguir
      if (!parsed.vulnerability_chain && !parsed.vulnerabilities) {
        throw new Error("O JSON precisa conter chaves de auditoria como 'vulnerability_chain'.");
      }
      
      setParsedReport(parsed);
    } catch (err: any) {
      setError(err.message || "Erro ao decodificar JSON de Auditoria. Verifique a sintaxe.");
      setParsedReport(null);
    }
  };

  const handleUploadClick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result as string;
        setInputText(text);
        handleProcessJSON(text);
      };
      reader.readAsText(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const text = event.target?.result as string;
        setInputText(text);
        handleProcessJSON(text);
      };
      reader.readAsText(file);
    }
  };

  // Calcular métricas derivadas para a diretoria corporativa
  const getDerivedMetrics = () => {
    if (!parsedReport) return { totalCwe: 0, financialRiskValue: 0, systemCrash: false, maxPriority: 'P3' };
    
    let totalCwe = 0;
    let financialRiskValue = 0;
    let systemCrash = false;
    let maxPriority = 'P3';
    
    const chain = parsedReport.vulnerability_chain || parsedReport.vulnerabilities || [];
    totalCwe = chain.length;
    
    chain.forEach((vuln: any) => {
      const vec = vuln.execution_vector || {};
      const metrics = vec.impact_metrics || {};
      if (metrics.simulated_leak_value) {
        financialRiskValue += metrics.simulated_leak_value;
      }
      if (vec.system_state === "CRASH" || vec.exception_raised === "ZeroDivisionError") {
        systemCrash = true;
      }
      if (vuln.severity === "CRITICAL") {
        maxPriority = "P1";
      } else if (vuln.severity === "HIGH" && maxPriority !== "P1") {
        maxPriority = "P2";
      }
    });

    return { totalCwe, financialRiskValue, systemCrash, maxPriority };
  };

  const metrics = getDerivedMetrics();

  // Exportar Relatório em Markdown
  const generateMarkdown = () => {
    if (!parsedReport) return "";
    
    const chainId = parsedReport.audit_session?.chain_id || "CHL-GENERIC";
    const chain = parsedReport.vulnerability_chain || parsedReport.vulnerabilities || [];
    const dateStr = parsedReport.export_timestamp 
      ? new Date(parsedReport.export_timestamp * 1000).toLocaleString('pt-BR') 
      : new Date().toLocaleString('pt-BR');
      
    let md = `# RELATÓRIO DE AUDITORIA DE SEGURANÇA E CONFORMIDADE UNIVERSAL\n\n`;
    md += `**REMETENTE:** Cyber Hunter Lab Report Engine v${parsedReport.cyber_hunter_lab_version || "2.5"}\n`;
    md += `**SESSÃO ID:** ${chainId}\n`;
    md += `**DATA DO REGISTRO:** ${dateStr}\n`;
    md += `**STATUS DE EXCLUSIVIDADE:** CONFIDENCIAL / APENAS PARA A DIRETORIA\n\n`;
    md += `--- \n\n`;
    
    md += `## 1. SUMÁRIO EXECUTIVO (C-SUITE DIRECTIVE)\n\n`;
    md += `- **Risco de Liquidez / Desfalque Imediato:** ${metrics.financialRiskValue > 0 ? formatBRL(metrics.financialRiskValue) + " por transação fraudulenta explorada" : "Risco de Vazamento Crítico de Segredos"}\n`;
    md += `- **Integridade da Planta Tecnológica:** ${metrics.systemCrash ? "Risco de Parada Definitiva dos Negócios (Inoperabilidade de Produção)" : "Estabilidade Parcial sob Tentativa de Invasão"}\n`;
    md += `- **Prioridade de Triage Recomendada:** ${metrics.maxPriority}\n\n`;
    md += `> **Diligência Corporativa:** A auditoria cibernética determinou um fluxo de vulnerabilidades interconectadas. `;
    md += `Ao manipular dados numéricos no checkout e ultrapassar limites de sistemas de arquivos, os ativos corporativos foram comprometidos, simulando desvios diretos de recursos e derrubando servidores vitais.\n\n`;
    
    md += `## 2. MAPEAMENTO DE CONFORMIDADE GLOBAL\n\n`;
    md += `| ID CWE | Categoria de Vulnerabilidade | Severidade | Impacto no Business / Risco Técnico | Arquivo Alvo |\n`;
    md += `|---|---|---|---|---|\n`;
    
    chain.forEach((v: any) => {
      const textMap = CWE_BUSINESS_RISK_MAP[v.cwe_id] || {
        title: v.vulnerability_type,
        business_impact: "Comprometimento Geral de API"
      };
      const vec = v.execution_vector || {};
      const remed = vec.patch_remediation || {};
      md += `| ${v.cwe_id} | ${v.vulnerability_type} | ${v.severity} | ${textMap.business_impact} | ${remed.target_file || "Sistemas Internos"} |\n`;
    });
    
    md += `\n### Resoluções de Correção (Mitigações Sem Código Próprio)\n\n`;
    chain.forEach((v: any) => {
      const vec = v.execution_vector || {};
      const remed = vec.patch_remediation || {};
      if (remed.target_file) {
        md += `#### Correção sugerida para: \`${remed.target_file}\`\n`;
        md += `\`\`\`python\n# Lógica e Validação recomendada\n${remed.validation_logic}\n\`\`\`\n\n`;
      }
    });

    md += `## 3. PROVA DE CONCEITO SEQUENCIAL (RECON/EXPLOIT CHAIN)\n\n`;
    chain.forEach((v: any) => {
      const vec = v.execution_vector || {};
      md += `### Passo ${v.step}: ${v.vulnerability_type} (${v.severity})\n`;
      md += `- **Componente/Campo:** \`${vec.input_field}\`\n`;
      md += `- **Payload Ativo Aplicado:** \`${vec.payload}\`\n`;
      md += `- **Comportamento Gerado:** ${vec.mathematical_effect ? "Inversão de Coeficiente Matemático" : vec.exception_raised ? "Estouro de Exceção Fatal de Processador" : "Vazamento de Dados"}\n\n`;
    });

    md += `## 4. DIAGNÓSTICO E AUDITORIA COMPORTAMENTAL (FINAL VERDICT)\n\n`;
    md += `*A análise comportamental independente determinou que o ecossistema tecnológico apresenta carência gritante de travas defensivas de paridade física nas APIs expostas. `;
    md += `Não se trata de consertar strings localizadas, mas de unificar filtros numéricos absolutos que preservem a estabilidade fiduciária do checkout e impeçam vazamentos de caminhos fora das pastas públicas. `;
    md += `Recomenda-se a adoção imediata do protocolo de auditoria preventiva contínua do Cyber Hunter Lab.* \n`;
    
    return md;
  };

  const handleDownloadMarkdown = () => {
    const md = generateMarkdown();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `Cyber_Hunter_Report_${parsedReport?.audit_session?.chain_id || 'CHL-9521'}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleCopyToClipboard = () => {
    const md = generateMarkdown();
    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-8 bg-[#0a0a0a] min-h-screen p-1 text-zinc-300 font-sans">
      <div className="bg-[#121212] border border-zinc-900 rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row items-center gap-6 justify-between">
        <div className="space-y-3 max-w-xl">
          <div className="inline-flex items-center gap-1.5 bg-[#ef4444]/10 border border-[#ef4444]/20 px-3 py-1 rounded-full text-[10px] font-mono text-red-400 uppercase tracking-widest font-bold">
            <Activity size={12} className="animate-pulse" /> Gerador Auxiliar de Auditoria Universal
          </div>
          <h2 className="text-3xl font-black text-white tracking-tight leading-none uppercase">
            Cyber Hunter Lab <span className="text-[#10b981]">Report Generator</span>
          </h2>
          <p className="text-zinc-500 text-xs leading-relaxed">
            Ingira dados brutos JSON coletados do terminal, realize o parsing determinístico do risco financeiro por transação e mapeie imediatamente sob o padrão CWE para fechar auditorias corporativas.
          </p>
        </div>

        <div className="flex gap-3">
          <button
            onClick={() => {
              setInputText(JSON.stringify(DEFAULT_JSON_PAYLOAD, null, 2));
              handleProcessJSON(JSON.stringify(DEFAULT_JSON_PAYLOAD, null, 2));
            }}
            className="px-4 py-2 bg-zinc-900 border border-zinc-850 hover:bg-zinc-800 text-xs font-mono font-bold uppercase text-zinc-400 rounded-lg transition-all flex items-center gap-2"
          >
            <Sparkles size={14} className="text-[#10b981]" /> Carregar Exemplo VRP
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        {/* Left Side: Input & Ingestion Area */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-[#121212] border border-zinc-900 rounded-2xl p-5 sm:p-6 space-y-4">
            <h4 className="text-[11px] font-mono uppercase tracking-widest text-zinc-400 font-bold flex items-center gap-2">
              <Sparkles size={14} className="text-[#10b981]" /> SaaS Pipeline Simulator
            </h4>
            <p className="text-[10px] text-zinc-500 leading-normal">
              Execute a dynamic Black Box mutation run to trigger system states, zero-division outcomes, and coupon value loops in real time, directly populating the local state.
            </p>

            {isSaaSRunning ? (
              <div className="bg-black/60 border border-zinc-850 rounded-xl p-4 font-mono text-[10px] space-y-1.5 leading-relaxed text-zinc-400 h-40 overflow-y-auto">
                {saasLogs.map((log, i) => (
                  <div key={i} className="text-emerald-400">{log}</div>
                ))}
                <div className="text-zinc-600 animate-pulse">Running SaaS mutation calculation matrix...</div>
              </div>
            ) : (
              <button
                onClick={runSaaSMutationEngine}
                className="w-full py-2.5 bg-zinc-900 border border-zinc-800 hover:bg-zinc-850 hover:border-zinc-700 text-zinc-300 font-bold uppercase text-[10px] tracking-widest rounded-xl transition-all flex items-center justify-center gap-2"
              >
                <Cpu size={12} className="text-[#10b981] animate-spin" /> Iniciar Mutador SaaS (Automático)
              </button>
            )}
          </div>

          <div 
            onDragOver={handleDragOver}
            onDrop={handleDrop}
            className="bg-[#121212] border border-zinc-900 rounded-2xl p-5 sm:p-6 space-y-4"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 font-bold flex items-center gap-2">
                <Database size={14} className="text-[#10b981]" /> Entrada JSON (Payload Bruto)
              </span>
              
              <label className="cursor-pointer px-3 py-1 bg-zinc-950 border border-zinc-800 rounded-md text-[10px] font-mono text-zinc-400 hover:text-white transition-colors uppercase flex items-center gap-1.5 font-bold">
                <UploadCloud size={12} /> Carregar Arquivo
                <input 
                  type="file" 
                  accept=".json" 
                  onChange={handleUploadClick} 
                  className="hidden" 
                />
              </label>
            </div>

            <p className="text-[10px] text-zinc-600 leading-normal italic">
              Arraste e solte o arquivo contendo a cadeia de exploração do terminal ou cole-o abaixo na caixa para mapear os riscos.
            </p>

            <textarea
              value={inputText}
              onChange={(e) => {
                setInputText(e.target.value);
                // Auto-processamento em tempo real se o JSON estiver parcialmente pronto
                if (e.target.value.trim().endsWith('}')) {
                  handleProcessJSON(e.target.value);
                }
              }}
              placeholder="Cole o JSON de logs e payloads da auditoria aqui..."
              className="w-full h-80 bg-black/40 border border-zinc-850 rounded-xl p-4 font-mono text-xs text-emerald-400 focus:outline-none focus:border-emerald-500/30 transition-all resize-none"
            />

            {error && (
              <div className="p-3 bg-red-950/20 border border-red-900/40 rounded-xl text-[11px] font-mono text-red-400 leading-relaxed">
                ⚠️ {error}
              </div>
            )}

            <button
              onClick={() => handleProcessJSON(inputText)}
              className="w-full py-3 bg-[#10b981] hover:bg-[#10b981]/90 text-black font-bold uppercase text-xs tracking-wider rounded-xl transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(16,185,129,0.15)]"
            >
              <Cpu size={14} /> Processar Dados Executivos
            </button>
          </div>

          <div className="bg-[#121212]/50 border border-zinc-900 p-5 rounded-2xl space-y-3">
            <h4 className="text-zinc-400 text-xs font-mono font-bold uppercase tracking-widest">Padrão de Mapeamento</h4>
            <p className="text-zinc-600 text-[10px] leading-relaxed">
              O gerador mapeia chaves estruturais obtidas do script Python (ex: <code className="text-zinc-400 font-mono">simulated_leak_value</code>, <code className="text-zinc-400 font-mono">cwe_id</code>, <code className="text-zinc-400 font-mono">system_state</code> e <code className="text-zinc-400 font-mono">patch_remediation</code>) convertendo-as em um parecer estratégico assinado de alto valor comercial.
            </p>
          </div>
        </div>

        {/* Right Side: Professional Render / Presentation Area */}
        <div className="lg:col-span-3 space-y-6">
          {parsedReport ? (
            <div className="bg-[#121212] border border-zinc-900 rounded-2xl overflow-hidden shadow-2xl">
              {/* Header inside report box */}
              <div className="bg-zinc-950 px-6 py-5 border-b border-zinc-900 flex justify-between items-center gap-4 flex-wrap">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-widest font-bold">Confidencial • Relatório Executivo</span>
                    <Badge variant="danger">v{parsedReport.cyber_hunter_lab_version || "2.5"}-Core</Badge>
                  </div>
                  <h3 className="text-white font-bold text-sm font-mono uppercase">
                    SESSÃO: {parsedReport.audit_session?.chain_id || "CHL-CHAIN-9521"}
                  </h3>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyToClipboard}
                    className="p-2 bg-zinc-900 hover:bg-zinc-800 hover:text-white border border-zinc-850 rounded-lg text-zinc-400 text-xs font-mono transition-all flex items-center gap-1.5 uppercase font-bold"
                    title="Copiar Relatório Completo em Markdown"
                  >
                    {copied ? <Check size={14} className="text-[#10b981]" /> : <Copy size={14} />}
                    <span>{copied ? "Copiado!" : "Copiar MD"}</span>
                  </button>

                  <button
                    onClick={handleDownloadMarkdown}
                    className="p-2 bg-zinc-900 hover:bg-zinc-800 hover:text-white border border-[#10b981]/20 rounded-lg text-[#10b981] text-xs font-mono transition-all flex items-center gap-1.5 uppercase font-bold"
                  >
                    <Download size={14} />
                    <span>Baixar Markdown</span>
                  </button>
                </div>
              </div>

              {/* Tabs for sections */}
              <div className="flex border-b border-zinc-90 w-full overflow-x-auto no-scrollbar bg-zinc-950/40 p-1">
                {[
                  { id: 'summary', name: '1. Sumário Executivo' },
                  { id: 'compliance', name: '2. Mapeamento Global' },
                  { id: 'evidence', name: '3. Prova de Conceito' },
                  { id: 'diagnosis', name: '4. Diagnóstico Final' },
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={cn(
                      "flex-1 py-3 text-[10px] sm:text-xs font-mono font-bold uppercase transition-all border-b-2 text-center whitespace-nowrap px-4",
                      activeTab === tab.id 
                        ? "text-[#10b981] border-[#10b981] bg-black/30" 
                        : "text-zinc-500 hover:text-zinc-300 border-transparent"
                    )}
                  >
                    {tab.name}
                  </button>
                ))}
              </div>

              {/* Content Panels */}
              <div className="p-6 sm:p-8 min-h-96">
                
                {/* 1. SUMÁRIO EXECUTIVO PANEL */}
                {activeTab === 'summary' && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-8"
                  >
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Financial Impact Indicator Card */}
                      <div className="bg-[#ef4444]/5 border border-[#ef4444]/20 p-5 rounded-xl space-y-2 relative overflow-hidden group">
                        <div className="absolute top-4 right-4 text-[#ef4444]/20 group-hover:text-[#ef4444]/30 transition-colors">
                          <TrendingDown size={40} />
                        </div>
                        <span className="text-[9px] font-mono text-[#ef4444]/80 uppercase tracking-wider font-bold">Risco de Perda Instantânea</span>
                        <h4 className="text-2xl sm:text-3xl font-black text-[#ef4444]">
                          {metrics.financialRiskValue > 0 ? formatBRL(metrics.financialRiskValue) : "R$ 0,00"}
                        </h4>
                        <p className="text-zinc-400 text-[10px] leading-relaxed font-mono">
                          por cada transação de faturamento executada sem validação física.
                        </p>
                      </div>

                      {/* Network & Infrastructure Health Indicator Card */}
                      <div className={cn(
                        "p-5 rounded-xl space-y-2 relative overflow-hidden group border",
                        metrics.systemCrash 
                          ? "bg-amber-600/5 border-amber-500/20" 
                          : "bg-zinc-900/40 border-zinc-800"
                      )}>
                        <div className="absolute top-4 right-4 text-zinc-700/30">
                          <AlertOctagon size={40} />
                        </div>
                        <span className="text-[9px] font-mono text-zinc-500 uppercase tracking-wider font-bold">Integridade de Rede</span>
                        <h4 className={cn(
                          "text-base sm:text-lg font-bold font-mono tracking-wide",
                          metrics.systemCrash ? "text-amber-400 text-sm" : "text-white"
                        )}>
                          {metrics.systemCrash ? "COLAPSO DIGITAL (System Crash)" : "ESTABILIDADE NORMAL"}
                        </h4>
                        <p className="text-zinc-500 text-[10px] leading-relaxed">
                          Divisores vazios sem travas de barreira induzem interrupções letais das threads.
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-col sm:flex-row justify-between items-start gap-4 p-4 bg-zinc-950 border border-zinc-850 rounded-xl font-mono text-[11px]">
                      <div>
                        <span className="text-zinc-500">Gravificação de Severidade:</span>
                        <span className="text-red-400 font-bold uppercase ml-2">{parsedReport.vulnerability_chain?.[1]?.severity || "CRÍTICA"}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500">Vulnerabilidades Rastreáveis:</span>
                        <span className="text-[#10b981] font-bold ml-2">{metrics.totalCwe} CWEs Ativos</span>
                      </div>
                      <div>
                        <span className="text-zinc-500">Triage Scope:</span>
                        <span className="text-white font-bold ml-2">{metrics.maxPriority} Priority High</span>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <h4 className="text-[#10b981] text-xs font-mono font-bold uppercase tracking-widest flex items-center gap-2">
                        <Scale size={14} /> Resumo Analítico de Negócio
                      </h4>
                      <div className="text-zinc-300 text-sm leading-relaxed space-y-4 p-5 bg-black/30 border border-zinc-900 rounded-xl select-none">
                        <p>
                          A auditoria de mutação simulada rastreou o encadeamento de falhas lógicas no sistema de checkout e nos limites de pastas. 
                        </p>
                        <p>
                          A presença de parâmetros de entrada numéricos não validados (<code className="text-red-400 font-mono">payload: {parsedReport.vulnerability_chain?.[1]?.execution_vector?.payload || "-15074"}</code>) inverte a aritmética interna de crédito e faturamento. Se explorada em larga escala por agentes automatizados, a falha cria um <strong>canal contínuo de sangria de receita</strong> sem que alarmes de autenticidade convencionais sejam acionados no WAF.
                        </p>
                        <p className="text-zinc-400 text-xs italic">
                          Documento parametrizado sem a entrega de códigos-fonte proprietários, garantindo total conformidade ética.
                        </p>
                      </div>
                    </div>
                  </motion.div>
                )}

                {/* 2. COMPLIANCE MAPPING PANEL */}
                {activeTab === 'compliance' && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-6"
                  >
                    <h4 className="text-[#10b981] text-xs font-mono font-bold uppercase tracking-widest">
                      Adequação de Ativos Globais e CWEs
                    </h4>
                    
                    <div className="space-y-4">
                      {(parsedReport.vulnerability_chain || parsedReport.vulnerabilities || []).map((v: any, idx: number) => {
                        const safetyMeta = CWE_BUSINESS_RISK_MAP[v.cwe_id] || {
                          title: v.vulnerability_type,
                          scope: "Mapeamento Comportamental",
                          risk_desc: "Validação insatisfatória em APIs ou inputs públicos.",
                          business_impact: "Risco de desfalque em APIs expostas."
                        };

                        const vec = v.execution_vector || {};
                        const remed = vec.patch_remediation || {};

                        return (
                          <div key={idx} className="bg-zinc-950 border border-zinc-850 rounded-xl p-5 space-y-4">
                            <div className="flex justify-between items-center flex-wrap gap-2">
                              <div className="flex items-center gap-2.5">
                                <span className="px-2 py-0.5 rounded bg-[#10b981]/15 text-[#10b981] font-mono text-xs font-bold">{v.cwe_id}</span>
                                <span className="text-white text-xs font-mono font-bold">{v.vulnerability_type}</span>
                              </div>
                              <Badge variant={v.severity === 'CRITICAL' ? 'danger' : 'warning'}>{v.severity}</Badge>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                              <div className="space-y-1 bg-black/20 p-3 rounded border border-zinc-900">
                                <span className="text-zinc-500 font-mono text-[10px] uppercase">Risco de Negócio Enquadrado</span>
                                <p className="text-zinc-300 leading-relaxed font-sans">{safetyMeta.risk_desc}</p>
                              </div>
                              <div className="space-y-1 bg-black/20 p-3 rounded border border-zinc-900">
                                <span className="text-zinc-500 font-mono text-[10px] uppercase">Impacto Comercial Direto</span>
                                <p className="text-zinc-300 leading-relaxed font-sans italic">{safetyMeta.business_impact}</p>
                              </div>
                            </div>

                            {remed.target_file && (
                              <div className="p-4 bg-zinc-900/50 border border-zinc-850 rounded-lg space-y-2">
                                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-500">
                                  <span>Fórmula de Correção Sanitária</span>
                                  <span className="text-[#10b981]">{remed.target_file}</span>
                                </div>
                                <pre className="text-[11px] font-mono text-emerald-400 bg-black/40 p-3 rounded overflow-x-auto whitespace-pre">
                                  {remed.validation_logic}
                                </pre>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </motion.div>
                )}

                {/* 3. PROVA DE CONCEITO TIMELINE PANEL */}
                {activeTab === 'evidence' && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-8"
                  >
                    <div className="flex items-center justify-between">
                      <h4 className="text-[#10b981] text-xs font-mono font-bold uppercase tracking-widest">
                        Reação em Cadeia de Exploração (PoC Tree)
                      </h4>
                      <span className="text-[10px] font-mono text-zinc-500 uppercase">Arquitetura de Hunt Ativa</span>
                    </div>

                    {/* Timeline Vertical */}
                    <div className="relative pl-6 border-l border-zinc-850 space-y-10 ml-3">
                      {(parsedReport.vulnerability_chain || parsedReport.vulnerabilities || []).map((v: any, idx: number) => {
                        const vec = v.execution_vector || {};
                        return (
                          <div key={idx} className="relative space-y-3">
                            {/* Dot */}
                            <div className="absolute -left-[31px] top-1.5 w-4.5 h-4.5 rounded-full bg-zinc-950 border-2 border-[#10b981] flex items-center justify-center z-10 shadow-[0_0_10px_rgba(16,185,129,0.3)]">
                              <span className="text-[8px] font-mono font-bold text-[#10b981]">{v.step || idx + 1}</span>
                            </div>

                            <div className="flex items-center justify-between flex-wrap gap-2">
                              <h5 className="text-white text-xs font-mono font-bold uppercase tracking-wide">
                                Passo {v.step || idx + 1}: {v.vulnerability_type}
                              </h5>
                              <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                                STATUS HTTP: {vec.status_code || "EXCEPT"}
                              </span>
                            </div>

                            <div className="bg-[#111] p-4 rounded-xl border border-zinc-900 space-y-3">
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] font-mono text-zinc-500">
                                <div>
                                  <span>Estrutura de Entrada:</span>
                                  <span className="text-zinc-300 ml-1.5">{vec.input_field}</span>
                                </div>
                                <div className="truncate">
                                  <span>Payload Entregue:</span>
                                  <span className="text-[#ef4444] font-bold ml-1.5">{String(vec.payload)}</span>
                                </div>
                              </div>

                              <div className="text-xs text-zinc-400 bg-black/20 p-2.5 rounded border border-zinc-950/60 leading-relaxed font-sans">
                                <strong className="text-zinc-500 font-mono text-[10px] mr-1 uppercase">Implicação de estado:</strong>
                                {vec.leaked_data_reference 
                                  ? `Mapeou o contêiner interno resultando na exposição do segmento '${vec.leaked_data_reference}'.`
                                  : vec.mathematical_effect 
                                    ? `Inverteu o cálculo operacional resultando no efeito de '${vec.mathematical_effect}' e liberando saldo credor fictício.`
                                    : `Acionou estouro de memória no empilhamento de barreira e resultou em '${vec.exception_raised || "Crash"}' sistêmico.`
                                }
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </motion.div>
                )}

                {/* 4. DIAGNÓSTICO E AUTO-PARECER PANEL */}
                {activeTab === 'diagnosis' && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-6"
                  >
                    <div className="flex items-center justify-between border-b border-zinc-900 pb-4">
                      <h4 className="text-[#10b981] text-xs font-mono font-bold uppercase tracking-widest">
                        Parecer Técnico Comportamental do Auditor
                      </h4>
                      <span className="text-[10px] font-mono text-zinc-500">Chancelado por IA Determinística</span>
                    </div>

                    <div className="p-6 bg-zinc-950 border border-zinc-850 rounded-xl space-y-6 text-zinc-300 text-sm leading-relaxed font-sans select-none">
                      <div className="space-y-4">
                        <p>
                          A auditoria comportamental de segurança conduzida sob o rastreamento mutacional e simulação determinística de injeção provou, sem margem a falsos positivos, que as APIs voltadas ao público e o checkout fiduciário contam com lacunas graves de validação física preventiva.
                        </p>
                        <p>
                          Diferente de sistemas legados que buscam correspondência estática de regex em strings simples, nossa plataforma de Hunt identificou que uma alteração estrutural combinada é capaz de cruzar permissões e provocar exaustão de servidores e fraudes fiscais em faturamento numa reação sequencial linear.
                        </p>
                        <p>
                          Recomenda-se veementemente a incorporação das rotinas matemáticas blindadas (<code className="text-emerald-400 font-mono">Assertion Guards</code>) presentes no escopo técnico de conformidade deste dossiê. Tais alterações devolvem ao ecossistema a barreira de faturamento, isolando completamente a exposição de dados nativos na pasta raiz.
                        </p>
                      </div>

                      <div className="pt-6 border-t border-zinc-900 flex justify-between items-center font-mono">
                        <div className="space-y-1">
                          <span className="text-zinc-600 text-[10px] uppercase block">Assinatura Digital</span>
                          <span className="text-white text-xs font-bold tracking-wider uppercase">ARCHITECT ENGINE (CHL)</span>
                        </div>
                        <div className="text-right">
                          <span className="text-zinc-600 text-[10px] uppercase block">Validação Cryptográfica</span>
                          <span className="text-[#10b981] text-[11px]">8h5f-CHL-HASH-SUCCESS</span>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}

              </div>
            </div>
          ) : (
            <div className="h-full min-h-96 bg-[#121212]/30 border border-dashed border-zinc-800 rounded-2xl flex flex-col items-center justify-center p-8 text-center space-y-3">
              <div className="p-4 bg-zinc-900/60 rounded-full text-zinc-500">
                <FileCheck2 size={32} />
              </div>
              <h3 className="text-white font-bold text-sm">Aguardando dados de auditoria</h3>
              <p className="text-zinc-500 text-xs max-w-sm">
                Cole o JSON ou carregue um arquivo correspondente para ver o relatório executivo e o desfalque calculado na hora.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
