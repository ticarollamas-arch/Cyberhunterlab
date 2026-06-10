import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  ChevronRight, 
  Lock, 
  Terminal, 
  Activity, 
  TrendingUp, 
  Layers, 
  Play, 
  Cpu, 
  CreditCard, 
  Check, 
  Star, 
  HelpCircle,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Wifi,
  Sparkles,
  RefreshCw,
  MessageSquare
} from 'lucide-react';
import { Badge } from './ui/Badge';

interface LandingPageProps {
  onStart: (bypassAuth?: boolean) => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onStart }) => {
  const [activeTab, setActiveTab] = useState<'features' | 'plans' | 'demo'>('features');
  const [billingPeriod, setBillingPeriod] = useState<'monthly' | 'annual'>('monthly');
  const [selectedPlan, setSelectedPlan] = useState<any | null>(null);
  const [showCheckout, setShowCheckout] = useState(false);
  const [checkoutStep, setCheckoutStep] = useState<'input' | 'processing' | 'success'>('input');
  
  // Checkout Form State
  const [cardName, setCardName] = useState('');
  const [cardNumber, setCardNumber] = useState('4111 2222 3333 4444');
  const [cardExpiry, setCardExpiry] = useState('12/28');
  const [cardCvc, setCardCvc] = useState('022');
  const [domainToVerify, setDomainToVerify] = useState('minhaempresa.com.br');

  // Terminal Simulation States
  const [terminalLines, setTerminalLines] = useState<string[]>([
    "CHL Kernel v5.2.0-core initialized.",
    "Connecting to Stateful Mutation Engine... OK",
    "Initializing sandboxed target isolation... OK",
    "Awaiting target domain launch..."
  ]);
  const [terminalStatus, setTerminalStatus] = useState<'idle' | 'running' | 'completed'>('idle');
  const [currentStep, setCurrentStep] = useState(0);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  const simulationSteps = [
    { text: "⚡ [MUTATION] Injecting stateful float mutations on checkout endpoints...", type: "info" },
    { text: "🎯 [TARGET] probing: https://minhaempresa.com.br/api/v1/billing/coupon", type: "info" },
    { text: "⚠️ [WARN] Non-canonical boundary detection. Directory escape patterns resolved.", type: "warning" },
    { text: "🔥 [CRITICAL] CWE-697: coupon_code_input accept integers < 0. Reverse mathematical subversion!", type: "danger" },
    { text: "💀 [SYSTEM_STATE: CRASH] CWE-369 Divison by zero raised ZeroDivisionError. Main balancer thread offline.", type: "danger" },
    { text: "📦 [EXPLOIT SEARCH] Generating Machine-Readable Exploit tree...", type: "info" },
    { text: "✔ [SUCCESS] Chain CHL-CHAIN-9521 completed. Simulated leak value: R$ 15.074,00.", type: "success" },
    { text: "📜 [REPORT] Executive translation pipeline ready for direct C-Suite presentation.", type: "success" }
  ];

  // Auto Scroll Terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLines]);

  // Terminal Runner Simulation
  const startTerminalSimulation = () => {
    if (terminalStatus === 'running') return;
    setTerminalStatus('running');
    setTerminalLines([
      "CHL Kernel v5.2.0-core initialized.",
      "Connecting to Stateful Mutation Engine... OK",
      "Initializing sandboxed target isolation... OK",
      "Domain verified: " + domainToVerify,
      "⚡ [START] Under audit engagement protocol..."
    ]);
    
    let i = 0;
    const interval = setInterval(() => {
      if (i < simulationSteps.length) {
        setTerminalLines(prev => [...prev, simulationSteps[i].text]);
        i++;
      } else {
        clearInterval(interval);
        setTerminalStatus('completed');
      }
    }, 1500);
  };

  const handleCheckoutSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCheckoutStep('processing');
    setTimeout(() => {
      setCheckoutStep('success');
    }, 2000);
  };

  const handleApplySignature = () => {
    setShowCheckout(false);
    onStart(true); // Bypass / Log them in instantly upon payment success!
  };

  const pricingPlans = [
    {
      id: 'core',
      name: 'Hunter Core',
      desc: 'Perfeito para pesquisadores autônomos e caçadores de recompensa iniciantes.',
      priceMonthly: 199,
      priceAnnual: 159,
      features: [
        'Acesso ao Gerador de Relatório Universal',
        'Parsing completo de payloads JSON',
        '5 Templates de PoC Legíveis por Máquina',
        'Exportação profissional em Markdown padrão C-Suite.md',
        'Suporte por e-mail (24h/48h)'
      ],
      badge: 'Básico',
      isPopular: false
    },
    {
      id: 'pro',
      name: 'Hunter Pro',
      desc: 'Mecanismo completo para consultores seniores de infraestrutura e startups.',
      priceMonthly: 599,
      priceAnnual: 479,
      features: [
        'Tudo do plano Core e mais:',
        'Acesso ao Motor de Mutação por Terminal de Estado',
        'Geração Automatizada de Impacto Financeiro (BRL)',
        'Suporte prioritário e imediato via WhatsApp',
        'Templates de bypass avançados contra WAF comuns',
        'Isolamento e controle local de auditorias ilimitadas'
      ],
      badge: 'Recomendado',
      isPopular: true
    },
    {
      id: 'enterprise',
      name: 'Enterprise / Planta Industrial',
      desc: 'Auditoria corporativa dedicada em nível operacional de alta governança.',
      priceMonthly: 1999,
      priceAnnual: 1599,
      features: [
        'Controle e triagem de API em nível de container',
        'Logs de auditoria e conformidade customizados',
        'Prevenção de escalada de permissão na nuvem',
        'Sessões de mentoria e suporte direto de arquitetos',
        'Relatórios customizados sob as regras regulatórias LGPD'
      ],
      badge: 'Corporativo',
      isPopular: false
    }
  ];

  return (
    <div className="min-h-screen bg-[#050505] text-white flex flex-col relative overflow-x-hidden font-sans selection:bg-emerald-500/20 selection:text-emerald-400">
      
      {/* Background Graphic Overlay */}
      <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
        <div className="absolute inset-x-0 top-0 h-96 bg-gradient-to-b from-emerald-950/20 to-transparent" />
        <div className="absolute -left-48 top-48 w-96 h-96 rounded-full bg-emerald-500/5 blur-[120px] pointer-events-none" />
        <div className="absolute -right-48 top-96 w-96 h-96 rounded-full bg-blue-500/5 blur-[120px] pointer-events-none" />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#10b981_1px,transparent_1px),linear-gradient(to_bottom,#10b981_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-[0.02]" />
      </div>

      {/* Corporate Technical Navbar / Presentation Top */}
      <nav className="relative z-10 w-full max-w-7xl mx-auto px-6 py-6 border-b border-zinc-900 bg-black/40 backdrop-blur-md flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-xl shadow-[0_0_15px_rgba(16,185,129,0.15)] text-emerald-500">
            <Shield size={18} />
          </div>
          <div>
            <span className="text-xs font-mono font-bold uppercase tracking-[0.2em] text-white">Cyber Hunter Lab</span>
            <span className="text-[9px] font-mono text-emerald-500 uppercase block font-bold">Stateful Threat Assurance</span>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <button 
            onClick={() => {
              const element = document.getElementById('pricing-grid');
              element?.scrollIntoView({ behavior: 'smooth' });
            }}
            className="text-zinc-400 hover:text-white transition-colors"
          >
            Nossos Planos
          </button>
          <span className="text-zinc-800">|</span>
          <button 
            onClick={() => onStart()}
            className="px-4 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-300 hover:text-white hover:border-zinc-700 transition-all font-bold uppercase tracking-wider text-[10px]"
          >
            Portal de Transações (Login stakeholders)
          </button>
        </div>
      </nav>

      {/* Main SaaS Showcase */}
      <main className="flex-1 relative z-10 w-full max-w-6xl mx-auto px-6 py-16 md:py-24 space-y-24">
        
        {/* Headline Section */}
        <section className="text-center space-y-6 max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 bg-emerald-500/15 border border-emerald-500/30 px-3 py-1 rounded-full text-[10px] font-mono text-emerald-400 uppercase tracking-widest font-bold mb-4">
            <Sparkles size={12} className="animate-pulse" /> MECANISMO DE AUDITORIA DE RECOLHAS v5.2 ELITE
          </div>
          
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-black text-white tracking-tight leading-tight uppercase">
            Identifique falhas críticas de faturamento e riscos de colapso antes que se tornem <span className="text-emerald-400 underline decoration-emerald-950 underline-offset-12">prejuízo em caixa</span>.
          </h1>
          
          <p className="text-zinc-400 text-sm sm:text-base md:text-lg font-light leading-relaxed max-w-2xl mx-auto">
            Proteja a sua propriedade intelectual (sem entregar códigos e senhas privadas do servidor). Nosso motor atua puramente como uma <strong>Caixa-Preta de Alta Performance</strong>, colhendo logs de mutação determinística e gerando relatórios de impacto financeiro prontos para a diretoria corporativa.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center pt-8">
            <button
              onClick={() => {
                const element = document.getElementById('pricing-grid');
                element?.scrollIntoView({ behavior: 'smooth' });
              }}
              className="px-8 py-4 bg-emerald-500 text-black text-xs font-bold uppercase tracking-widest rounded-full hover:bg-emerald-400 transition-all shadow-[0_0_30px_rgba(16,185,129,0.3)] flex items-center gap-2 w-full sm:w-auto justify-center"
            >
              Ativar Assinatura
              <ArrowRight size={14} />
            </button>
            
            <button
              onClick={() => onStart()}
              className="px-8 py-4 bg-zinc-950 border border-zinc-800 text-zinc-300 text-xs font-bold uppercase tracking-widest rounded-full hover:border-zinc-700 hover:text-white transition-all w-full sm:w-auto justify-center text-center"
            >
              Acessar com Credencial Ativa
            </button>
          </div>
        </section>

        {/* Dynamic Live Terminal Simulation Box */}
        <section className="bg-zinc-950 border border-zinc-900 rounded-2xl overflow-hidden shadow-2xl relative">
          <div className="bg-zinc-900/60 px-4 py-3 border-b border-zinc-900 flex justify-between items-center text-xs">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80" />
              <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
              <span className="w-3 h-3 rounded-full bg-green-500/80" />
              <span className="text-[10px] font-mono text-zinc-500 ml-2">SIMULADOR MOTOR MUTACIONAL CHL</span>
            </div>
            <div className="flex items-center gap-1.5 text-[9px] font-mono text-[#10b981] uppercase font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10b981] animate-pulse" /> Sandbox Ativo
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-5 dark-twilight divide-y lg:divide-y-0 lg:divide-x divide-zinc-900">
            {/* Terminal simulation screen */}
            <div className="lg:col-span-3 p-6 font-mono text-xs text-zinc-400 min-h-80 flex flex-col justify-between">
              <div className="space-y-2 max-h-72 overflow-y-auto no-scrollbar">
                {terminalLines.map((line, idx) => {
                  let colorClass = "text-zinc-400";
                  if (line.includes("SUCCESS")) colorClass = "text-emerald-400 font-bold";
                  else if (line.includes("CRITICAL") || line.includes("SYSTEM_STATE: CRASH")) colorClass = "text-red-400 font-bold";
                  else if (line.includes("WARN")) colorClass = "text-amber-400";
                  
                  return (
                    <div key={idx} className={colorClass}>
                      &gt; {line}
                    </div>
                  );
                })}
                <div ref={terminalEndRef} />
              </div>
              
              <div className="pt-4 border-t border-zinc-900 flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase">Testar domínio próprio:</span>
                  <input
                    type="text"
                    value={domainToVerify}
                    onChange={(e) => setDomainToVerify(e.target.value)}
                    ref={(el) => { if (el) el.onclick = (e) => e.stopPropagation(); }}
                    placeholder="empresa.com"
                    className="bg-black border border-zinc-850 px-2 py-1 rounded text-[10px] text-zinc-300 font-mono focus:outline-none focus:border-emerald-500/30"
                  />
                </div>
                <button
                  onClick={startTerminalSimulation}
                  disabled={terminalStatus === 'running'}
                  className="px-4 py-1.5 bg-zinc-900 border border-zinc-800 text-emerald-400 font-mono hover:text-white hover:border-emerald-500/30 text-[10px] rounded uppercase transition-all flex items-center gap-1 font-bold"
                >
                  <Play size={12} />
                  {terminalStatus === 'running' ? 'Rodando...' : 'Iniciar Simulação de Exploração'}
                </button>
              </div>
            </div>

            {/* Simulated report sidebar */}
            <div className="lg:col-span-2 p-6 space-y-4 bg-zinc-950/40">
              <h3 className="text-xs font-mono font-bold uppercase text-white tracking-widest flex items-center gap-2">
                <Layers size={14} className="text-emerald-400" /> Relatório Executivo Associado
              </h3>
              <p className="text-[11px] text-zinc-500 leading-relaxed font-sans">
                O motor determinístico consolida essa cascata explorada do terminal gerando o JSON de conformidade, que ao ser colado na aplicação cria instantaneamente o seguinte sumário estratégico:
              </p>

              <div className="bg-black/50 border border-zinc-900 p-4 rounded-xl space-y-3 font-mono text-[10px]">
                <div className="flex justify-between border-b border-zinc-900 pb-2">
                  <span className="text-zinc-500 uppercase">Audit ID:</span>
                  <span className="text-[#10b981] font-bold">CHL-CHAIN-9521</span>
                </div>
                <div className="flex justify-between border-b border-zinc-900 pb-2">
                  <span className="text-zinc-500 uppercase">Perda de Receita Calculada:</span>
                  <span className="text-red-400 font-bold">R$ 15.074,00 / trx</span>
                </div>
                <div className="flex justify-between border-b border-zinc-900 pb-2">
                  <span className="text-zinc-500 uppercase">Ameaça Operacional:</span>
                  <span className="text-red-400 font-bold">CRASH DE PRODUÇÃO</span>
                </div>
                <div className="flex justify-between pb-1">
                  <span className="text-zinc-500 uppercase">Segredos Expostos:</span>
                  <span className="text-white">chaves_de_configuracao</span>
                </div>
              </div>

              <div className="p-3 bg-emerald-500/5 border border-emerald-500/10 rounded-lg">
                <p className="text-[10px] text-emerald-400/80 leading-relaxed italic font-sans font-medium">
                  "Mostramos à diretoria o risco fiduciário preciso da mutação lógica, forçando o comitê a agir rápido."
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* 3 Steps Works Presentation */}
        <section className="space-y-12">
          <div className="text-center space-y-2">
            <span className="text-[11px] font-mono text-emerald-500 uppercase tracking-[0.3em] font-bold">LIVRE DE BUROCRACIA</span>
            <h2 className="text-3xl font-black text-white uppercase tracking-tight">O Funcionamento em 3 Passos (A Experiência Blindada)</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="bg-[#121212]/40 border border-zinc-900 p-8 rounded-2xl space-y-4 hover:border-zinc-800 transition-colors">
              <div className="w-10 h-10 rounded-xl bg-zinc-900/80 border border-zinc-800 flex items-center justify-center text-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.1)]">
                <span className="text-sm font-mono font-bold">01</span>
              </div>
              <h3 className="text-base font-bold text-white uppercase">Mapeamento Comportamental</h3>
              <p className="text-zinc-400 text-xs leading-relaxed">
                Nossa tecnologia analisa os campos de entrada, checkout e cabeçalhos de sua infraestrutura física, rastreando desvios nos limiares de faturamento em tempo real, agindo inteiramente de fora dos limites privados do servidor.
              </p>
            </div>

            <div className="bg-[#121212]/40 border border-zinc-900 p-8 rounded-2xl space-y-4 hover:border-zinc-800 transition-colors">
              <div className="w-10 h-10 rounded-xl bg-zinc-900/80 border border-zinc-800 flex items-center justify-center text-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.1)]">
                <span className="text-sm font-mono font-bold">02</span>
              </div>
              <h3 className="text-base font-bold text-white uppercase">Mutação Dinâmica Baseada em Estado</h3>
              <p className="text-zinc-400 text-xs leading-relaxed">
                Durante a exploração do sandbox, os payloads de busca sofrem reajustes dinâmicos que contornam filtros lógicos clássicos e testam robustezas operacionais da interface, garantindo uma auditoria que nunca se replica de forma trivial.
              </p>
            </div>

            <div className="bg-[#121212]/40 border border-zinc-900 p-8 rounded-2xl space-y-4 hover:border-zinc-800 transition-colors">
              <div className="w-10 h-10 rounded-xl bg-zinc-900/80 border border-zinc-800 flex items-center justify-center text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.1)]">
                <span className="text-sm font-mono font-bold">03</span>
              </div>
              <h3 className="text-base font-bold text-white uppercase">Sumário Executivo Automatizado</h3>
              <p className="text-zinc-400 text-xs leading-relaxed">
                Copie os relatórios em formato JSON (máquina-readable exploit trees) e visualize imediatamente o impacto financeiro estruturado com o mapeamento regulatório CWE e diretrizes de defesa sem nenhum termo complexo.
              </p>
            </div>
          </div>
        </section>

        {/* Subscription / Pricing Grid */}
        <section id="pricing-grid" className="space-y-12">
          <div className="text-center space-y-3">
            <span className="text-[11px] font-mono text-emerald-500 uppercase tracking-[0.3em] font-bold">NOSSAS ASSINATURAS</span>
            <h2 className="text-3xl md:text-4xl font-black text-white uppercase">Planos de Acesso à Plataforma</h2>
            <p className="text-zinc-500 text-xs max-w-md mx-auto">
              Selecione o nível de assinatura que melhor integra o seu fluxo de triagem e caças de Bug Bounty ético corporativos.
            </p>

            {/* Monthly / Annual toggle wrapper */}
            <div className="pt-4 flex justify-center">
              <div className="bg-[#121212] border border-zinc-850 rounded-lg p-1 flex items-center gap-1 font-mono text-[10px]">
                <button
                  onClick={() => setBillingPeriod('monthly')}
                  className={`px-3 py-1.5 rounded uppercase font-bold transition-all ${billingPeriod === 'monthly' ? 'bg-white text-black' : 'text-zinc-500'}`}
                >
                  Mensal
                </button>
                <button
                  onClick={() => setBillingPeriod('annual')}
                  className={`px-3 py-1.5 rounded uppercase font-bold transition-all ${billingPeriod === 'annual' ? 'bg-[#10b981] text-black' : 'text-zinc-500'}`}
                >
                  Anual (20% Off)
                </button>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-stretch pt-6">
            {pricingPlans.map((plan) => {
              const basePrice = billingPeriod === 'monthly' ? plan.priceMonthly : plan.priceAnnual;
              return (
                <div 
                  key={plan.id}
                  className={`bg-[#121212]/60 border rounded-3xl p-8 space-y-6 flex flex-col justify-between relative transition-all duration-300 ${plan.isPopular ? 'border-emerald-500 shadow-[0_0_40px_rgba(16,185,129,0.08)] bg-[#121212]' : 'border-zinc-900 hover:border-zinc-800'}`}
                >
                  {plan.isPopular && (
                    <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-emerald-500 text-black font-mono font-black text-[9px] uppercase tracking-[0.2em] px-4 py-1 rounded-full shadow-lg">
                      {plan.badge}
                    </div>
                  )}

                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <h3 className="text-lg font-black text-white uppercase font-mono">{plan.name}</h3>
                      {!plan.isPopular && <Badge variant="neutral">{plan.badge}</Badge>}
                    </div>
                    
                    <p className="text-zinc-500 text-xs leading-relaxed min-h-[48px]">{plan.desc}</p>

                    <div className="flex items-baseline gap-1 pt-2">
                      <span className="text-2xl font-black text-white">R$</span>
                      <span className="text-4xl sm:text-5xl font-black text-white tracking-tight">
                        {basePrice}
                      </span>
                      <span className="text-zinc-500 text-xs font-mono">/mês</span>
                    </div>

                    {billingPeriod === 'annual' && (
                      <span className="text-[10px] font-mono text-emerald-400 block uppercase tracking-wider font-bold">
                        Faturado anualmente (Economia inclusa)
                      </span>
                    )}

                    <div className="h-px bg-zinc-900/80 my-4" />

                    <ul className="space-y-3 pt-2 text-xs">
                      {plan.features.map((feat, fIdx) => (
                        <li key={fIdx} className="flex items-start gap-2.5 text-zinc-400">
                          <Check size={14} className="text-emerald-500 mt-0.5 shrink-0" />
                          <span className="leading-snug">{feat}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <button
                    onClick={() => {
                      setSelectedPlan(plan);
                      setCheckoutStep('input');
                      setShowCheckout(true);
                    }}
                    className={`w-full py-4 rounded-xl font-bold uppercase tracking-wider text-[11px] transition-all flex items-center justify-center gap-1.5 font-mono ${plan.isPopular ? 'bg-emerald-500 text-black hover:bg-emerald-400 shadow-[0_4px_20px_rgba(16,185,129,0.2)]' : 'bg-zinc-950 text-zinc-300 hover:text-white border border-zinc-850 hover:border-zinc-700'}`}
                  >
                    Adquirir Plano {plan.name.replace("Hunter ", "")}
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {/* Biblical Quote and Context integration */}
        <section className="relative text-center max-w-2xl mx-auto pt-16 border-t border-zinc-950">
          <p className="text-base text-zinc-400 font-serif leading-relaxed italic">
            "Pelo contrário, Deus escolheu as coisas loucas do mundo para confundir os sábios; e Deus escolheu as coisas fracas do mundo para confundir as fortes."
          </p>
          <div className="mt-4 text-[10px] font-mono text-emerald-500/40 uppercase tracking-[0.5em] font-bold">
            — 1 Coríntios 1:27
          </div>
        </section>

      </main>

      {/* Corporate Technical Footer */}
      <footer className="w-full mt-auto py-12 px-6 border-t border-zinc-900 bg-black/40 backdrop-blur-sm relative z-10">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-8">
          <div className="flex flex-col items-center md:items-start gap-2">
            <div className="text-[10px] font-mono text-zinc-600 tracking-[0.3em] uppercase font-bold">
              Propriedade de Ana Caroline Lamas
            </div>
            <div className="text-[9px] font-mono text-zinc-750 tracking-[0.2em] uppercase">
              Auditoria de Sistemas Críticos • © 2026
            </div>
          </div>
          
          <div className="flex flex-col md:flex-row items-center gap-6 md:gap-12">
            <div className="flex flex-col items-center md:items-end gap-1">
              <span className="text-[9px] font-mono text-zinc-600 uppercase tracking-widest">Canal Estrutural</span>
              <span className="text-[10px] font-mono text-zinc-400 tracking-wider">contato@cyberhuntlab.com.br</span>
            </div>
            <div className="h-8 w-px bg-zinc-900 hidden md:block" />
            <div className="flex flex-col items-center md:items-end gap-1">
              <span className="text-[9px] font-mono text-emerald-500/40 uppercase tracking-widest font-bold">Direct WhatsApp (Prioritário)</span>
              <a 
                href="https://wa.me/5531972442973" 
                target="_blank" 
                rel="no-referrer"
                className="text-[11px] font-mono text-emerald-500 hover:text-emerald-400 transition-colors tracking-widest font-bold"
              >
                +55 31 97244-2973
              </a>
            </div>
          </div>
        </div>
      </footer>

      {/* Subscription Payment Sandbox Modal */}
      <AnimatePresence>
        {showCheckout && selectedPlan && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 15 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 15 }}
              className="bg-[#121212] border border-zinc-850 rounded-[2rem] w-full max-w-lg p-8 relative shadow-[0_0_50px_rgba(0,0,0,0.8)]"
            >
              <button 
                onClick={() => setShowCheckout(false)}
                className="absolute top-6 right-6 text-zinc-650 hover:text-white text-xs font-mono"
              >
                [FECHAR]
              </button>

              <div className="space-y-6">
                <div>
                  <span className="text-[10px] font-mono text-emerald-400 uppercase font-bold tracking-widest">Gateway Mock Premium</span>
                  <h3 className="text-xl font-mono font-black text-white uppercase">Checkout {selectedPlan.name}</h3>
                  <p className="text-zinc-500 text-xs">Ative instantaneamente sua credencial e libere as ferramentas do Lab.</p>
                </div>

                <div className="h-px bg-zinc-900" />

                {checkoutStep === 'input' && (
                  <form onSubmit={handleCheckoutSubmit} className="space-y-4">
                    <div className="space-y-1.5">
                      <label className="text-[9px] font-mono text-zinc-500 uppercase font-bold tracking-widest flex items-center gap-1">
                        <CreditCard size={12} /> Número do Cartão de Teste (Sandbox)
                      </label>
                      <input
                        type="text"
                        value={cardNumber}
                        onChange={(e) => setCardNumber(e.target.value)}
                        className="w-full bg-zinc-950 border border-zinc-850 rounded-xl px-4 py-3 text-xs font-mono text-zinc-300 focus:outline-none focus:border-emerald-500/30"
                        required
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="text-[9px] font-mono text-zinc-500 uppercase font-bold tracking-widest">Expiração</label>
                        <input
                          type="text"
                          value={cardExpiry}
                          onChange={(e) => setCardExpiry(e.target.value)}
                          className="w-full bg-zinc-950 border border-zinc-850 rounded-xl px-4 py-3 text-xs font-mono text-zinc-300 focus:outline-none"
                          required
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-[9px] font-mono text-zinc-500 uppercase font-bold tracking-widest">CVC / Código</label>
                        <input
                          type="text"
                          value={cardCvc}
                          onChange={(e) => setCardCvc(e.target.value)}
                          className="w-full bg-zinc-950 border border-zinc-850 rounded-xl px-4 py-3 text-xs font-mono text-zinc-300 focus:outline-none"
                          required
                        />
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-[9px] font-mono text-zinc-500 uppercase font-bold tracking-widest">Nome Impresso no Portador</label>
                      <input
                        type="text"
                        value={cardName}
                        onChange={(e) => setCardName(e.target.value)}
                        placeholder="Ana Caroline Lamas"
                        className="w-full bg-zinc-950 border border-zinc-850 rounded-xl px-4 py-3 text-xs font-mono text-zinc-300 focus:outline-none"
                        required
                      />
                    </div>

                    <div className="space-y-1.5">
                      <label className="text-[9px] font-mono text-zinc-500 uppercase font-bold tracking-widest">Domínio Verificado Escopo</label>
                      <input
                        type="text"
                        value={domainToVerify}
                        onChange={(e) => setDomainToVerify(e.target.value)}
                        className="w-full bg-zinc-950 border border-zinc-850 rounded-xl px-4 py-3 text-xs font-mono text-[#10b981] focus:outline-none"
                        required
                      />
                    </div>

                    <button
                      type="submit"
                      className="w-full py-4 bg-[#10b981] text-black font-mono font-bold uppercase text-xs tracking-wider rounded-xl hover:bg-[#10b981]/90 transition-all flex items-center justify-center gap-1.5"
                    >
                      <Lock size={14} /> Ativar Assinatura • R$ {billingPeriod === 'monthly' ? selectedPlan.priceMonthly : selectedPlan.priceAnnual},00
                    </button>
                    <p className="text-[9px] font-mono text-zinc-600 text-center uppercase tracking-widest">Sem cobrança real. Sandbox ativo.</p>
                  </form>
                )}

                {checkoutStep === 'processing' && (
                  <div className="py-12 flex flex-col items-center justify-center space-y-4">
                    <RefreshCw className="animate-spin text-emerald-400" size={32} />
                    <span className="text-xs font-mono text-zinc-400 uppercase tracking-widest font-bold">Autorizando Cartão via Stripe Securo...</span>
                  </div>
                )}

                {checkoutStep === 'success' && (
                  <div className="py-8 flex flex-col items-center justify-center text-center space-y-4">
                    <div className="w-16 h-16 rounded-full bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-500">
                      <Check size={32} className="animate-bounce" />
                    </div>
                    <div className="space-y-1.5">
                      <h4 className="text-white font-mono font-bold text-sm uppercase">Assinatura Ativada com Sucesso!</h4>
                      <p className="text-zinc-500 text-xs max-w-sm">Dossiê {selectedPlan.name} ativo. Domínio {domainToVerify} registrado.</p>
                    </div>

                    <button
                      onClick={handleApplySignature}
                      className="px-6 py-3 bg-white text-black font-mono font-bold uppercase text-xs tracking-widest rounded-xl hover:bg-zinc-200 transition-all flex items-center gap-1"
                    >
                      Entrar no Laboratório
                      <ChevronRight size={14} />
                    </button>
                  </div>
                )}

              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
};
