import React from 'react';
import { motion } from 'motion/react';
import { Shield, ShieldCheck, AlertTriangle, Fingerprint, Search, Info, CheckCircle2, XCircle, Zap, Activity, FileCode, BookOpen, UserCheck, Scale, Globe, Copy, Download } from 'lucide-react';
import { SecurityAnalysis } from '../types';
import { Badge } from './ui/Badge';
import { cn } from '../lib/utils';
import ReactMarkdown from 'react-markdown';

interface AnalysisDashboardProps {
  analysis: SecurityAnalysis;
}

export const AnalysisDashboard = ({ analysis }: AnalysisDashboardProps) => {
  const result = analysis.result;
  const verification = analysis.verification;

  const exportPoCScript = (content: string) => {
    const isPython = content.includes('import') || content.includes('def ');
    const ethicalHeader = `# AVISO: Este script de PoC (Prova de Conceito) destina-se exclusivamente a fins de validação técnica autorizada. 
# O uso contra sistemas sem permissão explícita é ilegal e viola os termos de conduta do Cyber Hunter Lab.
# Gerado por: Cyber Hunter Lab | Trusted Researcher Process\n\n`;
    
    // Prepend header if not already present
    const finalContent = content.includes('AVISO: Este script de PoC') ? content : (ethicalHeader + content);
    
    const filename = `poc_cyberhunter_${Date.now()}.${isPython ? 'py' : 'txt'}`;
    const blob = new Blob([finalContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const getImpactColor = (impact: string) => {
    switch (impact) {
      case 'critico': return 'danger';
      case 'alto': return 'danger';
      case 'medio': return 'warning';
      case 'baixo': return 'info';
      default: return 'neutral';
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col gap-6"
    >
      {/* Header Stat Bar */}
      <div className={cn(
        "grid grid-cols-2 xxs:grid-cols-3 sm:grid-cols-4 lg:grid-cols-7 bg-zinc-800 border border-zinc-800 rounded-lg overflow-hidden shrink-0",
        !result.oss_vrp_tier && "lg:grid-cols-6"
      )}>
        <StatItem label="Vulnerabilidade" value={result.vulnerabilidade || 'Nenhuma'} />
        <StatItem label="Cat VRP" value={result.vrp_category} variant="info" />
        {result.oss_vrp_tier && (
          <StatItem label="OSS Tier" value={result.oss_vrp_tier} variant="neutral" />
        )}
        <StatItem label="Impact" value={result.impacto} variant={getImpactColor(result.impacto)} />
        <StatItem label="Dup Risk" value={result.risco_duplicata} variant={result.risco_duplicata === 'baixo' ? 'success' : (result.risco_duplicata === 'alto' ? 'danger' : 'warning')} />
        <StatItem label="Priority" value={result.triage_priority} variant="neutral" />
        <StatItem label="Audit" value={verification?.final_status || result.status} variant={verification?.final_status === 'confirmado' ? 'success' : 'neutral'} />
        <div className="bg-emerald-600 flex items-center justify-center cursor-pointer hover:bg-emerald-500 transition-colors p-2 sm:p-4" title="Copiar Relatório Completo" onClick={() => navigator.clipboard.writeText(result.relatorio_markdown)}>
          <Zap size={16} className="text-white" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Findings */}
        <div className="lg:col-span-2 flex flex-col gap-6">
          {/* Source -> Sink Flow Section */}
          <section className="bg-[#1a1a1a] border border-zinc-800 rounded-lg overflow-hidden">
            <div className="bg-zinc-900 px-6 py-3 border-b border-zinc-800 flex items-center justify-between">
              <h3 className="text-[11px] font-mono uppercase tracking-widest text-zinc-400 flex items-center gap-2">
                <Fingerprint size={14} className="text-zinc-500" /> Data Flow (Source → Sink)
              </h3>
              <Badge variant={result.fluxo_confirmado ? 'success' : 'neutral'}>
                {result.fluxo_confirmado ? 'Fluxo Confirmado' : 'Fluxo Parcial'}
              </Badge>
            </div>
            
            <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6 relative">
              <div className="hidden md:block absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-zinc-700 z-0">
                <motion.div 
                  animate={{ x: [0, 10, 0] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <Search size={32} />
                </motion.div>
              </div>

              <div className="space-y-2 z-10">
                <label className="text-[10px] font-mono uppercase text-zinc-500 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500" /> Source (Input)
                </label>
                <div className="bg-zinc-900 border border-zinc-800 p-3 rounded font-mono text-[11px] text-blue-400 border-l-2 border-l-blue-500 break-all">
                  {result.source || 'Not identified'}
                </div>
              </div>

              <div className="space-y-2 z-10">
                <label className="text-[10px] font-mono uppercase text-zinc-500 flex items-center gap-1 justify-end">
                   Sink (Critical Point) <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                </label>
                <div className="bg-zinc-900 border border-zinc-800 p-3 rounded font-mono text-[11px] text-red-400 border-r-2 border-r-red-500 text-right break-all">
                  {result.sink || 'Not identified'}
                </div>
              </div>
            </div>

            <div className="bg-zinc-900/40 p-4 border-t border-zinc-800 flex flex-wrap items-center gap-8">
              <div className="flex flex-col min-w-[120px]">
                <span className="text-[9px] font-mono uppercase text-zinc-500 mb-1">Sanitization Analysis</span>
                <span className={`text-[11px] font-bold uppercase ${(result.sanitizacao || '').includes('adequate') || (result.sanitizacao || '').includes('adequada') ? 'text-emerald-500' : 'text-amber-500'}`}>
                  {result.sanitizacao || 'Analysis Pending'}
                </span>
              </div>
              
              <div className="flex-1 flex flex-col min-w-[150px]">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[9px] font-mono uppercase text-zinc-500">Certeza Técnica (Grounding)</span>
                  <span className="text-[10px] font-mono text-zinc-400">{(result.confianca * 100).toFixed(0)}%</span>
                </div>
                <div className="h-1 w-full bg-zinc-800 rounded-full overflow-hidden">
                  <motion.div 
                    initial={{ width: 0 }}
                    animate={{ width: `${(result.confianca || 0) * 100}%` }}
                    className={`h-full ${(result.confianca || 0) >= 0.9 ? 'bg-emerald-500' : (result.confianca || 0) >= 0.7 ? 'bg-blue-500' : 'bg-amber-500'}`}
                  />
                </div>
              </div>

              <div className="w-px h-6 bg-zinc-800 hidden md:block" />
              
              <div className="flex flex-col">
                <span className="text-[9px] font-mono uppercase text-zinc-500">Impacto Real</span>
                <span className={`text-[11px] font-bold uppercase ${result.impacto_real ? 'text-emerald-500' : 'text-zinc-500'}`}>
                  {result.impacto_real ? 'Validado' : 'Teórico'}
                </span>
              </div>
            </div>
          </section>

          <section className="bg-[#1a1a1a] border border-zinc-800 rounded-lg p-8">
            <h3 className="text-[11px] font-mono uppercase tracking-[0.3em] text-emerald-500 mb-8 flex items-center gap-2 border-b border-emerald-500/10 pb-2">
              <Shield size={14} /> Auditoria de Kernel
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10 text-left">
              <div className="bg-zinc-900/30 p-6 rounded-xl border border-zinc-800/50">
                <p className="text-[10px] font-mono text-zinc-500 uppercase mb-2">Vulnerabilidade Identificada</p>
                <p className="text-xl font-bold text-white tracking-tight leading-tight">{result.vulnerabilidade || 'Análise Concluída'}</p>
              </div>
              <div className="bg-zinc-900/30 p-6 rounded-xl border border-zinc-800/50">
                <p className="text-[10px] font-mono text-zinc-500 uppercase mb-2">Classe de Risco (CWE)</p>
                <div className="flex items-center gap-3">
                  <span className={cn(
                    "px-3 py-1 rounded text-xs font-bold uppercase",
                    result.severidade === 'CRITICAL' ? "bg-red-500/20 text-red-400 border border-red-500/30" :
                    result.severidade === 'HIGH' ? "bg-orange-500/20 text-orange-400 border border-orange-500/30" :
                    "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                  )}>
                    {result.severidade}
                  </span>
                  <span className="text-zinc-400 text-sm font-mono">{result.tipo}</span>
                </div>
              </div>
            </div>

            <div className="space-y-12">
              <section>
                <div className="flex items-center justify-between mb-6">
                  <h4 className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 border-l-2 border-emerald-500 pl-4">Relatório de Triage (Tripartite Engine)</h4>
                  <div className="flex gap-2">
                    <button 
                      onClick={() => navigator.clipboard.writeText(result.relatorio_markdown)}
                      className="p-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded transition-colors text-zinc-400 hover:text-white"
                      title="Copy Content"
                    >
                      <Copy size={14} />
                    </button>
                    <a 
                      href={`data:text/markdown;charset=utf-8,${encodeURIComponent(result.relatorio_markdown)}`}
                      download={`CyberHunter_Audit_${Date.now()}.md`}
                      className="p-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded transition-colors text-zinc-400 hover:text-white"
                      title="Download Analysis"
                    >
                      <Download size={14} />
                    </a>
                  </div>
                </div>
                <div className="prose prose-invert prose-base max-w-none text-zinc-300 font-mono text-sm leading-relaxed bg-[#0a0a0a] p-4 sm:p-8 rounded-2xl border border-zinc-900 shadow-2xl overflow-x-auto">
                  <ReactMarkdown>{result.relatorio_markdown || ''}</ReactMarkdown>
                </div>
              </section>

              <section className="bg-zinc-950/50 p-8 rounded-2xl border border-zinc-900/50">
                <h4 className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 mb-6 flex items-center gap-2">
                  <Fingerprint size={14} className="text-emerald-500" /> Grounding Evidence
                </h4>
                <div className="prose prose-invert prose-sm max-w-none text-zinc-400 font-mono text-sm leading-relaxed italic border-l-2 border-zinc-800 pl-6">
                  <ReactMarkdown>{result.evidencia || ''}</ReactMarkdown>
                </div>
              </section>
            </div>
          </section>

          <section className="bg-[#1a1a1a] border border-zinc-800 rounded-lg p-6">
            <h3 className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 mb-4 flex items-center gap-2">
              <Search size={14} /> Patch Analysis
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-start gap-3 p-4 bg-zinc-900/50 rounded border border-zinc-800/50">
                {result.patch_corrige ? (
                  <CheckCircle2 className="text-emerald-500 shrink-0" size={18} />
                ) : (
                  <XCircle className="text-red-500 shrink-0" size={18} />
                )}
                <div>
                  <h4 className="text-xs font-semibold text-zinc-200 uppercase mb-1">Patch Efficacy</h4>
                  <p className="text-[11px] text-zinc-400">
                    The patch {result.patch_corrige ? 'neutralizes' : 'fails to neutralize'} the identified vulnerability.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-4 bg-zinc-900/50 rounded border border-zinc-800/50">
                {result.regressao_detectada ? (
                  <AlertTriangle className="text-amber-500 shrink-0" size={18} />
                ) : (
                  <ShieldCheck className="text-emerald-500 shrink-0" size={18} />
                )}
                <div>
                  <h4 className="text-xs font-semibold text-zinc-200 uppercase mb-1">Regressions</h4>
                  <p className="text-[11px] text-zinc-400">
                    {result.regressao_detectada ? 'New risks introduced by the patch were detected.' : 'No immediate regressions were identified.'}
                  </p>
                </div>
              </div>
            </div>
          </section>

          <section className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
            <h3 className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 mb-6 flex items-center gap-2">
              <Shield size={14} /> Threat Modeling & Attack Path
            </h3>
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-3">
                {(result.modelagem_ataque || "").split('->').map((step, idx) => {
                  const steps = (result.modelagem_ataque || "").split('->');
                  return (
                    <React.Fragment key={idx}>
                      <div className={cn(
                        "px-4 py-2 rounded border font-mono text-[10px] uppercase tracking-tighter",
                        idx === 0 ? "bg-blue-500/10 border-blue-500/50 text-blue-400" :
                        idx === steps.length - 1 ? "bg-red-500/10 border-red-500/50 text-red-400 font-bold" :
                        "bg-zinc-800 border-zinc-700 text-zinc-400"
                      )}>
                        {step.trim()}
                      </div>
                      {idx < steps.length - 1 && (
                        <Search size={12} className="text-zinc-700" />
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
              <p className="text-[10px] text-zinc-600 italic">
                Visual path generated based on the identified Source → Sink trace.
              </p>
            </div>
          </section>

          <section className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-[11px] font-mono uppercase tracking-widest text-emerald-500 mb-0 flex items-center gap-2">
                <ShieldCheck size={14} /> PoC & Security Report
              </h3>
              <Badge variant="info" className="text-[9px]">{result.policy_violada}</Badge>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="text-[10px] font-mono uppercase text-zinc-500 border-b border-zinc-800 pb-1">Reproduction Steps</h4>
                <ol className="space-y-2">
                  {(result.poc_passos || []).map((passo, i) => (
                    <li key={i} className="flex gap-3 text-[11px] text-zinc-300">
                      <span className="text-emerald-500 font-mono font-bold">{i + 1}.</span>
                      <span>{passo}</span>
                    </li>
                  ))}
                </ol>
              </div>

              {result.poc_reproducao && (
                <div className="space-y-2">
                  <h4 className="text-[10px] font-mono uppercase text-zinc-500 border-b border-zinc-800 pb-1 flex items-center justify-between">
                    Reproduction Payload
                    <div className="flex gap-3">
                      <button 
                        onClick={() => navigator.clipboard.writeText(result.poc_reproducao!)}
                        className="text-[9px] hover:text-white transition-colors"
                      >
                        COPY
                      </button>
                      <button 
                        onClick={() => exportPoCScript(result.poc_reproducao!)}
                        className="text-[9px] text-emerald-500 hover:text-emerald-400 transition-colors uppercase font-bold"
                      >
                        Export Script
                      </button>
                    </div>
                  </h4>
                  <pre className="bg-black/40 p-3 rounded border border-zinc-800 text-[10px] font-mono text-blue-400 overflow-x-auto">
                    {result.poc_reproducao}
                  </pre>
                </div>
              )}
            </div>

            <div className="p-6 bg-emerald-500/5 border border-emerald-500/20 rounded-2xl space-y-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div className="space-y-1">
                  <h4 className="text-[10px] font-mono uppercase text-emerald-500/70 flex items-center gap-2">
                    <CheckCircle2 size={12} /> Submission Pipeline
                  </h4>
                  <p className="text-[11px] text-zinc-500">Pronto para submissão oficial no Google VRP ou HackerOne.</p>
                </div>
                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <button 
                    onClick={() => navigator.clipboard.writeText(result.relatorio_markdown || '')}
                    className="flex-1 sm:flex-none px-3 py-1.5 bg-emerald-500 text-black text-[9px] sm:text-[10px] font-bold rounded-lg hover:bg-emerald-400 transition-all uppercase tracking-widest shadow-lg shadow-emerald-500/20"
                  >
                    Copy Report
                  </button>
                  <a 
                    href="https://bughunters.google.com/report"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex-1 sm:flex-none px-3 py-1.5 bg-white text-black text-[9px] sm:text-[10px] font-bold rounded-lg hover:bg-zinc-200 transition-all uppercase tracking-widest flex items-center justify-center gap-2"
                  >
                    Submit <Globe size={12} />
                  </a>
                </div>
              </div>

              {/* Researcher Attribution & Certification */}
              <div className="pt-6 border-t border-zinc-900">
                <div className="flex flex-col md:flex-row items-center justify-between gap-6">
                  <div className="space-y-2 text-center md:text-left">
                    <h5 className="text-[9px] font-mono uppercase text-zinc-600 tracking-[0.3em]">Auditor Neural Core</h5>
                    <p className="text-[10px] text-zinc-500 font-mono italic">
                      {(result.telemetria?.modelo || '').includes('pro') ? 'Deep Reasoning v3.1 (High Severity Recall)' : 'Neural Flash v3.0 (Low Latency Triage)'}
                    </p>
                  </div>
                  <div className="space-y-2 text-center md:text-right">
                    <h5 className="text-[9px] font-mono uppercase text-zinc-600 tracking-[0.3em]">Lead Security Engineer</h5>
                    <a 
                      href="https://g.dev/anacarolinelamas" 
                      target="_blank" 
                      rel="noreferrer"
                      className="text-[11px] text-emerald-500 font-mono hover:text-emerald-400 inline-flex items-center gap-2 group transition-colors"
                    >
                      Ana Caroline Lamas <Badge variant="info" className="text-[8px] py-0 px-1.5 font-bold bg-blue-500/10 text-blue-400 border-blue-500/20">VRP EXPERT</Badge>
                      <Search size={12} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section className="bg-zinc-900/30 border border-amber-500/20 rounded-lg p-6 border-dashed">
            <h3 className="text-[11px] font-mono uppercase tracking-widest text-amber-500/70 mb-4 flex items-center gap-2">
              <Zap size={14} /> Hunting Strategy (Anti-Duplicate)
            </h3>
            <div className="prose prose-invert prose-base max-w-none text-zinc-400 font-mono text-sm leading-relaxed italic">
              <ReactMarkdown>{result.estrategia_hunting}</ReactMarkdown>
            </div>
          </section>

          {/* Deep JSON Report Node */}
          <section className="bg-black/40 border border-zinc-800 rounded-lg p-6 overflow-hidden">
            <h3 className="text-[11px] font-mono uppercase tracking-[0.3em] text-zinc-500 mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode size={14} /> JSON Metadata Node (Raw Analysis)
              </div>
              <button 
                onClick={() => navigator.clipboard.writeText(JSON.stringify(result, null, 2))}
                className="text-[9px] text-blue-500 hover:text-blue-400 transition-colors uppercase font-bold tracking-widest border border-blue-500/30 px-2 py-0.5 rounded bg-blue-500/5"
              >
                Copy JSON
              </button>
            </h3>
            <div className="bg-zinc-950 p-4 rounded border border-zinc-900 overflow-x-auto max-h-96">
              <pre className="text-[10px] font-mono text-blue-400 leading-tight">
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>
            <p className="mt-3 text-[9px] font-mono text-zinc-600 uppercase tracking-widest italic">
              Relatório estruturado gerado em tempo real via Telemetria Mission Control.
            </p>
          </section>
        </div>

        {/* Audit & Verification Sidebar */}
        <div className="flex flex-col gap-6">
          <section className="bg-zinc-950 border border-zinc-800 rounded-lg p-5 border-l-4 border-l-blue-500 shadow-xl overflow-hidden relative">
            <div className="absolute top-0 right-0 p-2 opacity-10">
              <Activity size={48} />
            </div>
            <h3 className="text-[11px] font-mono uppercase tracking-[0.2em] text-blue-400 mb-4 flex items-center gap-2">
              <Activity size={14} /> Analysis Engine Metadatas
            </h3>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <span className="text-[9px] font-mono text-zinc-600 uppercase">Processing Model</span>
                <p className="text-[11px] font-mono text-zinc-300 truncate">{result.telemetria?.modelo || 'Flash 3.0 Generic'}</p>
              </div>
              <div className="space-y-1 text-right">
                <span className="text-[9px] font-mono text-zinc-600 uppercase">Latency</span>
                <p className="text-[11px] font-mono text-blue-400">{result.telemetria?.latencia_ms || 0}ms</p>
              </div>
              <div className="space-y-1">
                <span className="text-[9px] font-mono text-zinc-600 uppercase">Input Token TP</span>
                <p className="text-[11px] font-mono text-zinc-300">{result.telemetria?.throughput_tokens || 0} t/s</p>
              </div>
              <div className="space-y-1 text-right">
                <span className="text-[9px] font-mono text-zinc-600 uppercase">Reasoning Path</span>
                <p className="text-[11px] font-mono text-amber-500/80">{result.telemetria?.pipeline || 'Standard Scan'}</p>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-zinc-900 border-dashed">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
                <span className="text-[9px] font-mono text-zinc-500 uppercase tracking-widest">Enterprise Auditor Bridge: ACTIVE</span>
              </div>
              <p className="text-[10px] text-zinc-600 font-mono italic">
                Dados processados exclusivamente via lógica de análise em conformidade.
              </p>
            </div>
          </section>

          <section className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
            <h3 className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 mb-4 flex items-center gap-2">
              <Shield size={14} /> Auditoria Red Team
            </h3>
            
            {verification ? (
              <div className="flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-zinc-500">Integridade Logic:</span>
                  <Badge variant={verification.is_valid ? 'success' : 'danger'}>
                    {verification.is_valid ? 'Válida' : 'Suposta'}
                  </Badge>
                </div>

                <div className="space-y-4">
                  <div>
                    <span className="text-[10px] font-mono text-zinc-500 uppercase block mb-1">Feedback do Auditor:</span>
                    <p className="text-xs text-zinc-400 italic">"{verification.feedback}"</p>
                  </div>

                  {verification.found_assumptions.length > 0 && (
                    <div>
                      <span className="text-[10px] font-mono text-zinc-500 uppercase block mb-1">Suposições Detectadas:</span>
                      <ul className="list-disc list-inside text-xs text-amber-500/80 space-y-1">
                        {verification.found_assumptions.map((a, i) => (
                          <li key={i}>{a}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-xs text-zinc-600 italic">Auditoria em aguardo...</div>
            )}
          </section>

          <section className="bg-zinc-900/50 border border-dashed border-zinc-800 rounded-lg p-5">
            <h3 className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 mb-3 flex items-center gap-2">
              <Info size={14} /> Neural Pipeline Methodology
            </h3>
            <p className="text-[11px] text-zinc-500 leading-relaxed font-mono">
              This analysis utilizes cross-grounding. First, the {result.telemetria.pipeline} identifies critical flows. Then, a secondary Auditor verifies every piece of evidence against the source code to mitigate technical hallucinations.
            </p>
          </section>

          <section className="bg-emerald-500/5 border border-emerald-500/10 rounded-lg p-5">
            <h4 className="text-[11px] font-mono uppercase tracking-widest text-emerald-500/70 mb-4 flex items-center gap-2">
              <BookOpen size={14} /> Cyber Hunter Lab - Ethics & Compliance
            </h4>
            <div className="space-y-3">
              <ClauseItem 
                icon={<Search size={12} />} 
                title="Recon Module Ethics" 
                text="Auditoria de superfície concluída. Este mapeamento foi realizado de forma passiva/não intrusiva, respeitando os limites do programa de Bug Bounty. Nenhuma alteração foi feita nos ativos do alvo." 
              />
              <ClauseItem 
                icon={<Scale size={12} />} 
                title="Trusted Researcher" 
                text="As vulnerabilidades descritas foram tratadas sob sigilo e enviadas diretamente ao proprietário do sistema, seguindo as diretrizes de Trusted Researcher." 
              />
              <ClauseItem 
                icon={<Shield size={12} />} 
                title="Zero Trust Principle" 
                text="User input is never trusted. All external info is potentially malicious until sanitized." 
              />
              <ClauseItem 
                icon={<UserCheck size={12} />} 
                title="Researcher Identity" 
                text="Student of Google Cloud Skills Boost (Gen AI) applying advanced security frameworks." 
              />
              <div className="pt-2 border-t border-emerald-500/10 mt-2">
                <a 
                  href="https://g.dev/anacarolinelamas" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-[10px] font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1.5 transition-colors"
                >
                  <Globe size={11} /> Developer Profile: g.dev/anacarolinelamas
                </a>
              </div>
            </div>
          </section>
        </div>
      </div>
    </motion.div>
  );
};

const ClauseItem = ({ icon, title, text }: { icon: any, title: string, text: string }) => (
  <div className="flex gap-3">
    <div className="text-emerald-500 mt-0.5">{icon}</div>
    <div className="space-y-0.5">
      <h5 className="text-[10px] font-bold text-zinc-300 uppercase font-mono">{title}</h5>
      <p className="text-[10px] text-zinc-500 leading-tight font-mono">{text}</p>
    </div>
  </div>
);

const StatItem = ({ label, value, variant }: { label: string, value: string, variant?: any }) => (
  <div className="bg-[#1a1a1a] p-2.5 sm:p-4 flex flex-col gap-1 min-w-0">
    <span className="text-[8px] sm:text-[9px] font-mono uppercase tracking-widest text-zinc-500 opacity-60 italic truncate">{label}</span>
    <div className="flex items-center gap-2 min-w-0">
      {variant ? (
        <Badge variant={variant} className="w-full text-center text-[9px] sm:text-[10px] py-1 truncate">{value}</Badge>
      ) : (
        <span className="text-xs sm:text-sm font-mono text-white font-medium truncate" title={value}>{value}</span>
      )}
    </div>
  </div>
);
