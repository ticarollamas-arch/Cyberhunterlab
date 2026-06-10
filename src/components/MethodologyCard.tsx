import React from 'react';
import { Shield, Target, Zap, Search, Fingerprint, Bug } from 'lucide-react';

export const MethodologyCard = () => {
  return (
    <div className="bg-[#121212] border border-zinc-800 rounded-xl overflow-hidden shadow-2xl">
      <div className="p-4 border-b border-zinc-800 bg-zinc-900/50 flex items-center justify-between">
        <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 flex items-center gap-2">
          <Shield size={14} className="text-zinc-500" /> Grounding & Escopo Técnico
        </h3>
        <span className="text-[10px] font-mono text-zinc-600 bg-zinc-800 px-2 py-0.5 rounded border border-zinc-700">v2.1</span>
      </div>
      
      <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-8">
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Fingerprint className="text-blue-500" size={20} />
            </div>
            <h4 className="text-xs font-bold text-zinc-200 uppercase tracking-tight">Source → Sink</h4>
          </div>
          <p className="text-[11px] text-zinc-500 leading-relaxed">
            Identificamos a origem dos dados (entrada) e o ponto crítico de execução (sink). Sem fluxo confirmado, a análise é descartada como especulativa.
          </p>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg">
              <Target className="text-purple-500" size={20} />
            </div>
            <h4 className="text-xs font-bold text-zinc-200 uppercase tracking-tight">Impacto Real</h4>
          </div>
          <p className="text-[11px] text-zinc-500 leading-relaxed">
            Prioridade total para falhas exploráveis em ambiente de produção (S0-S2). Exclusão ativa de vulnerabilidades puramente teóricas ou teóricas sem PoC.
          </p>
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 rounded-lg">
              <Zap className="text-emerald-500" size={20} />
            </div>
            <h4 className="text-xs font-bold text-zinc-200 uppercase tracking-tight">VRP Grounding</h4>
          </div>
          <p className="text-[11px] text-zinc-500 leading-relaxed">
            Conformidade estrita com as regras do <strong>Google Bug Hunters</strong> e filtro anti-AI-Slop integrado para relatórios limpos, curtos e com PoCs manuais não-especulativas.
          </p>
        </div>
      </div>

      <div className="bg-zinc-900 p-4 border-t border-zinc-800">
        <div className="flex flex-wrap gap-4 text-[9px] font-mono text-zinc-600 uppercase">
          <span className="flex items-center gap-1"><Bug size={10} /> Não-Especulativo</span>
          <span className="flex items-center gap-1"><Search size={10} /> Evidência Direta</span>
          <span className="flex items-center gap-1"><Shield size={10} /> Validação de Patch</span>
        </div>
      </div>
    </div>
  );
};
