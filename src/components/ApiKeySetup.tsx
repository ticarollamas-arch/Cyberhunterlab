import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Key, ShieldCheck, Zap, AlertCircle, X, ExternalLink } from 'lucide-react';
import { useApiKey } from '../lib/apiKey';
import { cn } from '../lib/utils';

export function ApiKeySetup({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { apiKey, setApiKey, isConfigured } = useApiKey();
  const [inputValue, setInputValue] = useState(apiKey || '');
  const [showKey, setShowKey] = useState(false);

  const handleSave = () => {
    setApiKey(inputValue.trim() || null);
    onClose();
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[60]"
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-[#121212] border border-zinc-800 rounded-2xl shadow-2xl p-8 z-[70] overflow-hidden"
          >
            {/* Background Accent */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/5 blur-3xl rounded-full -mr-16 -mt-16" />
            
            <div className="relative space-y-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={cn(
                    "p-2 rounded-lg border",
                    isConfigured ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-500" : "bg-zinc-800 border-zinc-700 text-zinc-500"
                  )}>
                    <Zap size={20} className={isConfigured ? "animate-pulse" : ""} />
                  </div>
                  <div>
                    <h2 className="text-sm font-mono font-bold uppercase tracking-widest text-white">System Activation</h2>
                    <p className="text-[10px] font-mono text-zinc-500 uppercase">Bring Your Own Key (BYOK)</p>
                  </div>
                </div>
                <button onClick={onClose} className="text-zinc-500 hover:text-white transition-colors">
                  <X size={20} />
                </button>
              </div>

              <div className="space-y-4">
                <div className="p-4 bg-zinc-900/50 border border-zinc-800/50 rounded-xl space-y-3">
                  <p className="text-xs text-zinc-400 leading-relaxed italic">
                    "O motor matemático do Cyber Hunter Lab requer combustível (Google AI API Key) de alta performance."
                  </p>
                  <div className="flex flex-col gap-2 p-3 bg-amber-500/5 border border-amber-500/20 rounded-lg">
                    <div className="flex items-center gap-2 text-[10px] font-mono text-amber-500 uppercase tracking-tighter font-bold">
                      <Zap size={12} className="animate-pulse" /> Requisito de Alta Performance
                    </div>
                    <p className="text-[9px] font-mono text-zinc-500 leading-tight">
                      DICA: Para evitar 'Logic Stalling' (atrasos de sincronização), recomenda-se o uso de chaves com faturamento ativo (saldo acima de R$ 200). A ferramenta não consumirá todo seu crédito, o saldo apenas garante prioridade e alta vazão de tokens para processamento neural profundo.
                    </p>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 flex justify-between">
                    Google AI API Key
                    <a 
                      href="https://aistudio.google.com/app/apikey" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:underline flex items-center gap-1 normal-case tracking-normal"
                    >
                      Obter Chave <ExternalLink size={10} />
                    </a>
                  </label>
                  <div className="relative group">
                    <input
                      type={showKey ? "text" : "password"}
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder="AIzaSy..."
                      className="w-full bg-[#0d0d0d] border border-zinc-800 rounded-lg px-4 py-3 text-xs font-mono text-white focus:outline-none focus:border-zinc-500 transition-all pr-12 group-hover:border-zinc-700"
                    />
                    <button
                      type="button"
                      onClick={() => setShowKey(!showKey)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-zinc-600 hover:text-zinc-400 transition-colors"
                    >
                      {showKey ? <Key size={14} /> : <Key size={14} className="opacity-50" />}
                    </button>
                  </div>
                </div>

                {!isConfigured && !inputValue && (
                  <div className="flex items-start gap-2 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                    <AlertCircle size={14} className="text-red-500 mt-0.5 flex-shrink-0" />
                    <p className="text-[10px] text-red-500/80 font-mono italic">
                      O sistema funcionará em modo 'Offline' (Sem IA) até que uma chave seja detectada.
                    </p>
                  </div>
                )}
              </div>

              <div className="pt-2 flex flex-col gap-3">
                <div className="flex gap-3">
                  <button
                    onClick={handleSave}
                    className="flex-1 px-4 py-2.5 bg-zinc-100 text-black text-[10px] sm:text-xs font-bold uppercase tracking-widest rounded-lg hover:bg-white transition-all shadow-xl shadow-white/5"
                  >
                    Ativar Motor
                  </button>
                  {apiKey && (
                    <button
                      onClick={() => { setApiKey(null); setInputValue(''); onClose(); }}
                      className="px-4 py-2.5 bg-red-500/10 border border-red-500/20 text-red-500 text-[10px] sm:text-xs font-bold uppercase tracking-widest rounded-lg hover:bg-red-500/20 transition-all"
                    >
                      Remover
                    </button>
                  )}
                </div>
                <p className="text-[9px] font-mono text-zinc-600 text-center uppercase tracking-widest">
                  <ShieldCheck size={10} className="inline mr-1 text-emerald-500" /> 
                  Segurança Total: Chave salva apenas nesta sessão
                </p>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
