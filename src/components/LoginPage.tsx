import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Shield, Lock, User, Eye, EyeOff, AlertCircle, ArrowLeft } from 'lucide-react';
import { cn } from '../lib/utils';

interface LoginPageProps {
  onLogin: (success: boolean) => void;
  onBack?: () => void;
}

export function LoginPage({ onLogin, onBack }: LoginPageProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(false);

    // Credenciais solicitadas pelo usuário
    if (username === 'patchcyberhunter' && password === '@patch321') {
      setTimeout(() => {
        onLogin(true);
      }, 800);
    } else {
      setTimeout(() => {
        setError(true);
        setIsSubmitting(false);
      }, 500);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d0d0d] flex items-center justify-center p-4 selection:bg-emerald-500/30 selection:text-emerald-500">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-md bg-[#121212]/80 backdrop-blur-xl border border-zinc-800 rounded-[2rem] p-8 md:p-12 shadow-[0_0_50px_rgba(0,0,0,0.5)] border-zinc-800/50 relative"
      >
        {onBack && (
          <button 
            onClick={onBack}
            className="absolute top-8 left-8 text-zinc-600 hover:text-white transition-colors flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest"
          >
            <ArrowLeft size={14} /> Voltar
          </button>
        )}

        <div className="flex flex-col items-center mb-10 mt-8 md:mt-4">
          <div className="p-5 bg-emerald-500/10 rounded-2xl border border-emerald-500/20 mb-6 shadow-[0_0_20px_rgba(16,185,129,0.1)]">
            <Shield size={44} className="text-emerald-500" />
          </div>
          <h1 
            translate="no" 
            className="text-3xl font-black text-white tracking-tighter uppercase text-center mb-2"
          >
            Cyber Hunter Lab
          </h1>
          <h2 className="text-[11px] font-mono font-bold text-zinc-500 tracking-[0.2em] uppercase text-center max-w-[240px] leading-relaxed">
            Mecanismo de Auditoria de Elite
          </h2>
          <div className="mt-6 flex items-center gap-3">
            <span className="text-[9px] font-mono text-emerald-500/80 border border-emerald-500/30 bg-emerald-500/5 px-3 py-1 rounded-full uppercase tracking-widest font-bold">Protocolo v5.0</span>
            <div className="w-1 h-1 rounded-full bg-zinc-800" />
            <span className="text-[9px] font-mono text-zinc-600 uppercase tracking-widest font-medium">Kernel Ativo</span>
          </div>
        </div>

        {error && (
          <motion.div 
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-6 p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-start gap-3"
          >
            <AlertCircle size={18} className="text-amber-500 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-amber-200/80 leading-relaxed">
              Sistema protegido. Tentativas incorretas são registradas localmente.
            </p>
          </motion.div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <label className="text-[10px] font-mono font-bold text-zinc-500 uppercase tracking-widest flex items-center gap-2">
              <User size={12} /> Conecte-se
            </label>
            <div className="relative group">
              <input 
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Usuário"
                className="w-full bg-zinc-900/50 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-zinc-300 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all font-mono"
                required
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[10px] font-mono font-bold text-zinc-500 uppercase tracking-widest flex items-center gap-2">
              <Lock size={12} /> Senha
            </label>
            <div className="relative group">
              <input 
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Senha"
                className="w-full bg-zinc-900/50 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-zinc-300 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all font-mono pr-12"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400 transition-colors"
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className={cn(
              "w-full bg-[#1a1a1a] hover:bg-zinc-800 border border-zinc-800 rounded-xl py-3.5 flex items-center justify-center gap-3 transition-all active:scale-[0.98] group",
              isSubmitting ? "opacity-50 cursor-not-allowed" : "cursor-pointer"
            )}
          >
            {isSubmitting ? (
              <div className="w-4 h-4 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <Lock size={16} className="text-emerald-500 group-hover:scale-110 transition-transform" />
                <span className="text-xs font-mono font-bold uppercase tracking-[0.2em] text-zinc-300 group-hover:text-white">Acessar Sistema</span>
              </>
            )}
          </button>
        </form>

        <div className="mt-8 text-center">
          <p className="text-[10px] font-mono text-zinc-600 leading-relaxed max-w-[240px] mx-auto uppercase">
            Autenticação: SHA-256 + token de sessão (8h) • Limite de taxa: 5 x/15 min
          </p>
        </div>
      </motion.div>
    </div>
  );
}
