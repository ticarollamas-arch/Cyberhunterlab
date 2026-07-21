import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldAlert, 
  Activity, 
  Search, 
  History, 
  Zap, 
  Bug, 
  Lock, 
  AlertCircle,
  Loader2,
  FileCode,
  Image as ImageIcon,
  Target,
  ArrowLeft,
  Shield,
  Zap as Power,
  Globe,
  Settings,
  LayoutDashboard,
  Cpu,
  Terminal,
  LogOut,
  Key,
  Trash2,
  Database,
  BookOpen,
  FileText
} from 'lucide-react';
import { CodeInput } from './components/CodeInput';
import { AnalysisDashboard } from './components/AnalysisDashboard';
import { VRPResourceHub } from './components/VRPResourceHub';
import { AgenticPipeline } from './components/AgenticPipeline';
import { OSVSchemaModule } from './components/OSVSchemaModule';
import { OSSVRPScopeGenerator } from './components/OSSVRPScopeGenerator';
import { ReverseArchEngine } from './components/ReverseArchEngine';
import { CWE22Academy } from './components/CWE22Academy';
import { UniversalReportGenerator } from './components/UniversalReportGenerator';
import { LoginPage } from './components/LoginPage';
import { LandingPage } from './components/LandingPage';
import { analyzePatch } from './services/gemini';
import { SecurityAnalysis } from './types';
import { MethodologyCard } from './components/MethodologyCard';
import { Badge } from './components/ui/Badge';
import { cn } from './lib/utils';
import { ApiKeyProvider, useApiKey } from './lib/apiKey';
import { ApiKeySetup } from './components/ApiKeySetup';

function AppContent() {
  const [hasStarted, setHasStarted] = useState<boolean>(() => {
    return localStorage.getItem('lab_started') === 'true';
  });
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return localStorage.getItem('vrp_auth') === 'true';
  });
  const { apiKey, isConfigured, selectedModel } = useApiKey();
  const [showApiKeySetup, setShowApiKeySetup] = useState(false);
  const [view, setView] = useState<'validator' | 'resources' | 'pipeline' | 'osv' | 'vrp-scope' | 'reverse-arch' | 'cwe22-academy' | 'report-generator'>(() => {
    return (localStorage.getItem('validator_view') as any) || 'validator';
  });
  const [codeBefore, setCodeBefore] = useState(() => {
    const saved = localStorage.getItem('validator_code_before');
    return saved !== null ? saved : `func (sp *subpath) SafeMakeDir(subdir string, base string, perm os.FileMode) error {
        realBase, err := filepath.EvalSymlinks(base)
        if err != nil {
                return fmt.Errorf("error resolving symlinks in %s: %s", base, err)
        }

        // VULNERABILIDADE LÓGICA: Junção direta sem validação de prefixo estrito.
        // Se o 'subdir' contiver "../../../", o caminho final escapa da 'realBase'.
        realFullPath := filepath.Join(realBase, subdir)

        return doSafeMakeDir(realFullPath, realBase, perm)
}`;
  });
  const [codeAfter, setCodeAfter] = useState(() => {
    const saved = localStorage.getItem('validator_code_after');
    return saved !== null ? saved : `func (sp *subpath) SafeMakeDirSecure(subdir string, base string, perm os.FileMode) error {
        realBase, err := filepath.EvalSymlinks(base)
        if err != nil {
                return fmt.Errorf("error resolving symlinks in %s: %s", base, err)
        }

        // REMEDIAÇÃO CANÔNICA: Limpeza e canonicalização do caminho resultante
        realFullPath := filepath.Clean(filepath.Join(realBase, subdir))

        // PROTEÇÃO ATIVA: Garante estritamente que o caminho final pertença à pasta base
        if !strings.HasPrefix(realFullPath, realBase + string(filepath.Separator)) {
                return fmt.Errorf("security violation: subpath escaped target directory boundary")
        }

        return doSafeMakeDir(realFullPath, realBase, perm)
}`;
  });
  const [diff, setDiff] = useState(() => {
    const saved = localStorage.getItem('validator_diff');
    return saved !== null ? saved : `-        realFullPath := filepath.Join(realBase, subdir)
+        realFullPath := filepath.Clean(filepath.Join(realBase, subdir))
+        if !strings.HasPrefix(realFullPath, realBase + string(filepath.Separator)) {
+                return fmt.Errorf("security violation: subpath escaped target directory boundary")
+        }`;
  });
  const [customRules, setCustomRules] = useState(() => {
    return localStorage.getItem('validator_custom_rules') || '';
  });
  const [showCustomRules, setShowCustomRules] = useState(false);
  const [useThinking, setUseThinking] = useState(() => {
    return localStorage.getItem('validator_use_thinking') === 'true';
  });
  const [safeMode, setSafeMode] = useState(() => {
    const saved = localStorage.getItem('validator_safe_mode');
    return saved === null ? true : saved === 'true';
  });
  const [validaAssinatura, setValidaAssinatura] = useState<boolean>(() => {
    const saved = localStorage.getItem('validator_valida_assinatura');
    return saved === null ? true : saved === 'true';
  });
  const [alvosCloud, setAlvosCloud] = useState<boolean>(() => {
    const saved = localStorage.getItem('validator_alvos_cloud');
    return saved === null ? true : saved === 'true';
  });
  const [bypassWAF, setBypassWAF] = useState<boolean>(() => {
    const saved = localStorage.getItem('validator_bypass_waf');
    return saved === null ? true : saved === 'true';
  });
  const [impactoDinamico, setImpactoDinamico] = useState<boolean>(() => {
    const saved = localStorage.getItem('validator_impacto_dinamico');
    return saved === null ? true : saved === 'true';
  });
  const [targetPlatform, setTargetPlatform] = useState<'google_vrp' | 'hackerone'>(() => {
    return (localStorage.getItem('validator_platform') as any) || 'google_vrp';
  });
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<SecurityAnalysis[]>(() => {
    const saved = localStorage.getItem('validator_history');
    return saved ? JSON.parse(saved) : [];
  });

  const [currentAnalysis, setCurrentAnalysis] = useState<SecurityAnalysis | null>(() => {
    const saved = localStorage.getItem('validator_current');
    return saved ? JSON.parse(saved) : null;
  });

  const handleLogin = (success: boolean) => {
    if (success) {
      setIsAuthenticated(true);
      localStorage.setItem('vrp_auth', 'true');
    }
  };

  const handleStartLab = (bypassAuth?: boolean) => {
    setHasStarted(true);
    localStorage.setItem('lab_started', 'true');
    if (bypassAuth) {
      setIsAuthenticated(true);
      localStorage.setItem('vrp_auth', 'true');
    }
  };

  const handleBackToLanding = () => {
    setHasStarted(false);
    localStorage.removeItem('lab_started');
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setHasStarted(false);
    localStorage.removeItem('vrp_auth');
    localStorage.removeItem('lab_started');
  };

  const deleteHistoryItem = (id: string) => {
    setHistory(prev => {
      const updated = prev.filter(item => item.id !== id);
      return updated;
    });
  };

  const clearHistory = () => {
    if (window.confirm("ATENÇÃO: Isso apagará permanentemente todo o histórico local de análises. Continuar?")) {
      setHistory([]);
      localStorage.removeItem('validator_history');
      localStorage.removeItem('validator_current');
      setCurrentAnalysis(null);
    }
  };

  // Persistence side effects
  useEffect(() => {
    localStorage.setItem('validator_history', JSON.stringify(history.slice(0, 20))); // Keep last 20
  }, [history]);

  useEffect(() => {
    localStorage.setItem('validator_current', JSON.stringify(currentAnalysis));
  }, [currentAnalysis]);

  useEffect(() => {
    localStorage.setItem('validator_view', view);
  }, [view]);

  useEffect(() => {
    const handleSwitch = (e: Event) => {
      const customEvent = e as CustomEvent;
      if (customEvent.detail) {
        setView(customEvent.detail);
      }
    };
    const handleOpenApiKeySetup = () => {
      setShowApiKeySetup(true);
    };
    window.addEventListener('switch-view', handleSwitch);
    window.addEventListener('open-api-key-setup', handleOpenApiKeySetup);
    return () => {
      window.removeEventListener('switch-view', handleSwitch);
      window.removeEventListener('open-api-key-setup', handleOpenApiKeySetup);
    };
  }, []);

  useEffect(() => {
    localStorage.setItem('validator_code_before', codeBefore);
  }, [codeBefore]);

  useEffect(() => {
    localStorage.setItem('validator_code_after', codeAfter);
  }, [codeAfter]);

  useEffect(() => {
    localStorage.setItem('validator_diff', diff);
  }, [diff]);

  useEffect(() => {
    localStorage.setItem('validator_custom_rules', customRules);
  }, [customRules]);

  useEffect(() => {
    localStorage.setItem('validator_use_thinking', String(useThinking));
  }, [useThinking]);

  useEffect(() => {
    localStorage.setItem('validator_safe_mode', String(safeMode));
  }, [safeMode]);

  useEffect(() => {
    localStorage.setItem('validator_valida_assinatura', String(validaAssinatura));
  }, [validaAssinatura]);

  useEffect(() => {
    localStorage.setItem('validator_alvos_cloud', String(alvosCloud));
  }, [alvosCloud]);

  useEffect(() => {
    localStorage.setItem('validator_bypass_waf', String(bypassWAF));
  }, [bypassWAF]);

  useEffect(() => {
    localStorage.setItem('validator_impacto_dinamico', String(impactoDinamico));
  }, [impactoDinamico]);

  useEffect(() => {
    localStorage.setItem('validator_platform', targetPlatform);
  }, [targetPlatform]);

  if (!hasStarted) {
    return <LandingPage onStart={handleStartLab} />;
  }

  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} onBack={handleBackToLanding} />;
  }

  const loadExample = () => {
    setCodeBefore(`// API de Gerenciamento de Arquivos - v1.0\napp.get('/download', (req, res) => {\n  const { filename } = req.query;\n  // Falha Crítica: Path Traversal direto sem sanitização\n  const filePath = path.join(__dirname, 'public', filename);\n  res.download(filePath);\n});`);
    setCodeAfter(`// API de Gerenciamento de Arquivos - v1.1 (Patch)\napp.get('/download', (req, res) => {\n  const { filename } = req.query;\n  // Fix: Sanitização usando basename e verificação de diretório\n  const safePath = path.basename(filename);\n  const finalPath = path.join(__dirname, 'public', safePath);\n  res.download(finalPath);\n});`);
    setDiff(`-  const filePath = path.join(__dirname, 'public', filename);\n+  const safePath = path.basename(filename);\n+  const finalPath = path.join(__dirname, 'public', safePath);`);
  };

  const handleStartAnalysis = async () => {
    const trimBefore = codeBefore ? codeBefore.trim() : '';
    if (trimBefore.startsWith('{') && (trimBefore.includes('vulnerability_chain') || trimBefore.includes('cyber_hunter_lab_version') || trimBefore.includes('vulnerabilities'))) {
      setError(null);
      localStorage.setItem('universal_pasted_json', trimBefore);
      setView('report-generator');
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('load-pasted-json', { detail: trimBefore }));
      }, 100);
      return;
    }

    if (!apiKey) {
      setShowApiKeySetup(true);
      return;
    }

    if (!codeBefore && !codeAfter && !diff) {
      setError('Forneça ao menos um dos campos de código ou diff.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setCurrentAnalysis(null);

    const activeRules: string[] = [];
    if (validaAssinatura) {
      activeRules.push("ANÁLISE DE ASSINATURA DE CONTEÚDO: Inclua checagem explícita de conteúdo no relatório buscando assinaturas reais (ex: 'root:x:0:0' para passwd, tokens GCP ou tags de configuração) demonstrando que não é um falso positivo.");
    }
    if (alvosCloud) {
      activeRules.push("FOCO EM CONTAINER E CLOUD: Priorize alvos e caminhos Kubernetes (/var/run/secrets/kubernetes.io/serviceaccount/token), credenciais do GCP/gcloud, logs de Docker e chaves cloud API em mappers.");
    }
    if (bypassWAF) {
      activeRules.push("BYPASS DE WAF SECUNDÁRIO: Se houver filtros, desenvolva variações de bypass do WAF em Double URL Encoding (%252e%252e%252f), Nested Paths (....//) ou UTF-8 Unicode, adicionando uma seção 'WAF Bypass Vector' na PoC.");
    }
    if (impactoDinamico) {
      activeRules.push("MATEIZ DE IMPACTO DINÂMICO: Se o leak atingir credenciais da nuvem ou tokens ativas, mude a severidade dinamicamente para P1/Crítico destacando 'Acesso e Compromisso total de Infraestrutura'.");
    }

    const compiledRules = [
      customRules,
      activeRules.length > 0 ? `[DIRECTIVAS DE REGRAS VRP 2026 INTEGRATED MODIFIERS]:\n${activeRules.map((r, i) => `${i + 1}. ${r}`).join("\n")}` : ""
    ].filter(Boolean).join("\n\n");

    try {
      const { analysis, verification } = await analyzePatch(
        codeBefore, 
        codeAfter, 
        diff, 
        useThinking, 
        compiledRules,
        history.map(h => h.result),
        targetPlatform,
        apiKey,
        safeMode,
        selectedModel
      );
      
      const session: SecurityAnalysis = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        code_before: codeBefore,
        code_after: codeAfter,
        diff: diff,
        result: analysis,
        verification: verification
      };

      setCurrentAnalysis(session);
      setHistory(prev => [session, ...prev]);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Erro durante a análise de IA.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d0d0d] text-zinc-300 font-sans selection:bg-zinc-700 selection:text-white overflow-x-hidden">
      {/* Top Navigation - Technical Header */}
      <header className="border-b border-zinc-800 bg-[#121212] py-4 px-4 md:px-6 flex flex-col md:flex-row items-center justify-between sticky top-0 z-50 gap-4 md:gap-0">
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="p-2 bg-zinc-800/50 rounded-lg border border-zinc-700/50 flex-shrink-0">
            <ShieldAlert size={20} className="text-zinc-100" />
          </div>
          <div className="min-w-0">
            <h1 translate="no" className="text-xs font-mono font-bold uppercase tracking-[0.2em] text-zinc-100 truncate max-w-[200px] sm:max-w-none">
              Cyber Hunter Lab <span className="text-zinc-500 font-normal">v5.0 Elite</span>
            </h1>
            <p className="text-[10px] font-mono text-zinc-500 uppercase flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse flex-shrink-0" />
              Status: Engenharia de Triagem (P1 Elite)
            </p>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 md:gap-6 w-full md:w-auto">
          <div className="flex items-center gap-2 sm:gap-4 text-[10px] font-mono text-zinc-500 bg-zinc-900/50 px-2 sm:px-3 py-1 rounded-full border border-zinc-800 max-w-full overflow-x-auto no-scrollbar">
            <button 
              onClick={() => setShowApiKeySetup(true)}
              className={cn(
                "flex items-center gap-1.5 transition-colors whitespace-nowrap",
                isConfigured ? "text-emerald-500" : "text-zinc-600 hover:text-zinc-400"
              )}
            >
              <Key size={12} className="shrink-0" /> <span className="hidden xs:inline">ENGINE:</span> {isConfigured ? "FUELED" : "BYOK"}
            </button>
            <span className="flex items-center gap-1.5 text-zinc-400 border-l border-zinc-800 pl-2 sm:pl-4 whitespace-nowrap">
              <Cpu size={12} className="shrink-0" /> {useThinking ? "PRO 3.1" : "FLASH 3.5"}
            </span>
          </div>
          <nav className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-1 w-full sm:w-auto justify-center sm:justify-start gap-px sm:gap-1 overflow-x-auto no-scrollbar">
            <button 
              onClick={() => setView('validator')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'validator' ? "bg-zinc-800 text-white border border-zinc-700 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <LayoutDashboard size={14} className="shrink-0" /> <span className="hidden xxs:inline">Validator</span>
            </button>
            <button 
              onClick={() => setView('pipeline')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'pipeline' ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <Terminal size={14} className="shrink-0" /> <span className="hidden xxs:inline">Pipeline</span>
            </button>
            <button 
              onClick={() => setView('osv')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'osv' ? "bg-zinc-800 text-white border border-zinc-700 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <Database size={14} className="shrink-0" /> <span className="hidden xxs:inline">OSV 1.7.5</span>
            </button>
            <button 
              onClick={() => setView('vrp-scope')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'vrp-scope' ? "bg-zinc-800 text-white border border-zinc-700 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <Target size={14} className="shrink-0" /> <span className="hidden xxs:inline">VRP Scope</span>
            </button>
            <button 
              onClick={() => setView('reverse-arch')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'reverse-arch' ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <Cpu size={14} className="shrink-0 text-indigo-400" /> <span className="hidden xxs:inline">Reverse Arch</span>
            </button>
            <button 
              id="nav-btn-cwe22-academy"
              onClick={() => setView('cwe22-academy')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'cwe22-academy' ? "bg-red-500/10 text-red-400 border border-red-500/20 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <BookOpen size={14} className="shrink-0 text-red-400" /> <span className="hidden xxs:inline">CWE-22 Academy</span>
            </button>
            <button 
              id="nav-btn-report-generator"
              onClick={() => setView('report-generator')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'report-generator' ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <FileText size={14} className="shrink-0 text-[#10b981]" /> <span className="hidden xxs:inline">Gerador Relatório</span>
            </button>
            <button 
              onClick={() => setView('resources')}
              className={cn(
                "flex-1 sm:flex-none flex items-center justify-center gap-1 xs:gap-2 px-2 xs:px-3 py-1.5 rounded-md text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest transition-all whitespace-nowrap",
                view === 'resources' ? "bg-zinc-800 text-white border border-zinc-700 shadow-xl" : "text-zinc-500 hover:text-zinc-400"
              )}
            >
              <Globe size={14} className="shrink-0" /> <span className="hidden xxs:inline">Resources</span>
            </button>
          </nav>

          <div className="flex items-center flex-nowrap gap-2 w-full sm:w-auto justify-center overflow-x-auto no-scrollbar py-1">
            <button 
              onClick={() => setUseThinking(!useThinking)}
              className={cn(
                "flex-1 sm:flex-none p-1.5 xs:p-2 rounded border transition-all flex items-center justify-center gap-1.5 xs:gap-2 text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest whitespace-nowrap",
                useThinking ? "bg-amber-500/10 border-amber-500/50 text-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.2)]" : "bg-zinc-800 border-zinc-700 text-zinc-500 hover:text-zinc-400"
              )}
              title={useThinking ? "Modo Raciocínio (PRO 3.1): Faz auditoria lógica cognitiva profunda (15-30s)" : "Modo High-Speed (FLASH 3.5): Triagem instantânea em segundos"}
            >
              <Power size={14} className="shrink-0" />
              <span>
                {useThinking ? "Thinking" : "Fast"}
              </span>
            </button>

            <div className="flex items-center gap-1 bg-zinc-800 rounded p-0.5 border border-zinc-700">
              <button 
                onClick={() => setTargetPlatform('google_vrp')}
                className={cn(
                  "px-2 py-0.5 rounded text-[9px] font-mono uppercase transition-all",
                  targetPlatform === 'google_vrp' ? "bg-white text-black" : "text-zinc-500 hover:text-zinc-400"
                )}
              >
                VRP
              </button>
              <button 
                onClick={() => setTargetPlatform('hackerone')}
                className={cn(
                  "px-2 py-0.5 rounded text-[9px] font-mono uppercase transition-all",
                  targetPlatform === 'hackerone' ? "bg-blue-600 text-white" : "text-zinc-500 hover:text-zinc-400"
                )}
              >
                H1
              </button>
            </div>

            <button 
              onClick={() => setSafeMode(!safeMode)}
              className={cn(
                "flex-1 sm:flex-none p-1.5 xs:p-2 rounded border transition-all flex items-center justify-center gap-1.5 xs:gap-2 text-[9px] xs:text-[10px] font-mono uppercase tracking-tight xs:tracking-widest whitespace-nowrap",
                safeMode ? "bg-emerald-500/10 border-emerald-500/50 text-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.2)]" : "bg-red-500/10 border-red-500/50 text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.2)]"
              )}
              title={safeMode ? "Modo Seguro Ativo (Ético)" : "Modo Ofensivo Ativo (Cautela)"}
            >
              <Shield size={14} className="shrink-0" />
              <span>
                {safeMode ? "Safe" : "Off"}
              </span>
            </button>
            
            <button 
              onClick={handleLogout}
              className="p-2 bg-red-500/10 border border-red-500/20 text-red-500 rounded hover:bg-red-500/20 transition-all flex-shrink-0"
              title="Logout"
            >
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto p-4 sm:p-6 md:p-8 space-y-12">
        <AnimatePresence mode="wait">
          {view === 'resources' ? (
            <VRPResourceHub key="resources" />
          ) : view === 'pipeline' ? (
            <AgenticPipeline key="pipeline" />
          ) : view === 'osv' ? (
            <OSVSchemaModule key="osv" />
          ) : view === 'vrp-scope' ? (
            <OSSVRPScopeGenerator key="vrp-scope" />
          ) : view === 'reverse-arch' ? (
            <ReverseArchEngine key="reverse-arch" />
          ) : view === 'cwe22-academy' ? (
            <CWE22Academy key="cwe22-academy" />
          ) : view === 'report-generator' ? (
            <UniversalReportGenerator key="report-generator" />
          ) : !currentAnalysis ? (
            <motion.div 
              key="input-form"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-8"
            >
              {/* Introduction Card */}
              <div className="bg-[#121212] border border-zinc-800 rounded-xl p-6 sm:p-8 flex flex-col md:flex-row items-center gap-8 justify-between shadow-2xl">
                <div className="max-w-2xl space-y-4 text-center md:text-left">
                  <Badge variant="info">Arquitetura de Segurança Propriatária v5.0 Elite</Badge>
                  <h2 className="text-3xl font-bold text-white tracking-tight leading-none">
                    <span translate="no">Cyber Hunter Lab</span>: Engenharia <span className="text-emerald-500 underline decoration-emerald-800 underline-offset-8">de Auditoria Avançada</span>.
                  </h2>
                  <p className="text-zinc-400 text-sm leading-relaxed max-w-xl">
                    Pipeline integrado com <strong>Infraestrutura Proprietária</strong> para triagem massiva, análise de fluxo de dados (IDOR/BAC) e geração automatizada de bypasses para WAF.
                  </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button 
                  onClick={loadExample}
                  className="px-4 py-2 bg-blue-500/10 border border-blue-500/30 text-blue-400 rounded-lg text-[10px] font-mono uppercase tracking-widest hover:bg-blue-500/20 transition-all flex items-center gap-2"
                >
                  <Target size={14} /> Carregar Exemplo VRP
                </button>
                <div className="flex flex-wrap gap-2">
                  {['RCE', 'XSLeak', 'IDOR', 'AI Safety', 'Supply Chain'].map(rule => (
                    <span key={rule} className="text-[9px] font-mono text-zinc-600 bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800/50 flex items-center">
                      {rule}
                    </span>
                  ))}
                </div>
              </div>
                </div>
                <div className="grid grid-cols-2 gap-3 w-full md:w-auto">
                   <FeatureIcon icon={<Bug size={24} />} title="Sanity Checks" />
                   <FeatureIcon icon={<Activity size={24} />} title="Diff Analysis" />
                   <FeatureIcon icon={<History size={24} />} title="Regression" />
                   <FeatureIcon icon={<Zap size={24} />} title="Fast Audit" />
                </div>
              </div>

              {/* Input Section */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
                <CodeInput 
                  label="Código 'Vulnerável'" 
                  value={codeBefore} 
                  onChange={setCodeBefore} 
                  placeholder="Cole o arquivo antes do patch..."
                />
                <CodeInput 
                  label="Código 'Patch'" 
                  value={codeAfter} 
                  onChange={setCodeAfter} 
                  placeholder="Cole o arquivo após o patch..."
                  icon={<ShieldAlert size={14} />}
                />
              </div>

              {/* Directivas VRP 2026 Englober (GCP, WAF Bypasses, Assinatura, Impacto Dinâmico) */}
              <div className="border border-zinc-800 rounded-xl bg-[#121212]/35 overflow-hidden">
                <div className="p-4 border-b border-zinc-900 bg-zinc-900/10 flex items-center justify-between">
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-400 flex items-center gap-2">
                    <Shield className="text-emerald-500" size={14} /> Diretivas Gold-Standard VRP 2026 (Google I/O Spec)
                  </h3>
                  <span className="text-[10px] text-zinc-600 font-mono uppercase tracking-wider bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800">
                    Otimizadores de Motor
                  </span>
                </div>
                
                <div className="p-6 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                  {/* Toggle 1: Validação de Assinatura */}
                  <div className="p-4 bg-zinc-900/30 border border-zinc-800 hover:border-zinc-700/50 rounded-lg flex flex-col justify-between transition-all gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono font-bold text-white uppercase tracking-wider">Checagem de Assinatura</span>
                        <div className="w-2 h-2 rounded-full bg-emerald-500/80 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                      </div>
                      <p className="text-[10px] text-zinc-400">Analisa corpos de resposta em busca de assinaturas reais (ex: root:x:0:0 ou payloads env) mitigando falsos positivos de status 200 OK.</p>
                    </div>
                    <button
                      onClick={() => setValidaAssinatura(!validaAssinatura)}
                      className={cn(
                        "w-full py-2 font-mono text-[9px] uppercase font-bold tracking-widest border rounded transition-all",
                        validaAssinatura 
                          ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20" 
                          : "bg-zinc-900/55 border-zinc-800 text-zinc-600 hover:text-zinc-500"
                      )}
                    >
                      {validaAssinatura ? "Ativo (Filtro Anti-Slop)" : "Inativo"}
                    </button>
                  </div>

                  {/* Toggle 2: Dicionário GCP e Containers */}
                  <div className="p-4 bg-zinc-900/30 border border-zinc-800 hover:border-zinc-700/50 rounded-lg flex flex-col justify-between transition-all gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono font-bold text-white uppercase tracking-wider">Alvos Cloud & Containers</span>
                        <div className="w-2 h-2 rounded-full bg-blue-500/80 shadow-[0_0_8px_rgba(59,130,246,0.5)]" />
                      </div>
                      <p className="text-[10px] text-zinc-400">Foca em tokens K8s, credenciais de contas de serviço GCP/gcloud, chaves de API secretas de nuvem e logs internos de microsserviços.</p>
                    </div>
                    <button
                      onClick={() => setAlvosCloud(!alvosCloud)}
                      className={cn(
                        "w-full py-2 font-mono text-[9px] uppercase font-bold tracking-widest border rounded transition-all",
                        alvosCloud 
                          ? "bg-blue-500/10 border-blue-500/30 text-blue-400 hover:bg-blue-500/20" 
                          : "bg-zinc-900/55 border-zinc-800 text-zinc-600 hover:text-zinc-500"
                      )}
                    >
                      {alvosCloud ? "Ativo (Foco GCP & K8s)" : "Inativo"}
                    </button>
                  </div>

                  {/* Toggle 3: Bypass Automático de WAF */}
                  <div className="p-4 bg-zinc-900/30 border border-zinc-800 hover:border-zinc-700/50 rounded-lg flex flex-col justify-between transition-all gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono font-bold text-white uppercase tracking-wider">WAF Bypass Automatic</span>
                        <div className="w-2 h-2 rounded-full bg-amber-500/80 shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
                      </div>
                      <p className="text-[10px] text-zinc-400">Implementa retroalimentação para contornar proteções básicas com Double URL Encoding, Nested Paths ou variações UTF-8.</p>
                    </div>
                    <button
                      onClick={() => setBypassWAF(!bypassWAF)}
                      className={cn(
                        "w-full py-2 font-mono text-[9px] uppercase font-bold tracking-widest border rounded transition-all",
                        bypassWAF 
                          ? "bg-amber-500/10 border-amber-500/30 text-amber-500 hover:bg-amber-500/20" 
                          : "bg-zinc-900/55 border-zinc-800 text-zinc-600 hover:text-zinc-500"
                      )}
                    >
                      {bypassWAF ? "Ativo (Double & Nested)" : "Inativo"}
                    </button>
                  </div>

                  {/* Toggle 4: Impacto de Negócio Dinâmico */}
                  <div className="p-4 bg-zinc-900/30 border border-zinc-800 hover:border-zinc-700/50 rounded-lg flex flex-col justify-between transition-all gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono font-bold text-white uppercase tracking-wider">Severidade Dinâmica</span>
                        <div className="w-2 h-2 rounded-full bg-red-500/80 shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                      </div>
                      <p className="text-[10px] text-zinc-400">Surgicamente ajusta criticidade de P2 para P1 ao ler leaks confidenciais, fundamentando impacto de infraestrutura de nuvem.</p>
                    </div>
                    <button
                      onClick={() => setImpactoDinamico(!impactoDinamico)}
                      className={cn(
                        "w-full py-2 font-mono text-[9px] uppercase font-bold tracking-widest border rounded transition-all",
                        impactoDinamico 
                          ? "bg-red-500/10 border-red-500/30 text-red-500 hover:bg-red-500/20" 
                          : "bg-zinc-900/55 border-zinc-800 text-zinc-600 hover:text-zinc-500"
                      )}
                    >
                      {impactoDinamico ? "Ativo (Dinâmico S1/S2)" : "Inativo"}
                    </button>
                  </div>
                </div>
              </div>

              {/* Custom Rules Input (Collapsible) */}
              <div className="border border-zinc-800 rounded-xl overflow-hidden">
                <button 
                  onClick={() => setShowCustomRules(!showCustomRules)}
                  className="w-full flex items-center justify-between p-4 bg-zinc-900/30 hover:bg-zinc-900/50 transition-colors"
                >
                  <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-500 flex items-center gap-2">
                    <ShieldAlert size={14} /> Regras Customizadas (Contexto do App)
                  </h3>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-zinc-600 font-mono italic">
                      {customRules ? "Padrões Ativos" : "Opcional"}
                    </span>
                    <Search size={14} className={cn("text-zinc-600 transition-transform", showCustomRules && "rotate-180")} />
                  </div>
                </button>
                
                {showCustomRules && (
                  <div className="p-6 bg-[#121212] border-t border-zinc-800 animate-in slide-in-from-top-2">
                    <textarea 
                      value={customRules}
                      onChange={(e) => setCustomRules(e.target.value)}
                      placeholder="Ex: 'Neste codebase, não usamos queries SQL puras, apenas o ORM X. Qualquer uso de strings em queries é falha crítica.' ou 'Este serviço lida com dados PII bancários, regras de DP são prioridade.'"
                      className="w-full h-24 bg-zinc-900 border border-zinc-800 rounded p-3 text-xs font-mono text-zinc-300 focus:outline-none focus:border-zinc-700 transition-colors resize-none"
                    />
                  </div>
                )}
              </div>

              <div className="pt-4 border-t border-zinc-900 flex flex-col md:flex-row items-center justify-between gap-6">
                <div className="flex items-center gap-4 text-xs font-mono text-zinc-500">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" /> Lógica Determinística (High Precision)
                  </div>
                  <div className="w-px h-4 bg-zinc-800" />
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-blue-500" /> Grounding VRP 2025
                  </div>
                </div>

                <div className="flex items-center gap-4">
                   <button 
                    disabled={isAnalyzing}
                    onClick={handleStartAnalysis}
                    className="group relative px-4 sm:px-8 py-2.5 sm:py-3 bg-white text-black font-bold uppercase text-[10px] sm:text-xs tracking-[0.2em] rounded-md hover:bg-zinc-200 transition-all flex items-center gap-2 disabled:opacity-50"
                  >
                    {isAnalyzing ? <Loader2 className="animate-spin" size={16} /> : <Power size={16} />}
                    {isAnalyzing ? (useThinking ? "Analisando (Modo Pro)..." : "Analisando (Modo Rápido)...") : (!isConfigured ? "Ativar e Validar" : "Iniciar Validação")}
                  </button>
                  {error && (
                    <div className="flex items-center gap-2 text-red-500 text-xs font-mono animate-pulse">
                      <AlertCircle size={14} /> {error}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-6">
                  <div className="text-right">
                    <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">Logic Pipeline</p>
                    <p className="text-[11px] font-mono text-zinc-400">Cyber Hunter Kernel v5</p>
                  </div>
                </div>
              </div>

              <MethodologyCard />
            </motion.div>
          ) : (
            <div className="space-y-6">
              <div className="flex items-center justify-between gap-4">
                <button 
                  onClick={() => setCurrentAnalysis(null)}
                  className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 hover:text-white transition-colors flex items-center gap-2"
                >
                  <ArrowLeft size={14} /> Retornar ao Terminal
                </button>
                <div className="flex items-center gap-2">
                   <Badge variant="neutral">Sessão ID: {currentAnalysis.id.slice(0, 8)}</Badge>
                </div>
              </div>
              <AnalysisDashboard analysis={currentAnalysis} />
            </div>
          )}
        </AnimatePresence>

        {/* History Sidebar/Section */}
        {history.length > 0 && !currentAnalysis && (
          <motion.section 
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            className="pt-12 border-t border-zinc-900"
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xs font-mono font-bold uppercase tracking-[0.3em] text-zinc-500 flex items-center gap-2">
                <History size={16} /> Registros de Análise Recentes
              </h3>
              <button 
                onClick={clearHistory}
                className="text-[10px] font-mono text-red-500/70 hover:text-red-500 border border-red-500/20 px-3 py-1 rounded hover:bg-red-500/5 transition-all flex items-center gap-1.5 uppercase"
              >
                <Trash2 size={12} /> Limpar Tudo
              </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {history.map((item) => (
                <div key={item.id} className="relative group/item">
                  <button 
                    key={item.id}
                    onClick={() => setCurrentAnalysis(item)}
                    className="w-full bg-[#121212] border border-zinc-800 p-4 rounded-lg hover:border-zinc-600 transition-all text-left flex items-center gap-4 overflow-hidden group"
                  >
                    <div className="p-2 bg-zinc-800/50 rounded-lg group-hover:bg-zinc-700/50 transition-colors">
                      <FileCode size={20} className={cn(
                        item.result.vulnerabilidade ? "text-red-500" : "text-emerald-500"
                      )} />
                    </div>
                    <div className="flex-1 overflow-hidden">
                      <h4 className="text-[11px] font-mono font-bold text-white uppercase truncate">
                        {item.result.vulnerabilidade || "Nenhuma falha"}
                      </h4>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-[10px] font-mono text-zinc-500 truncate">{new Date(item.timestamp).toLocaleTimeString()}</span>
                        <Badge variant={item.result.impacto === 'baixo' ? 'info' : (item.result.impacto === 'medio' ? 'warning' : 'danger')}>
                          {item.result.impacto}
                        </Badge>
                      </div>
                    </div>
                  </button>
                  <button 
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteHistoryItem(item.id);
                    }}
                    className="absolute top-2 right-2 p-1.5 bg-red-500/10 text-red-500 rounded opacity-0 group-hover/item:opacity-100 transition-all hover:bg-red-500 hover:text-white border border-red-500/20"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
          </motion.section>
        )}
      </main>

      {/* Footer */}
      <footer className="mt-24 border-t border-zinc-900 py-12 px-6 text-center">
        <div className="flex flex-col items-center gap-4">
          <ShieldAlert className="text-zinc-700" size={32} />
          <h3 translate="no" className="text-xs font-mono font-bold text-zinc-500 uppercase tracking-widest">Cyber Hunter Lab</h3>
          <p className="text-[10px] font-mono text-zinc-600 max-w-lg leading-relaxed uppercase tracking-widest">
            Laboratório de Caçadores Cibernéticos • Assistente Técnico de Auditoria
          </p>
        </div>
      </footer>

      <ApiKeySetup isOpen={showApiKeySetup} onClose={() => setShowApiKeySetup(false)} />
    </div>
  );
}

export default function App() {
  return (
    <ApiKeyProvider>
      <AppContent />
    </ApiKeyProvider>
  );
}

const FeatureIcon = ({ icon, title }: { icon: React.ReactNode, title: string }) => (
  <div className="p-4 bg-zinc-900/50 border border-zinc-800/30 rounded-xl flex flex-col items-center gap-2 group hover:border-zinc-700 transition-colors">
    <div className="text-zinc-500 group-hover:text-zinc-300 transition-colors">{icon}</div>
    <span className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest">{title}</span>
  </div>
);

const ArrowBack = ({ size, className }: { size?: number, className?: string }) => (
  <svg 
    width={size || 16} 
    height={size || 16} 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2" 
    strokeLinecap="round" 
    strokeLinejoin="round" 
    className={className}
  >
    <path d="M19 12H5M12 19l-7-7 7-7" />
  </svg>
);
