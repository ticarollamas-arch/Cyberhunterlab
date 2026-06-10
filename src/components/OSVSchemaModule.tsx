import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  Database, 
  FileJson, 
  Plus, 
  Trash2, 
  Play, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Search, 
  Code, 
  Copy, 
  ExternalLink, 
  FileText, 
  Check, 
  Settings, 
  ShieldCheck,
  RefreshCw,
  Terminal,
  HelpCircle,
  Hash
} from 'lucide-react';
import { cn } from '../lib/utils';

// Types for OSV Specification v1.7.5
export interface OSVEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OSVRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  repo?: string;
  events: OSVEvent[];
}

export interface OSVPackage {
  ecosystem: string;
  name: string;
  purl?: string;
}

export interface OSVAffected {
  package: OSVPackage;
  versions?: string[];
  ranges?: OSVRange[];
  severity?: { type: string; score: string }[];
}

export interface OSVSchema {
  schema_version: string;
  id: string;
  modified: string;
  published?: string;
  withdrawn?: string;
  aliases?: string[];
  upstream?: string[];
  related?: string[];
  summary?: string;
  details?: string;
  severity?: { type: string; score: string }[];
  affected: OSVAffected[];
  references?: { type: string; url: string }[];
  credits?: { name: string; contact?: string[]; type?: string }[];
  database_specific?: Record<string, any>;
}

// Pre-configured real-world examples from the OSV spec/databases
const EXAMPLES: Record<string, { title: string; description: string; data: OSVSchema }> = {
  'cve-zlib': {
    title: 'CVE-2025-1212 (zlib SemVer)',
    description: 'Exemplo clássico de path traversal em compression-libs com intervalos SemVer lineares.',
    data: {
      schema_version: "1.7.5",
      id: "CVE-2025-1212",
      modified: "2026-01-21T18:30:00Z",
      published: "2026-01-15T12:00:00Z",
      aliases: ["GHSA-v98c-fx33-3114"],
      summary: "Critical Path Traversal in zlib compression tool",
      details: "A path traversal vulnerability exists in zlib unpack routine. If user input directory paths contain relative sequences like `../`, arbitrary file writing is executed in administrative contexts.",
      severity: [
        { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" },
        { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N" }
      ],
      affected: [
        {
          package: {
            ecosystem: "npm",
            name: "zlib",
            purl: "pkg:npm/zlib"
          },
          ranges: [
            {
              type: "SEMVER",
              events: [
                { introduced: "1.0.0" },
                { fixed: "1.2.12" }
              ]
            }
          ],
          versions: ["1.0.0", "1.1.0", "1.2.0", "1.2.5", "1.2.11"]
        }
      ],
      references: [
        { type: "ADVISORY", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-1212" },
        { type: "REPORT", url: "https://github.com/madler/zlib/issues/1212" }
      ],
      credits: [
        { name: "Oliver Chang", contact: ["ochang@google.com"], type: "REPORTER" }
      ]
    }
  },
  'git-commit': {
    title: 'OSV-2026-788 (Git Hash Limits)',
    description: 'Uso de hashes Git em repositórios para controle granular de ramificações complexas.',
    data: {
      schema_version: "1.7.5",
      id: "OSV-2026-788",
      modified: "2026-02-10T22:15:00Z",
      published: "2026-02-01T15:00:00Z",
      summary: "Memory corruption in hyper-engine core",
      details: "Heap buffer overflow in hyper-engine during stream frames chunk processing.",
      affected: [
        {
          package: {
            ecosystem: "Linux",
            name: "Kernel"
          },
          ranges: [
            {
              type: "GIT",
              repo: "https://github.com/torvalds/linux",
              events: [
                { introduced: "8a6c8e100f89d31fefbc90c0a6b7d2" },
                { fixed: "9c3c1a20df90db99ffeb901c0b1e1" },
                { limit: "f4410a56fe73e1c0d48" }
              ]
            }
          ],
          versions: ["v5.15-rc1", "v5.15-rc2"]
        }
      ]
    }
  },
  'opensuse-rpm': {
    title: 'openSUSE-SU-2026-0414 (Ecosystem Specific)',
    description: 'Advisory Linux com mapeamentos RPM binários específicos de ecossistema.',
    data: {
      schema_version: "1.7.5",
      id: "openSUSE-SU-2026-0414",
      modified: "2026-01-21T09:00:00Z",
      published: "2026-01-21T09:00:00Z",
      summary: "Security update for openssl",
      details: "Multiple security issue in OpenSSL library were patched in modern RPM compilation environments.",
      affected: [
        {
          package: {
            ecosystem: "openSUSE:Leap:15.5",
            name: "openssl",
            purl: "pkg:rpm/opensuse/openssl"
          },
          ranges: [
            {
              type: "ECOSYSTEM",
              events: [
                { introduced: "0" },
                { fixed: "3.1.4-150500.5.1" }
              ]
            }
          ]
        }
      ],
      database_specific: {
        "suse_priority": "important",
        "affected_architectures": ["x86_64", "aarch64"]
      }
    }
  }
};

export function OSVSchemaModule() {
  const [activeTab, setActiveTab] = useState<'editor' | 'form' | 'spec'>('editor');
  const [jsonInput, setJsonInput] = useState<string>(() => JSON.stringify(EXAMPLES['cve-zlib'].data, null, 2));
  const [parsedOsv, setParsedOsv] = useState<OSVSchema | null>(EXAMPLES['cve-zlib'].data);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  
  // Interactive testing states
  const [queryPkg, setQueryPkg] = useState<string>('zlib');
  const [queryVer, setQueryVer] = useState<string>('1.2.11');
  const [traceLogs, setTraceLogs] = useState<string[]>([]);
  const [verdict, setVerdict] = useState<'VULNERABLE' | 'SAFE' | 'UNKNOWN' | null>(null);

  // Form Fields states (synchronized with parent state parsedOsv)
  const [formId, setFormId] = useState<string>('CVE-2025-1212');
  const [formSummary, setFormSummary] = useState<string>('Critical Path Traversal in zlib compression tool');
  const [formDetails, setFormDetails] = useState<string>('A path traversal vulnerability exists in zlib unpack routine.');
  const [formEcosystem, setFormEcosystem] = useState<string>('npm');
  const [formPkgName, setFormPkgName] = useState<string>('zlib');
  const [formVersions, setFormVersions] = useState<string>('1.0.0, 1.1.0, 1.2.0, 1.2.5, 1.2.11');
  const [formRangeIntro, setFormRangeIntro] = useState<string>('1.0.0');
  const [formRangeFixed, setFormRangeFixed] = useState<string>('1.2.12');
  const [formRangeType, setFormRangeType] = useState<'SEMVER' | 'ECOSYSTEM' | 'GIT'>('SEMVER');

  // Load a preset example
  const handleLoadExample = (key: string) => {
    const example = EXAMPLES[key];
    if (example) {
      const content = JSON.stringify(example.data, null, 2);
      setJsonInput(content);
      validateAndParse(content);
      
      // Update form values
      setFormId(example.data.id);
      setFormSummary(example.data.summary || '');
      setFormDetails(example.data.details || '');
      if (example.data.affected?.[0]) {
        const aff = example.data.affected[0];
        setFormEcosystem(aff.package.ecosystem);
        setFormPkgName(aff.package.name);
        setFormVersions(aff.versions?.join(', ') || '');
        if (aff.ranges?.[0]) {
          setFormRangeType(aff.ranges[0].type);
          const introEvent = aff.ranges[0].events.find(e => e.introduced !== undefined);
          const fixedEvent = aff.ranges[0].events.find(e => e.fixed !== undefined);
          setFormRangeIntro(introEvent?.introduced || '0');
          setFormRangeFixed(fixedEvent?.fixed || '');
        }
      }
      addTraceLog(`Sistema carregado com o modelo: ${example.title}`);
    }
  };

  // Live validator effect helper
  const validateAndParse = (text: string) => {
    try {
      if (!text.trim()) {
        setValidationError('A entrada JSON está vazia.');
        setParsedOsv(null);
        return;
      }
      const data = JSON.parse(text) as OSVSchema;
      
      // Spec v1.7.5 Validation Checks
      if (!data.id) {
        throw new Error("Campo obrigatório ausente: 'id'");
      }
      if (!data.schema_version) {
        throw new Error("Campo obrigatório ausente: 'schema_version' (Ex: '1.7.5')");
      }
      if (!data.modified) {
        throw new Error("Campo obrigatório ausente: 'modified' (Formato ISO RFC3339)");
      }
      if (!data.affected || !Array.isArray(data.affected) || data.affected.length === 0) {
        throw new Error("Aviso de especificação: 'affected' deve ser uma matriz não vazia defendendo o ecossistema afetado.");
      }
      
      // Check individual affected objects
      data.affected.forEach((aff, idx) => {
        if (!aff.package) {
          throw new Error(`affected[${idx}] necessita de chave 'package'`);
        }
        if (!aff.package.ecosystem || !aff.package.name) {
          throw new Error(`affected[${idx}].package requer chaves 'ecosystem' e 'name'`);
        }
      });

      setValidationError(null);
      setParsedOsv(data);
    } catch (err: any) {
      setValidationError(err.message || 'JSON inválido ou corrompido.');
      setParsedOsv(null);
    }
  };

  // Sync Form to Raw JSON
  const handleSyncFormToRaw = () => {
    if (!formId || !formPkgName) return;
    
    const versionsArr = formVersions.split(',').map(s => s.trim()).filter(Boolean);
    const updatedOsv: OSVSchema = {
      schema_version: "1.7.5",
      id: formId,
      modified: new Date().toISOString(),
      published: parsedOsv?.published || new Date().toISOString(),
      summary: formSummary,
      details: formDetails,
      severity: parsedOsv?.severity || [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" }],
      affected: [
        {
          package: {
            ecosystem: formEcosystem,
            name: formPkgName,
            purl: `pkg:${formEcosystem.toLowerCase()}/${formPkgName}`
          },
          ranges: [
            {
              type: formRangeType,
              events: [
                { introduced: formRangeIntro },
                { fixed: formRangeFixed }
              ].filter(evt => Object.values(evt).some(val => val !== ''))
            }
          ],
          versions: versionsArr.length > 0 ? versionsArr : undefined
        }
      ],
      references: parsedOsv?.references || [{ type: "ADVISORY", url: `https://api.osv.dev/v1/vulns/${formId}` }]
    };

    const formatted = JSON.stringify(updatedOsv, null, 2);
    setJsonInput(formatted);
    setParsedOsv(updatedOsv);
    setValidationError(null);
    addTraceLog(`Valores do formulário de rascunho sincronizados na árvore JSON.`);
  };

  // Semantic Version utility comparing logic based on the spec
  const parseSemVer = (v: string) => {
    const clean = v.trim().replace(/^v/, '');
    const [core, pre] = clean.split('-');
    const parts = core.split('.').map(x => parseInt(x, 10) || 0);
    return { parts, pre };
  };

  const compareSemVer = (v1: string, v2: string): number => {
    if (v1 === '0') return -1; // special value "0" in OSV introduced limits (stands for earliest point)
    if (v2 === '0') return 1;
    if (v1 === '*') return 1;  // special value "*" limit (infinity)
    if (v2 === '*') return -1;
    
    const s1 = parseSemVer(v1);
    const s2 = parseSemVer(v2);
    
    const maxLength = Math.max(s1.parts.length, s2.parts.length);
    for (let i = 0; i < maxLength; i++) {
      const a = s1.parts[i] || 0;
      const b = s2.parts[i] || 0;
      if (a !== b) return a - b;
    }
    
    if (!s1.pre && s2.pre) return 1; // 1.2.0 > 1.2.0-rc1
    if (s1.pre && !s2.pre) return -1;
    if (s1.pre && s2.pre) {
      return s1.pre.localeCompare(s2.pre);
    }
    return 0;
  };

  const addTraceLog = (msg: string) => {
    setTraceLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  // Executing Canonical IsVulnerable algorithm (direct Javascript transcription of the OSV pseudocode)
  const handleExecuteIsVulnerable = () => {
    setTraceLogs([]);
    const logs: string[] = [];
    const logTrace = (msg: string) => {
      logs.push(`[TRACE] ${msg}`);
    };

    if (!parsedOsv) {
      setVerdict('UNKNOWN');
      setTraceLogs([`[ERRO] Nenhum esquema OSV válido carregado no editor para avaliar.`]);
      return;
    }

    logTrace(`Iniciando IsVulnerable(pkg="${queryPkg}", v="${queryVer}")`);
    
    let isVulnerableResult = false;
    let packageMatched = false;

    // Helper functions translating the exact pseudocode
    const IncludedInVersions = (v: string, versions?: string[]): boolean => {
      if (!versions) return false;
      logTrace(`  -> Avaliando se "${v}" está explicitamente incluído no array "versions": [${versions.join(', ')}]`);
      for (const version of versions) {
        if (v === version) {
          logTrace(`    [MATCH] Versão exata encontrada: "${v}" == "${version}"`);
          return true;
        }
      }
      return false;
    };

    const BeforeLimits = (v: string, range: OSVRange): boolean => {
      const limitEvents = range.events.filter(e => e.limit !== undefined);
      if (limitEvents.length === 0) {
        logTrace(`    -> No limit events found. Implicit "*" entry assumed (true)`);
        return true;
      }

      for (const evt of range.events) {
        if (evt.limit) {
          const comp = compareSemVer(v, evt.limit);
          logTrace(`    -> BeforeLimits check: comparando v="${v}" < limit="${evt.limit}" (Resultado comp: ${comp})`);
          if (comp < 0) {
            return true;
          }
        }
      }
      return false;
    };

    const IncludedInRanges = (v: string, ranges?: OSVRange[]): boolean => {
      if (!ranges) return false;
      logTrace(`  -> Avaliando se "${v}" está contido nos intervalos definidos de commits/SemVer`);

      for (let rIdx = 0; rIdx < ranges.length; rIdx++) {
        const range = ranges[rIdx];
        logTrace(`    -> Analisando range[${rIdx}] do tipo: ${range.type}`);
        
        if (BeforeLimits(v, range)) {
          let vulnerable = false;
          
          // Mimic: for evt in sorted(range.events)
          // Sort events so introduced comes first, then fixed, then last_affected
          const sortedEvents = [...range.events].sort((a, b) => {
            const valA = a.introduced || a.fixed || a.last_affected || '';
            const valB = b.introduced || b.fixed || b.last_affected || '';
            return compareSemVer(valA, valB);
          });

          for (const evt of sortedEvents) {
            if (evt.introduced) {
              const comp = compareSemVer(v, evt.introduced);
              logTrace(`      - Testando evt.introduced="${evt.introduced}": v="${v}" >= "${evt.introduced}"? ${comp >= 0 ? "SIM" : "NÃO"}`);
              if (comp >= 0) {
                vulnerable = true;
              }
            } 
            else if (evt.fixed) {
              const comp = compareSemVer(v, evt.fixed);
              logTrace(`      - Testando evt.fixed="${evt.fixed}": v="${v}" >= "${evt.fixed}"? ${comp >= 0 ? "SIM" : "NÃO"}`);
              if (comp >= 0) {
                vulnerable = false;
              }
            } 
            else if (evt.last_affected) {
              const comp = compareSemVer(v, evt.last_affected);
              logTrace(`      - Testando evt.last_affected="${evt.last_affected}": v="${v}" > "${evt.last_affected}"? ${comp > 0 ? "SIM" : "NÃO"}`);
              if (comp > 0) {
                vulnerable = false;
              }
            }
          }

          if (vulnerable) {
            logTrace(`    [VEREDITO INTERNO] Vulnerabilidade avaliada como ativa para o intervalo analisado.`);
            return true;
          }
        } else {
          logTrace(`    [RECUSADO] A versão "${v}" excede o evento de limite superior na especificação deste range.`);
        }
      }
      return false;
    };

    // Main algorithm loop
    for (const affected of parsedOsv.affected) {
      logTrace(`Comparando pacote da entrada ["${affected.package.name}"] com o pesquisado: "${queryPkg}"`);
      if (affected.package.name.toLowerCase() === queryPkg.toLowerCase()) {
        packageMatched = true;
        logTrace(`[MATCH] Pacote identificado como afetado. Iniciando verificação de versão lógica...`);
        
        if (IncludedInVersions(queryVer, affected.versions) || IncludedInRanges(queryVer, affected.ranges)) {
          isVulnerableResult = true;
          break;
        }
      }
    }

    if (!packageMatched) {
      logTrace(`[SAFE] Nenhum pacote afetado combina com "${queryPkg}".`);
    }

    setVerdict(isVulnerableResult ? 'VULNERABLE' : 'SAFE');
    setTraceLogs(logs);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(jsonInput);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Run initial parse
  useEffect(() => {
    validateAndParse(jsonInput);
  }, [jsonInput]);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-zinc-800 pb-6">
        <div>
          <div className="flex items-center gap-2 text-emerald-500 font-mono text-xs uppercase tracking-[0.2em] mb-2">
            <Database size={14} className="animate-pulse" /> Padrão OSV (Open Source Vulnerability)
          </div>
          <h2 className="text-xl font-mono font-bold text-white uppercase flex items-center gap-3">
             Esquema de Vulnerabilidade OSV <span className="text-zinc-500 text-xs tracking-normal normal-case italic">Spec v1.7.5 (2026)</span>
          </h2>
          <p className="text-[11px] font-sans text-zinc-400 mt-1 max-w-2xl leading-relaxed">
            Formato de intercâmbio compacto padronizado por Oliver Chang e Russ Cox (Google) para automação precisa e distribuída de vulnerabilidades em ecossistemas de código aberto.
          </p>
        </div>
        
        <div className="flex flex-wrap gap-2">
          {Object.keys(EXAMPLES).map((key) => (
            <button
              key={key}
              onClick={() => handleLoadExample(key)}
              className="px-2.5 py-1.5 bg-zinc-900 border border-zinc-800 rounded text-[9px] font-mono text-zinc-400 hover:border-zinc-700 hover:text-white transition-all"
            >
              ⚡ Carregar {EXAMPLES[key].title.split(' ')[0]}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Editor & Configuration Section (Left side, covers 7 of 12 columns) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-[#121212] border border-zinc-800 rounded-xl overflow-hidden shadow-xl">
            {/* Nav Tabs */}
            <div className="bg-zinc-900/60 border-b border-zinc-800 px-4 py-2 flex items-center justify-between">
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveTab('editor')}
                  className={cn(
                    "px-3 py-1 text-[10px] uppercase font-mono font-bold rounded tracking-wider flex items-center gap-1.5 transition-all",
                    activeTab === 'editor' 
                      ? "bg-zinc-800 text-white border border-zinc-700" 
                      : "text-zinc-500 hover:text-zinc-300"
                  )}
                >
                  <Code size={12} /> JSON Puro (.json)
                </button>
                <button
                  onClick={() => {
                    setActiveTab('form');
                    handleSyncFormToRaw();
                  }}
                  className={cn(
                    "px-3 py-1 text-[10px] uppercase font-mono font-bold rounded tracking-wider flex items-center gap-1.5 transition-all",
                    activeTab === 'form' 
                      ? "bg-zinc-800 text-white border border-zinc-700" 
                      : "text-zinc-500 hover:text-zinc-300"
                  )}
                >
                  <Settings size={12} /> Formulário de Rascunho
                </button>
                <button
                  onClick={() => setActiveTab('spec')}
                  className={cn(
                    "px-3 py-1 text-[10px] uppercase font-mono font-bold rounded tracking-wider flex items-center gap-1.5 transition-all",
                    activeTab === 'spec' 
                      ? "bg-zinc-800 text-white border border-zinc-700" 
                      : "text-zinc-500 hover:text-zinc-300"
                  )}
                >
                  <HelpCircle size={12} /> Ajuda da Spec
                </button>
              </div>

              {/* Status Indicator */}
              <div className="flex items-center gap-2">
                {validationError ? (
                  <span className="text-[9px] font-mono font-bold text-red-500 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded flex items-center gap-1">
                    <XCircle size={10} /> SINTAXE ECO INVÁLIDA
                  </span>
                ) : (
                  <span className="text-[9px] font-mono font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded flex items-center gap-1">
                    <CheckCircle2 size={10} /> OSV COMPLIANT
                  </span>
                )}
              </div>
            </div>

            {/* Tab: IDE Editor */}
            {activeTab === 'editor' && (
              <div className="p-4 space-y-4">
                <div className="flex items-center justify-between text-[10px] font-mono text-zinc-500">
                  <span>Sinta-se livre para modificar o JSON abaixo seguindo o padrão 1.7.5:</span>
                  <button
                    onClick={handleCopyCode}
                    className="flex items-center gap-1 text-[9px] bg-zinc-900 border border-zinc-800 px-2 py-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-white transition-all"
                  >
                    {copied ? <Check size={11} className="text-emerald-500" /> : <Copy size={11} />}
                    {copied ? 'Copiado!' : 'Copiar'}
                  </button>
                </div>
                
                <textarea
                  value={jsonInput}
                  onChange={(e) => setJsonInput(e.target.value)}
                  className="w-full h-96 bg-zinc-950 font-mono text-xs text-zinc-300 border border-zinc-800 rounded-lg p-4 focus:outline-none focus:border-zinc-700 focus:ring-1 focus:ring-zinc-800 resize-none select-all"
                  placeholder="Cole seu JSON OSV v1.7.5 aqui..."
                />

                {validationError && (
                  <div className="p-3 bg-red-950/20 border border-red-900/50 rounded-lg flex items-start gap-2.5">
                    <AlertTriangle size={14} className="text-red-500 shrink-0 mt-0.5" />
                    <span className="text-[10px] font-mono text-red-400">{validationError}</span>
                  </div>
                )}
              </div>
            )}

            {/* Tab: Form Builder */}
            {activeTab === 'form' && (
              <div className="p-6 space-y-6 max-h-[500px] overflow-y-auto no-scrollbar">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Identificador (id)</label>
                    <input
                      type="text"
                      value={formId}
                      onChange={(e) => setFormId(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500/50"
                      placeholder="Ex: CVE-2025-1212"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Summary (Título curto)</label>
                    <input
                      type="text"
                      value={formSummary}
                      onChange={(e) => setFormSummary(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-emerald-500/50"
                      placeholder="Resumo de até 120 caracteres"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Details (Markdown)</label>
                  <textarea
                    value={formDetails}
                    onChange={(e) => setFormDetails(e.target.value)}
                    className="w-full h-20 bg-zinc-950 border border-zinc-800 rounded p-3 text-xs font-mono text-white focus:outline-none focus:border-emerald-500/50 resize-none"
                    placeholder="Descrição detalhada sobre a rota e as condições de explotação..."
                  />
                </div>

                <div className="border-t border-zinc-900 pt-4 space-y-4">
                  <span className="text-[10px] font-mono font-bold text-emerald-500 uppercase tracking-widest block">📦 Pacote Afetado (Schema Target)</span>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div>
                      <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Ecosystem</label>
                      <input
                        type="text"
                        value={formEcosystem}
                        onChange={(e) => setFormEcosystem(e.target.value)}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white"
                        placeholder="Ex: npm, PyPI, crates.io"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Nome do Pacote</label>
                      <input
                        type="text"
                        value={formPkgName}
                        onChange={(e) => setFormPkgName(e.target.value)}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white"
                        placeholder="Ex: requests, django, openssl"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Versões Enumeradas (Vírgula)</label>
                      <input
                        type="text"
                        value={formVersions}
                        onChange={(e) => setFormVersions(e.target.value)}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white"
                        placeholder="1.0.0, 1.1.0, 1.2.0"
                      />
                    </div>
                  </div>
                </div>

                <div className="border-t border-zinc-900 pt-4 space-y-4">
                  <span className="text-[10px] font-mono font-bold text-emerald-500 uppercase tracking-widest block">⏳ Linha do Tempo de Versões (Events Core)</span>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div>
                      <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Formato de Intervalo</label>
                      <select
                        value={formRangeType}
                        onChange={(e) => setFormRangeType(e.target.value as any)}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white"
                      >
                        <option value="SEMVER">SEMVER (Semantic 2.0)</option>
                        <option value="ECOSYSTEM">ECOSYSTEM (Arbitrário)</option>
                        <option value="GIT">GIT (Commit SHA hashes)</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Versão Introduzida (introduced)</label>
                      <input
                        type="text"
                        value={formRangeIntro}
                        onChange={(e) => setFormRangeIntro(e.target.value)}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white"
                        placeholder="Ex: 1.0.0 ou 0"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] font-mono font-bold text-zinc-500 uppercase mb-2">Versão Corrigida (fixed)</label>
                      <input
                        type="text"
                        value={formRangeFixed}
                        onChange={(e) => setFormRangeFixed(e.target.value)}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs font-mono text-white"
                        placeholder="Ex: 1.2.12"
                      />
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t border-zinc-900 text-right">
                  <button
                    onClick={() => {
                      handleSyncFormToRaw();
                      setActiveTab('editor');
                    }}
                    className="px-6 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold font-mono text-[11px] uppercase tracking-wider rounded-lg transition-all"
                  >
                     Sincronizar e Visualizar JSON
                  </button>
                </div>
              </div>
            )}

            {/* Tab: Documentation */}
            {activeTab === 'spec' && (
              <div className="p-6 space-y-4 max-h-[500px] overflow-y-auto no-scrollbar text-xs font-mono text-zinc-400 leading-relaxed">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider border-b border-zinc-800 pb-1">Conceitos Chave da Spec OSV 1.7.5</h4>
                
                <div className="space-y-3">
                  <p>
                    <strong className="text-zinc-200">schema_version:</strong> Indica qual versão do esquema foi usada (SemVer 2.0.0 sem prefixo).
                  </p>
                  <p>
                    <strong className="text-zinc-200">id:</strong> Identificador único absoluto no formato <code className="text-emerald-400">&lt;DB&gt;-&lt;ENTRY&gt;</code> (ex: <code className="text-zinc-300">CVE-2025-0101, GHSA-vvv4-xxxx-1111</code>).
                  </p>
                  <p>
                    <strong className="text-zinc-200">ranges.events:</strong> Um log de eventos ordenado descrevendo o ciclo de vida. Tipos permitidos:
                  </p>
                  <ul className="list-disc pl-4 space-y-1 text-[11px]">
                    <li><code className="text-amber-400">introduced:</code> versão onde a falha começou (use "0" para representar do início).</li>
                    <li><code className="text-emerald-400">fixed:</code> versão exata que contém o patch definitivo de mitigação.</li>
                    <li><code className="text-zinc-300">last_affected:</code> última versão vulnerável catalogada antes de patches rápidos.</li>
                    <li><code className="text-blue-400">limit:</code> limitador superior rígido de branches paralelas exploradas.</li>
                  </ul>
                  <p>
                    <strong className="text-zinc-200">aliases:</strong> Uma matriz bidirecional que conecta esta descoberta com outros repositórios mundiais catalogados.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Live Playground: Vulnerability Engine Simulator (Right side, covers 5 of 12 columns) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Engine Card */}
          <div className="bg-[#121212] border border-blue-500/10 bg-gradient-to-b from-[#121212] to-blue-950/5 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-center gap-2 text-blue-400 font-mono text-[10px] uppercase tracking-widest">
              <Terminal size={14} /> CANONICAL OSV STATE ENGINE (RAM SIMULATOR)
            </div>

            <div className="space-y-1">
              <h3 className="text-sm font-mono font-bold text-white">Simulador do Algoritmo IsVulnerable()</h3>
              <p className="text-[10px] text-zinc-500 leading-relaxed font-mono">
                Execute e analise a árvore lógica do interpretador de pacotes baseado exatamente no pseudo-código canônico da especificação oficial.
              </p>
            </div>

            <div className="bg-zinc-950/70 border border-zinc-900 rounded-xl p-4 gap-4 grid grid-cols-1 sm:grid-cols-2">
              <div>
                <label className="block text-[9px] font-mono font-bold text-zinc-500 uppercase mb-2">Simular Pacote</label>
                <input
                  type="text"
                  value={queryPkg}
                  onChange={(e) => setQueryPkg(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-300"
                  placeholder="Ex: zlib"
                />
              </div>
              <div>
                <label className="block text-[9px] font-mono font-bold text-zinc-500 uppercase mb-2">Testar Versão do Usuário</label>
                <input
                  type="text"
                  value={queryVer}
                  onChange={(e) => setQueryVer(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-300"
                  placeholder="Ex: 1.2.11"
                />
              </div>
            </div>

            {/* Run Button */}
            <button
              onClick={handleExecuteIsVulnerable}
              disabled={!parsedOsv}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-mono font-bold text-xs uppercase tracking-widest rounded-lg transition-all shadow-[0_0_15px_rgba(37,99,235,0.2)] flex items-center justify-center gap-2"
            >
              <Play size={12} /> Executar Motor IsVulnerable()
            </button>

            {/* Simulated Verdict Output */}
            {verdict !== null && (
              <div className="border-t border-zinc-800 pt-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase">Veredito do interpretador:</span>
                  <span className={cn(
                    "text-xs font-mono font-extrabold px-3 py-1 rounded border",
                    verdict === 'VULNERABLE'
                      ? "bg-red-500/10 text-red-500 border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.15)] animate-pulse"
                      : verdict === 'SAFE'
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                      : "bg-zinc-800 text-zinc-400 border-zinc-700"
                  )}>
                    {verdict === 'VULNERABLE' ? '● VULN_DETECTED (AFETADO)' : verdict === 'SAFE' ? '● SAFE (PROTEGIDO)' : '● DESCONHECIDO'}
                  </span>
                </div>

                {/* Canonical pseudocode trace panel */}
                <div className="space-y-1.5">
                  <span className="text-[9px] font-mono text-zinc-500 uppercase tracking-widest block">Log de Rastreamento de Passos (Spec Flow):</span>
                  <div className="bg-black/80 border border-zinc-900 p-3 rounded-lg overflow-hidden font-mono text-[9px] text-zinc-400 leading-relaxed max-h-48 overflow-y-auto no-scrollbar space-y-1 select-all">
                    {traceLogs.length === 0 ? (
                      <div className="italic text-zinc-600 text-center py-2">
                        Execute a consulta lógica para monitorar os caminhos e escopos de recursão.
                      </div>
                    ) : (
                      traceLogs.map((log, idx) => (
                        <div key={idx} className={cn(
                          log.includes('[MATCH]') && "text-emerald-400 font-bold",
                          log.includes('[VEREDITO') && "text-amber-400 font-bold",
                          log.includes('[SAFE]') && "text-emerald-500",
                          log.includes('[ERRO]') && "text-red-500"
                        )}>
                          {log}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Quick Info Summary */}
          <div className="bg-[#121212] border border-zinc-800 rounded-xl p-5 space-y-3 text-[11px] leading-relaxed">
            <h4 className="text-zinc-300 font-mono font-bold text-xs flex items-center gap-2">
              <ShieldCheck size={14} className="text-emerald-500" /> Benefícios do Schema OSV v1.7.5
            </h4>
            <div className="space-y-2 text-zinc-400">
              <p>
                A grande desvantagem dos sistemas legados de triagem é a imprecisão de metadados de pacotes. O OSV resolve isso ao focar em <strong className="text-zinc-300">eventos específicos em commits</strong> e mapeá-los para ecossistemas de linguagens.
              </p>
              <p>
                Isso impede avisos erráticos alarmistas e falsos positivos em pipelines de análise CI/CD automáticos, aumentando a confiabilidade de ferramentas VRP do nível do Cyber Hunter Lab.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
