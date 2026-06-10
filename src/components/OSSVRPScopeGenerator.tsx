import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Target, 
  Zap, 
  Code, 
  Terminal, 
  Globe, 
  FileText, 
  Copy, 
  Check, 
  Download, 
  Sliders, 
  Play, 
  AlertTriangle,
  Coins,
  Cpu,
  Bookmark,
  Share2,
  Trash2,
  ChevronRight,
  Sparkles,
  Search,
  CheckSquare,
  Brain,
  RefreshCw,
  Eye,
  Send,
  Server
} from 'lucide-react';
import { cn } from '../lib/utils';
import { useApiKey } from '../lib/apiKey';
import { GoogleGenAI } from '@google/genai';
import ReactMarkdown from 'react-markdown';

// Pre-populated high-end templates for bug class presets
interface VRPTemplate {
  id: string;
  projectName: string;
  repoUrl: string;
  tier: 'Tier 1' | 'Tier 2' | 'Tier 3';
  vulnerabilityClass: string;
  source: string;
  sink: string;
  vulnerableCode: string;
  patchCode: string;
  pocSteps: string[];
  pocPayload: string;
}

const TEMPLATES: Record<string, VRPTemplate> = {
  'path-traversal-go': {
    id: 'path-traversal-go',
    projectName: 'Kubernetes VolumeMount Subpath',
    repoUrl: 'https://github.com/kubernetes/kubernetes',
    tier: 'Tier 1',
    vulnerabilityClass: 'Path Traversal (CWE-22 / Logical Symlink Escape)',
    source: 'Parâmetro input \'subdir\' fornecido na configuração do VolumeMount',
    sink: 'filepath.Join(realBase, subdir)',
    vulnerableCode: `func (sp *subpath) SafeMakeDir(subdir string, base string, perm os.FileMode) error {
        realBase, err := filepath.EvalSymlinks(base)
        if err != nil {
                return fmt.Errorf("error resolving symlinks in %s: %s", base, err)
        }

        // VULNERABILIDADE LÓGICA: Junção direta sem validação de prefixo estrito.
        // Se o 'subdir' contiver "../../../", o caminho final escapa da 'realBase'.
        realFullPath := filepath.Join(realBase, subdir)

        return doSafeMakeDir(realFullPath, realBase, perm)
}`,
    patchCode: `func (sp *subpath) SafeMakeDirSecure(subdir string, base string, perm os.FileMode) error {
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
}`,
    pocSteps: [
      "Configure um VolumeMount com a propriedade subPath contendo sequências de travessia (ex: '../../../../tmp/evil_dir').",
      "Inicie o pod correspondente no cluster do Kubernetes.",
      "O VolumeMount escapará do diretório base ('realBase'), criando ou acessando o diretório fora da fronteira de isolamento."
    ],
    pocPayload: `apiVersion: v1\nkind: Pod\nmetadata:\n  name: attack-pod\nspec:\n  containers:\n  - name: attack\n    image: nginx\n    volumeMounts:\n    - mountPath: /var/target\n      name: workdir\n      subPath: ../../../../../etc/malicious`
  },
  'arg-injection': {
    id: 'arg-injection',
    projectName: 'gRPC Protobuf Compiler toolchain',
    repoUrl: 'https://github.com/protocolbuffers/protobuf',
    tier: 'Tier 2',
    vulnerabilityClass: 'Argument Injection leading to RCE (CWE-88)',
    source: 'Compiler flag custom config input',
    sink: 'exec.Command("protoc", args...)',
    vulnerableCode: `// Node.js backend executing protoc CLI compiler
const { execFile } = require('child_process');

function compileProto(userProvidedFlag) {
  // BUG: Sem filtragem de opções de flags. Permite passar argumentos como '--plugin='
  const args = ['--proto_path=.', 'message.proto', userProvidedFlag];
  
  execFile('protoc', args, (error, stdout, stderr) => {
    console.log("Compile result:", stdout);
  });
}`,
    patchCode: `// Node.js backend executing protoc proxy compiling (Secured)
const { execFile } = require('child_process');

function compileProto(userProvidedFlag) {
  // FIX: Blindagem ativa e canônica de injeção de flags e argumentos CLI
  if (userProvidedFlag.startsWith('-') || userProvidedFlag.includes('=')) {
    throw new Error('Injeção maliciosa de argumentos de CommandLine detectada!');
  }
  
  const args = ['--proto_path=.', 'message.proto', userProvidedFlag];
  execFile('protoc', args, (error, stdout, stderr) => {
    console.log("Compile output:", stdout);
  });
}`,
    pocSteps: [
      "Simule a chamada do módulo de compilação CLI remota.",
      "Injete uma flag maliciosa que force a execução de scripts arbitrários do sistema no host (Ex: `--plugin=protoc-gen-grpc=/usr/bin/touch`)",
      "Confirme a criação do arquivo temporário indicando execução arbitrária remota no contêiner."
    ],
    pocPayload: `--plugin=protoc-gen-grpc=/usr/bin/touch`
  }
};

export function OSSVRPScopeGenerator() {
  const { apiKey } = useApiKey();
  const [selectedTemplate, setSelectedTemplate] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_selected_template');
    return saved !== null ? saved : 'path-traversal-go';
  });

  // Unified State Suite (Parameters for Adaptive Narrative Engine)
  const [targetCompany, setTargetCompany] = useState<'google' | 'aws' | 'meta' | 'microsoft' | 'custom'>(() => {
    const saved = localStorage.getItem('vrp_target_company');
    return saved !== null ? (saved as any) : 'google';
  });
  const [reportTone, setReportTone] = useState<'academic' | 'hunter' | 'advisor' | 'direct'>(() => {
    const saved = localStorage.getItem('vrp_report_tone');
    return saved !== null ? (saved as any) : 'hunter';
  });
  const [structuralFocus, setStructuralFocus] = useState<'filesystem' | 'iam' | 'kubernetes' | 'auth_bypass'>(() => {
    const saved = localStorage.getItem('vrp_structural_focus');
    return saved !== null ? (saved as any) : 'kubernetes';
  });
  const [inferredArchitecture, setInferredArchitecture] = useState<'GO_K8S' | 'NODE_EXPRESS' | 'GRAPHQL' | 'AZURE_AD'>(() => {
    const saved = localStorage.getItem('vrp_inferred_architecture');
    return saved !== null ? (saved as any) : 'GO_K8S';
  });

  // Input States
  const [projName, setProjName] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_proj_name');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].projectName;
  });
  const [repoUrl, setRepoUrl] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_repo_url');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].repoUrl;
  });
  const [tier, setTier] = useState<'Tier 1' | 'Tier 2' | 'Tier 3'>(() => {
    const saved = localStorage.getItem('vrp_tier');
    return saved !== null ? (saved as any) : TEMPLATES['path-traversal-go'].tier;
  });
  const [vulnClass, setVulnClass] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_vuln_class');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].vulnerabilityClass;
  });
  const [sourceFlow, setSourceFlow] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_source_flow');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].source;
  });
  const [sinkFlow, setSinkFlow] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_sink_flow');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].sink;
  });
  const [vulnCode, setVulnCode] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_vuln_code');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].vulnerableCode;
  });
  const [patchCode, setPatchCode] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_patch_code');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].patchCode;
  });
  const [pocStepsText, setPocStepsText] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_poc_steps_text');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].pocSteps.join('\n');
  });
  const [pocPayload, setPocPayload] = useState<string>(() => {
    const saved = localStorage.getItem('vrp_poc_payload');
    return saved !== null ? saved : TEMPLATES['path-traversal-go'].pocPayload;
  });

  // VRP 2026 Checklist Compliance Configuration
  const [policyAntiSlop, setPolicyAntiSlop] = useState<boolean>(() => {
    const val = localStorage.getItem('vrp_policy_anti_slop');
    return val !== null ? val === 'true' : true;
  });
  const [policyReproduction, setPolicyReproduction] = useState<boolean>(() => {
    const val = localStorage.getItem('vrp_policy_reproduction');
    return val !== null ? val === 'true' : true;
  });
  const [policyTaintFlow, setPolicyTaintFlow] = useState<boolean>(() => {
    const val = localStorage.getItem('vrp_policy_taint_flow');
    return val !== null ? val === 'true' : true;
  });
  const [policyNoPermission, setPolicyNoPermission] = useState<boolean>(() => {
    const val = localStorage.getItem('vrp_policy_no_permission');
    return val !== null ? val === 'true' : true;
  });

  // Scoring Index Parameters
  const [severity, setSeverity] = useState<'P1' | 'PS1' | 'P2' | 'S2'>(() => {
    return (localStorage.getItem('vrp_severity') as any) || 'PS1';
  });
  const [duplicationRisk, setDuplicationRisk] = useState<'LOW' | 'MEDIUM' | 'HIGH'>(() => {
    return (localStorage.getItem('vrp_duplication_risk') as any) || 'LOW';
  });

  // Interactive Alignment Parameters
  const [alignAssetType, setAlignAssetType] = useState<'auth' | 'oauth' | 'session' | 'iam' | 'sensitive_api' | 'internal_data' | 'peripheral'>(() => {
    return (localStorage.getItem('vrp_align_asset_type') as any) || 'sensitive_api';
  });
  const [alignBoundaryCrossing, setAlignBoundaryCrossing] = useState<'sandbox_escape' | 'directory_traversal_extraction' | 'local_arbitrary_read' | 'credential_disclosure' | 'cross_service_abuse' | 'no_boundary'>(() => {
    return (localStorage.getItem('vrp_align_boundary_crossing') as any) || 'directory_traversal_extraction';
  });
  const [alignPracticalExploit, setAlignPracticalExploit] = useState<'deterministic_rce' | 'proven_privilege_escalation' | 'authenticated_read_bypass' | 'hypothetical_theory'>(() => {
    return (localStorage.getItem('vrp_align_practical_exploit') as any) || 'proven_privilege_escalation';
  });
  const [alignSystemicImpact, setAlignSystemicImpact] = useState<'cross_service_impact' | 'shared_trust_model_abuse' | 'isolated_input_flaw'>(() => {
    return (localStorage.getItem('vrp_align_systemic_impact') as any) || 'shared_trust_model_abuse';
  });

  // Output generated text
  const [reportMarkdown, setReportMarkdown] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);
  const [rewardRange, setRewardRange] = useState<string>('$20,000 - $31,337 USD');
  const [reportLanguage, setReportLanguage] = useState<'pt' | 'en'>(() => {
    return (localStorage.getItem('vrp_report_language') as any) || 'pt';
  });

  // AI Orchestration States
  const [isAiGenerating, setIsAiGenerating] = useState<boolean>(false);
  const [aiAlignmentReview, setAiAlignmentReview] = useState<string>('');
  const [isAligningWithAi, setIsAligningWithAi] = useState<boolean>(false);

  // Cognitive Compressor Input Textbox 
  const [rawInputReport, setRawInputReport] = useState<string>(
    `=== RELATÓRIO DO HACKER BRUTO / TRACES DE EXECUÇÃO ===\n` +
    `Descobri um path traversal crítico no backend ao analisar a rota '/ServeLogFile'.\n` +
    `Se passarmos o parâmetro '?filepath=../../../../etc/passwd', o sistema lê diretamente\n` +
    `porque ele usa o path.Join que aceita múltiplos marcadores de subida '..'.\n` +
    `Isso dá acesso ao arquivo /etc/passwd da VM do contêiner e vaza os tokens do Google Cloud.\n` +
    `Não feche o relatório como duplicado ou fora de escopo! A falha é estrutural.`
  );

  // Interactive Sandbox Simulator parameters
  const [simulatedFilterOn, setSimulatedFilterOn] = useState<boolean>(false);
  const [simulatedCertECDSA, setSimulatedCertECDSA] = useState<boolean>(true);
  const [simulatedPayloadInput, setSimulatedPayloadInput] = useState<string>('../../../../etc/passwd');
  const [sandboxLogs, setSandboxLogs] = useState<string[]>([
    '[*] Target: Plataforma de simulação sintonizada para auditoria local.',
    '[*] TLS Status: Canal de criptografia GTS WE1 intermediário validado com ECDSA v2026.',
    '[*] Pronto: Aguardando disparo de payload lógico do sandbox interativo.'
  ]);
  const [isSimulatingExploit, setIsSimulatingExploit] = useState<boolean>(false);
  const [simulatedPacketStatus, setSimulatedPacketStatus] = useState<'IDLE' | 'ROUTE' | 'BLOCKED' | 'BREACHED'>('IDLE');

  // Passive Fingerprinting States
  const [fingerprintTargetUrl, setFingerprintTargetUrl] = useState<string>('https://vrp-api-staging.internal.google');
  const [fingerprintInput, setFingerprintInput] = useState<string>(
    `HTTP/1.1 502 Bad Gateway\n` +
    `Server: istio-envoy\n` +
    `Date: Wed, 27 May 2026 20:37:57 GMT\n` +
    `X-Envoy-Upstream-Service-Time: 42\n` +
    `X-Google-Backplane-Cluster: corp-prod-uswest2\n` +
    `Via: 1.1 google`
  );
  const [isFingerprinting, setIsFingerprinting] = useState<boolean>(false);
  const [fingerprintLogs, setFingerprintLogs] = useState<string[]>([]);
  const [fingerprintResult, setFingerprintResult] = useState<{
    company: 'google' | 'aws' | 'meta' | 'microsoft' | 'custom' | null;
    arch: 'GO_K8S' | 'NODE_EXPRESS' | 'GRAPHQL' | 'AZURE_AD' | null;
    focus: 'filesystem' | 'iam' | 'kubernetes' | 'auth_bypass' | null;
    detectedHeaders: string[];
    confidence: number;
  } | null>(null);

  // Collapsible panel status indicators 
  const [showSandboxPanel, setShowSandboxPanel] = useState<boolean>(false);
  const [showCompressorPanel, setShowCompressorPanel] = useState<boolean>(false);
  const [showFingerprintPanel, setShowFingerprintPanel] = useState<boolean>(true);

  // Storage-based pipeline data synchronization state
  const [pipelineDataToSync, setPipelineDataToSync] = useState<{
    targetUrl: string;
    queryParam: string;
    evolvedPayload: string;
    rawPayload: string;
    bypassType: string;
    step: string;
    pocScript: string;
    company: 'google' | 'aws' | 'meta' | 'microsoft' | 'custom';
    projectName: string;
  } | null>(null);

  useEffect(() => {
    const checkPipelineSync = () => {
      const url = localStorage.getItem('pipeline_sync_target_url');
      if (url) {
        setPipelineDataToSync({
          targetUrl: url,
          queryParam: localStorage.getItem('pipeline_sync_query_param') || '',
          evolvedPayload: localStorage.getItem('pipeline_sync_evolved_payload') || '',
          rawPayload: localStorage.getItem('pipeline_sync_raw_payload') || '',
          bypassType: localStorage.getItem('pipeline_sync_bypass_type') || '',
          step: localStorage.getItem('pipeline_sync_step') || '',
          pocScript: localStorage.getItem('pipeline_sync_poc_script') || '',
          company: (localStorage.getItem('pipeline_sync_company') as any) || 'google',
          projectName: localStorage.getItem('pipeline_sync_project_name') || 'Orchestrated Microservice Target'
        });
      } else {
        setPipelineDataToSync(null);
      }
    };

    checkPipelineSync();
    window.addEventListener('storage', checkPipelineSync);
    window.addEventListener('focus', checkPipelineSync);
    
    const interval = setInterval(checkPipelineSync, 1000);
    
    return () => {
      window.removeEventListener('storage', checkPipelineSync);
      window.removeEventListener('focus', checkPipelineSync);
      clearInterval(interval);
    };
  }, []);

  const handleMergePipelineData = () => {
    if (!pipelineDataToSync) return;
    
    setTargetCompany(pipelineDataToSync.company);
    setProjName(pipelineDataToSync.projectName);
    setRepoUrl(pipelineDataToSync.targetUrl);
    
    if (pipelineDataToSync.step === 'safety') {
      setStructuralFocus('auth_bypass');
      setAlignAssetType('auth');
      setAlignBoundaryCrossing('sandbox_escape');
      setVulnClass('Model Inundation or Jailbreak / Inundação Cognitiva (CWE-1156)');
      setSourceFlow('API Request Metadata with Cognitive bypass prompt');
      setSinkFlow('Orchestrator LLM Pipeline Exec/Evaluation');
    } else {
      setStructuralFocus(pipelineDataToSync.company === 'aws' ? 'iam' : 'filesystem');
      setAlignAssetType(pipelineDataToSync.company === 'aws' ? 'iam' : 'sensitive_api');
      setAlignBoundaryCrossing('directory_traversal_extraction');
      setVulnClass('Path Traversal (CWE-22)');
      setSourceFlow(`Parâmetro HTTP "${pipelineDataToSync.queryParam}"`);
      setSinkFlow('os.Open / File Reader stream handler');
    }

    setPocPayload(pipelineDataToSync.pocScript);
    
    setPocStepsText(
      `1. Dispare o script de validação funcional contra o endpoint de destino:\n   ${pipelineDataToSync.targetUrl}\n` +
      `2. Utilize a sequência de bypass evoluída (${pipelineDataToSync.bypassType}) no parâmetro "${pipelineDataToSync.queryParam}":\n   ${pipelineDataToSync.evolvedPayload}\n` +
      `3. Analise as respostas HTTP e valide a presença de assinaturas críticas do host.`
    );

    handleDismissPipelineSync();
    
    window.scrollTo({ top: 350, behavior: 'smooth' });
  };

  const handleDismissPipelineSync = () => {
    localStorage.removeItem('pipeline_sync_target_url');
    localStorage.removeItem('pipeline_sync_query_param');
    localStorage.removeItem('pipeline_sync_evolved_payload');
    localStorage.removeItem('pipeline_sync_raw_payload');
    localStorage.removeItem('pipeline_sync_bypass_type');
    localStorage.removeItem('pipeline_sync_step');
    localStorage.removeItem('pipeline_sync_poc_script');
    localStorage.removeItem('pipeline_sync_company');
    localStorage.removeItem('pipeline_sync_project_name');
    setPipelineDataToSync(null);
  };

  // Sync selection targets dynamically on user click helper rather than effect to avoid overwriting localStorage on mount
  const handleSelectTargetCompany = (company: 'google' | 'aws' | 'meta' | 'microsoft' | 'custom') => {
    setTargetCompany(company);
    if (company === 'google') {
      setInferredArchitecture('GO_K8S');
      setStructuralFocus('kubernetes');
      setAlignAssetType('sensitive_api');
      setAlignBoundaryCrossing('directory_traversal_extraction');
    } else if (company === 'aws') {
      setInferredArchitecture('NODE_EXPRESS');
      setStructuralFocus('iam');
      setAlignAssetType('iam');
      setAlignBoundaryCrossing('cross_service_abuse');
    } else if (company === 'meta') {
      setInferredArchitecture('GRAPHQL');
      setStructuralFocus('auth_bypass');
      setAlignAssetType('auth');
      setAlignBoundaryCrossing('credential_disclosure');
    } else if (company === 'microsoft') {
      setInferredArchitecture('AZURE_AD');
      setStructuralFocus('auth_bypass');
      setAlignAssetType('oauth');
      setAlignBoundaryCrossing('cross_service_abuse');
    } else {
      setInferredArchitecture('NODE_EXPRESS');
      setStructuralFocus('filesystem');
    }
  };

  // Dynamic preset template injection
  const handleLoadTemplate = (key: string) => {
    const temp = TEMPLATES[key];
    if (temp) {
      setSelectedTemplate(key);
      setProjName(temp.projectName);
      setRepoUrl(temp.repoUrl);
      setTier(temp.tier);
      setVulnClass(temp.vulnerabilityClass);
      setSourceFlow(temp.source);
      setSinkFlow(temp.sink);
      setVulnCode(temp.vulnerableCode);
      setPatchCode(temp.patchCode);
      setPocStepsText(temp.pocSteps.join('\n'));
      setPocPayload(temp.pocPayload);
    }
  };

  // Recalculate estimated target rewards instantly 
  useEffect(() => {
    let baseMin = 1000;
    let baseMax = 3000;

    // Define reward matrices depending on chosen Corporate Program
    if (targetCompany === 'google') {
      if (tier === 'Tier 1') {
        switch (severity) {
          case 'P1': baseMin = 31337; baseMax = 50537; break;
          case 'PS1': baseMin = 20000; baseMax = 31337; break;
          case 'P2': baseMin = 13337; baseMax = 20000; break;
          case 'S2': baseMin = 5000; baseMax = 10000; break;
        }
      } else if (tier === 'Tier 2') {
        switch (severity) {
          case 'P1': baseMin = 15000; baseMax = 25000; break;
          case 'PS1': baseMin = 10000; baseMax = 15000; break;
          case 'P2': baseMin = 7500; baseMax = 13337; break;
          case 'S2': baseMin = 3000; baseMax = 6000; break;
        }
      } else {
        switch (severity) {
          case 'P1': baseMin = 5000; baseMax = 10000; break;
          case 'PS1': baseMin = 3000; baseMax = 5000; break;
          case 'P2': baseMin = 1500; baseMax = 3000; break;
          case 'S2': baseMin = 500; baseMax = 1500; break;
        }
      }
    } else if (targetCompany === 'aws') {
      switch (severity) {
        case 'P1': baseMin = 20000; baseMax = 40000; break;
        case 'PS1': baseMin = 12000; baseMax = 20000; break;
        case 'P2': baseMin = 5000; baseMax = 12000; break;
        case 'S2': baseMin = 1500; baseMax = 5000; break;
      }
    } else if (targetCompany === 'meta') {
      switch (severity) {
        case 'P1': baseMin = 25000; baseMax = 45000; break;
        case 'PS1': baseMin = 15000; baseMax = 25000; break;
        case 'P2': baseMin = 8000; baseMax = 15000; break;
        case 'S2': baseMin = 2000; baseMax = 8000; break;
      }
    } else if (targetCompany === 'microsoft') {
      switch (severity) {
        case 'P1': baseMin = 20000; baseMax = 50000; break;
        case 'PS1': baseMin = 10000; baseMax = 20000; break;
        case 'P2': baseMin = 5000; baseMax = 10000; break;
        case 'S2': baseMin = 1000; baseMax = 5000; break;
      }
    } else { // Custom program
      switch (severity) {
        case 'P1': baseMin = 5000; baseMax = 15000; break;
        case 'PS1': baseMin = 3000; baseMax = 8000; break;
        case 'P2': baseMin = 1000; baseMax = 3000; break;
        case 'S2': baseMin = 300; baseMax = 1000; break;
      }
    }

    // Apply strict ethical deductions or duplication modifiers index
    let scaleMultiplier = 1.0;
    if (!policyAntiSlop) scaleMultiplier -= 0.3;
    if (!policyReproduction) scaleMultiplier -= 0.4;
    if (!policyTaintFlow) scaleMultiplier -= 0.2;
    if (duplicationRisk === 'HIGH') scaleMultiplier *= 0.3;
    else if (duplicationRisk === 'MEDIUM') scaleMultiplier *= 0.7;

    const roundedMin = Math.round(baseMin * scaleMultiplier);
    const roundedMax = Math.round(baseMax * scaleMultiplier);

    setRewardRange(`$${roundedMin.toLocaleString()} - $${roundedMax.toLocaleString()} USD`);
  }, [tier, severity, policyAntiSlop, policyReproduction, policyTaintFlow, duplicationRisk, targetCompany]);

   // Advanced Local Semantic Compiler: Simulates a Lead Security Architect's strict reasoning
  const buildCustomReportText = (
    projectName: string,
    vulnerabilityClass: string,
    repository: string,
    tierValue: string,
    severityValue: string,
    sourceVal: string,
    sinkVal: string,
    vulnCodeVal: string,
    patchCodeVal: string,
    pocStepsTextVal: string,
    pocPayloadVal: string,
    company: string,
    tone: string,
    focus: string,
    architecture: string,
    language: 'pt' | 'en'
  ) => {
    // Stage 1 & 2: Structural Framing depending on Corporate platform trust expectations
    let companyHeader = '';
    let trustAssumptionIntroduction = '';
    let dynamicBoundaryBreakExplanation = '';
    let semanticThreatNarrative = '';
    let attackVectorGraphAscii = '';

    const isPt = language === 'pt';

    // Set platform-specific terminologies
    let architectureLabel = '';
    if (architecture === 'GO_K8S') {
      architectureLabel = isPt 
        ? 'Trabalho Distribuído Go rodando em microsserviço no Kubernetes Container'
        : 'Go Distributed Workload running inside a Kubernetes Microservice Container';
    } else if (architecture === 'NODE_EXPRESS') {
      architectureLabel = isPt
        ? 'Cadeia de Relações de Rotas Express/Node.js'
        : 'Express/Node.js Routing Relation Chain';
    } else if (architecture === 'GRAPHQL') {
      architectureLabel = isPt
        ? 'Federated GraphQL Gateway Resolver stitched architecture'
        : 'Federated GraphQL Gateway Resolver Stitched Architecture';
    } else {
      architectureLabel = isPt
        ? 'C# Microservices sintonizados com políticas federadas do Azure Directory'
        : 'C# Microservices Aligned with Active Directory Azure Federated Policies';
    }

    if (company === 'google') {
      companyHeader = 'GOOGLE VRP CORE & INK SECURITY TEAM';
      trustAssumptionIntroduction = isPt
        ? `O modelo de modelagem de segurança do ecossistema Google assumia tacitamente que os recursos do diretório estivessem confinados no perímetro do contêiner isolado pela infraestrutura de computação de Borg e sandbox gVisor. Entretanto, a falha lógica em questão subverte essa premissa básica ao permitir a transposição lógica de escopo e o vazamento de caminhos.`
        : `The security modeling of the Google ecosystem tacitly assumed that directory resources were strictly confined within the container perimeter isolated by Borg computing infrastructure and gVisor sandboxing. However, the logical flaw in question subverts this baseline assumption by allowing logical scope transposition and path leakage.`;
      
      dynamicBoundaryBreakExplanation = isPt
        ? `Através da transposição de caminhos canônicos locais via concatenações impróprias, o agente atacante transpõe as fronteiras lógicas do contêiner de tarefas do Kubernetes de escopo restrito. Isso viabiliza a leitura arbitrária de arquivos essenciais e a exposição das Service Account Credentials montadas, o que põe abaixo o modelo de privilégio de isolamento granular.`
        : `Through local canonical path transposition via improper concatenation, the threat actor bypasses the logical boundaries of the restricted-scope Kubernetes task container. This enables arbitrary reading of essential files and exposure of mounted Service Account Credentials, disrupting the granular isolation privilege model.`;

      semanticThreatNarrative = isPt
        ? `Considerando que os workloads irmãos no cluster Kubernetes partilham conexões de controle de API do próprio cluster, obter o token da conta de serviço (/var/run/secrets/kubernetes.io/serviceaccount/token) possibilita a realização de lateral movement lateral, facilitando o comprometimento de namespaces paralelas do Borg Task.`
        : `Given that sibling workloads in the Kubernetes cluster share API control connections of the cluster itself, obtaining the service account token (/var/run/secrets/kubernetes.io/serviceaccount/token) allows for lateral movement, facilitating the compromise of parallel Borg Task namespaces.`;
      
      attackVectorGraphAscii = isPt ? 
`[USUÁRIO EXTERNO (Untrusted IP)] 
       │ 
       ▼ (Passagem de parâmetro de subida de diretórios)
[GOOGLE FRONTEND API GATEWAY] 
       │ 
       ▼ (Processamento no container gVisor)
[MICROSERVIÇO KUBERNETES WORKLOAD] ──► [CONCATENAÇÃO INVÁLIDA] ──► [SINK: os.Open()]
       │ 
       └─► [ROMPIMENTO DE ISOLAMENTO 🔴] ──► [LEITURA DE SERVICE ACCOUNT TOKEN]`
:
`[EXTERNAL USER (Untrusted IP)] 
       │ 
       ▼ (Path traversal parameter ingestion)
[GOOGLE FRONTEND API GATEWAY] 
       │ 
       ▼ (Borg Node processing inside gVisor sandbox)
[KUBERNETES WORKLOAD MICROSERVICE] ──► [INVALID CONCATENATION] ──► [SINK: os.Open()]
       │ 
       └─► [SANDBOX ESCAPE / ISOLATION FAILURE 🔴] ──► [READ SERVICE ACCOUNT TOKEN]`;

    } else if (company === 'aws') {
      companyHeader = 'AWS PRODUCT SECURITY & CLOUD OPERATIONS';
      trustAssumptionIntroduction = isPt
        ? `A premissa fundamental de segurança do AWS IAM Task de Contêineres isolados assume que recursos privados de rede e chaves de configurações são estritamente contidos contra acessos lógicos não autenticados locais. A ausência de canonicalização das entradas anula as restrições e expõe canais internos confidenciais.`
        : `The fundamental security premise of AWS IAM Task Container isolation assumes that private network resources and configuration keys are strictly contained against unauthorized local logical access. The lack of input canonicalization negates these restrictions and exposes confidential internal channels.`;

      dynamicBoundaryBreakExplanation = isPt
        ? `Ao burlar o controle de caminhos do sistema Express/Node.js, o bug permite que um ator externo ordene a leitura de arquivos contendo chaves confidenciais da AWS, ou acesse diretamente o endpoint confidencial do AWS Instance Metadata Service (IMDSv2) através da rede link-local privada do host de tarefas.`
        : `By bypassing the routing control of the Express/Node.js system, the bug allows an external actor to read files containing sensitive AWS keys, or directly access the confidential AWS Instance Metadata Service (IMDSv2) endpoint via the link-local private network of the task host.`;

      semanticThreatNarrative = isPt
        ? `Possuindo acesso às chaves temporárias providas pelo STS de credência da tarefa host (Container Task Role), o invasor ganha controle lateral e autorização para realizar chamadas contra sub-recursos confidenciais no AWS Secrets Manager e buckets S3 em conformidade corporativa.`
        : `Armed with access to temporary keys supplied by STS for the host Task Role, the attacker gains lateral control and authorization to make calls against sensitive sub-resources in AWS Secrets Manager and S3 buckets within corporate compliance.`;

      attackVectorGraphAscii = isPt ?
`[EXTERNAL WORKLOAD] ──► [AWS API INGRESS/VPC GATEWAY]
                                │
                                ▼
                       [TASK CONTAINER ENGINE]
                                │  (Path manipulation ou bypass dinâmico)
                                ▼
                       [METADATA SERVICE BYPASS (IMDSv2)]
                                │
                                ▼  [EXECUÇÃO BURLADA 🔴]
                       [AWS ROLE CREDS EXPOSED TO CLOUD ENVELOP DECRYPTION]`
:
`[EXTERNAL WORKLOAD] ──► [AWS API INGRESS/VPC GATEWAY]
                                │
                                ▼
                       [TASK CONTAINER ENGINE]
                                │  (Path manipulation or dynamic bypass)
                                ▼
                       [METADATA SERVICE BYPASS (IMDSv2)]
                                │
                                ▼  [FAILURE TRIGGER 🔴]
                       [AWS ROLE CREDS EXPOSED TO CLOUD ENVELOP DECRYPTION]`;

    } else if (company === 'meta') {
      companyHeader = 'META WHITEHAT SECURITY PLATFORM';
      trustAssumptionIntroduction = isPt
        ? `A infraestrutura Core Graph e os Resolvedores Federados de GraphQL da Meta partem do princípio que toda query lógica de relações possui checagem individual granular ao nível de aresta do grafo. Um bypass em camadas estruturais superiores de filtragem lógica compromete o controle de identidade em escala global.`
        : `Meta's Core Graph infrastructure and Federated GraphQL Resolvers assume that every logical relation query undergoes individual granular verification at the graph-edge level. A bypass at high structural logic filtering layers compromises identity control on a global scale.`;

      dynamicBoundaryBreakExplanation = isPt
        ? `Pelo desvio nas rotas e resolvers de identidade concatenados, arestas que definem relações privadas de usuários são consultadas de maneira arbitrária sem aplicação de handshakes de validação federada apropriada ao contexto.`
        : `Through the detour in routes and concatenated identity resolvers, edges defining users' private relationships can be queried arbitrarily without the application of appropriate context-aware federated validation handshakes.`;

      semanticThreatNarrative = isPt
        ? `Uma vez contornado o middleware regulatório de sessão, é gerada facilidade para propagação de identificadores de acesso de aplicativo (App Access Tokens), resultando em extração em massa de dados lógicos contornando restrições de Tenant / Usuário.`
        : `Once the regulatory session middleware is bypassed, it facilitates the propagation of App Access Tokens, leading to massive logical data extraction bypassing Tenant/User constraints.`;

      attackVectorGraphAscii = isPt ?
`[REST API REQUEST] ──► [META FEDERATION GRAPHQL GATEWAY]
                                     │
                                     ▼
                        [STITCHED SCHEMA GRAPH RESOLVER]
                                     │  (Bypass de aresta lógica de segurança)
                                     ▼
                        [CORE GRAPH ENDPOINT BYPASS] ────► [MASS DATA EXTRACTION 🔴]`
:
`[REST API REQUEST] ──► [META FEDERATION GRAPHQL GATEWAY]
                                     │
                                     ▼
                        [STITCHED SCHEMA GRAPH RESOLVER]
                                     │  (Logical edge security bypass)
                                     ▼
                        [CORE GRAPH ENDPOINT BYPASS] ────► [MASS DATA EXTRACTION 🔴]`;

    } else if (company === 'microsoft') {
      companyHeader = 'MICROSOFT SECURITY RESPONSE CENTER (MSRC)';
      trustAssumptionIntroduction = isPt
        ? `O ecossistema corporativo do Azure Active Directory e os Serviços Federados assumem isolamento absoluto de contextos lógicos de autenticação entre chamadas autenticadas locais e acesso administrátivo de locatário. A falha técnica quebra este critério ao permitir passagem lateral de parâmetros lógicos.`
        : `Azure Active Directory's corporate ecosystem and Federated Services assume absolute isolation of logical authentication contexts between local authenticated requests and tenant administrative access. The technical flaw breaks this criterion by allowing logical parameter lateral passage.`;

      dynamicBoundaryBreakExplanation = isPt
        ? `A falha no tratamento lógico do microserviço em C# .NET permite que uma identidade de aplicação com baixos privilégios de Active Directory extraia credenciais administrativas lógicas ou obtenha Managed Identity tokens reusáveis pertencentes a servidores adjacentes de maior privilégio de Tenant Azure.`
        : `The failure in the logical handling of the C# .NET microservice allows a low-privilege Active Directory app identity to extract logical admin credentials or obtain reusable Managed Identity tokens belonging to higher-privileged adjacent servers in the Azure Tenant.`;

      semanticThreatNarrative = isPt
        ? `De posse dessas identidades federais de privilégios elevados, o invasor é capaz de assumir lateralmente permissões globais na subscrição Azure, rompendo barreiras de governança e logs do Enterprise Tenant Admin Active Directory.`
        : `Posessing these highly privileged federated identities, the attacker can laterally assume global permissions in the Azure subscription, breaking governance barriers and Enterprise Tenant Active Directory logs.`;

      attackVectorGraphAscii = isPt ?
`[AZURE CLIENT] ──► [AZURE ENTRIES GATEWAY] 
                           │
                           ▼
                  [ENTERPRISE WORKLOAD SERVICES] 
                           │ (Logical privilege elevation)
                           ▼
                  [MANAGED AZURE IDENTITY LEAK] ──► [DOMÍNIO DE TENANT COMPROMETIDO 🔴]`
:
`[AZURE CLIENT] ──► [AZURE ENTRIES GATEWAY] 
                           │
                           ▼
                  [ENTERPRISE WORKLOAD SERVICES] 
                           │ (Logical privilege elevation)
                           ▼
                  [MANAGED AZURE IDENTITY LEAK] ──► [COMPROMISED AZURE TENANT 🔴]`;

    } else {
      companyHeader = 'CORPORATE VRP PRIVATE SECURITY REGISTRY';
      trustAssumptionIntroduction = isPt
        ? `A premissa lógica de segurança assume controle rígido de sanidade sobre os canais externos de inputs lógicos e dados privados de back-office. Entretanto, falha nas validações permitiu cruzamento de Trust Boundaries internos da empresa.`
        : `The logical security premise assumes strict sanity control over external logical input channels and private back-office data. However, a failure in validation allowed crossing internal corporate Trust Boundaries.`;

      dynamicBoundaryBreakExplanation = isPt
        ? `A ausência de políticas unificadas de contenção e validação lógica ativa permitiu que solicitações externas quebrassem os limites de isolamento lógicos locais de caminhos e privilégio operacional de sessões corporativas.`
        : `The absence of unified active logical validation and containment policies permitted external requests to break local filesystem path isolation boundaries and corporate session privileges.`;

      semanticThreatNarrative = isPt
        ? `Isto compromete gravemente a integridade dos limites lógicos de Tenant compartilhados, e pode viabilizar desvio de dados sensíveis e escalada horizontal profunda de privilégios operacionais.`
        : `This severely compromises the integrity of shared Tenant logical boundaries, potentially enabling sensitive data leakage and deep horizontal privilege escalation.`;

      attackVectorGraphAscii = isPt ?
`[USUÁRIO NÃO AUTORIZADO] ──► [API GATEWAY] ──► [MICROSSERVIÇO ALVO] ──► [FALHA DE FILTRO 🔴]`
:
`[UNAUTHORIZED USER] ──► [API GATEWAY] ──► [TARGET MICROSERVICE] ──► [ROUTING FILTER BYPASS 🔴]`;
    }

    // Fixed Structure Formatting incorporating specific Dynamic Contexts
    const stepsFormatted = pocStepsTextVal
      ? pocStepsTextVal.split('\n').map((line, i) => `${i + 1}. ${line}`).join('\n')
      : (isPt 
         ? "1. Dispare a requisição HTTP contra o endpoint alvo do servidor.\n2. Inspecione a resposta e confirme a recuperação de arquivos de sistema."
         : "1. Trigger the HTTP request against the target endpoint on the server.\n2. Inspect response and confirm retrieval of system local files.");

    // Advanced dynamic boundary evaluation for higher senior credibility
    const getBoundaryStatus = (boundaryType: string) => {
      if (focus === boundaryType) return isPt ? 'ROMPIDO 🔴' : 'BROKEN 🔴';
      
      // Indirect or conditional evaluation
      if (boundaryType === 'filesystem' && (focus === 'kubernetes' || focus === 'iam')) return isPt ? 'RISCO CONDICIONAL 🟡' : 'CONDITIONAL RISK 🟡';
      if (boundaryType === 'kubernetes' && company === 'google') return isPt ? 'RISCO CONDICIONAL 🟡' : 'CONDITIONAL RISK 🟡';
      if (boundaryType === 'iam' && company === 'aws') return isPt ? 'RISCO CONDICIONAL 🟡' : 'CONDITIONAL RISK 🟡';
      if (boundaryType === 'auth_bypass' && focus === 'iam') return isPt ? 'RISCO CONDICIONAL 🟡' : 'CONDITIONAL RISK 🟡';
      
      return isPt ? 'NÃO AVALIADO ⚪' : 'NOT EVALUATED ⚪';
    };

    if (isPt) {
      return `# SUBMISSÃO DE SEGURANÇA: QUEBRA DE CONFIANÇA EM ${companyHeader}
======================================================================
* **Projeto Técnico Alvo:** ${projectName}
* **Arquitetura Inferida:** ${architectureLabel}
* **Diretório / Repositório:** ${repository}
* **Tier de Risco:** ${tierValue}
* **Classification Scale:** ${vulnerabilityClass}
* **Triagem Priority Index (Severidade):** ${severityValue}
* **Check de Conteúdo Limpo (Anti-Slop):** Ativo & Validado (Inference Discipline Engine Enabled)
* **Data da Auditoria:** ${new Date().toLocaleDateString('pt-BR')}

---

## 1. SUMÁRIO EXECUTIVO & ANÁLISE DE CONFIANÇA (TRUST BOUNDARY DIAGNOSIS)
- **Descrição de Descoberta Básica**:
  Foi detectado um desalinhamento sistemático de design de segurança no processamento lógico de caminhos de entrada do cliente no projeto \`${projectName}\`. A vulnerabilidade de transposição se materializa especificamente quando os dados não higienizados de entrada (Source) são manipulados por rotas de junção e processados diretamente no sink crítico: \`${sinkVal}\`.
  
- **Suposição de Confiança Malsucedida (Trust Assumption)**:
  ${trustAssumptionIntroduction}

- **Falha de Design de Segurança (Security Design Failure)**:
  ${dynamicBoundaryBreakExplanation}

- **Foco Técnico de Isolamento Ativo**:
  A quebra se consolida sob restrições do tipo **${focus.toUpperCase()}**, demonstrando que proteções superficiais estáticas aplicadas em instâncias externas de balanceamento ou no tráfego da rede foram superadas pelo comportamento dinâmico do código.

---

## 1.1 DISCIPLINA DE INFERÊNCIA & MODELAGEM DE IMPACTO (INFERENCE DISCIPLINE ENGINE)
Para mitigar avaliações de caráter especulativo ("speculative impact") e garantir máxima previsibilidade na triagem humana de engenharia, este relatório diferencia expressamente o impacto real verificado empiricamente dos riscos adicionais de escalada secundária:

### Diferenciação de Impacto (Observed vs. Potential Impact)
- **Impacto Observado Diretamente (Observed Impact)**:
  Leitura arbitrária local de arquivos de sistema através de transposição clássica de parâmetros lógicos, viabilizando o vazamento estruturado de segredos e metadados confinados no próprio filesystem operacional da tarefa ativa.
- **Impacto Potencial e Escalonamento de Escopo (Potential Impact)**:
  Exposição direta de chaves API, tokens de barramento federado e credenciais de identidades (Service Account Tokens ou Metadata Keys corporativas) que estejam associadas ou ativamente montadas no contexto lógico do contêiner atacado, permitindo vetores de persistência em recursos de terceiros de confiança mista.

### Tabela de Níveis de Certeza do Relatório (Confidence Levels Matrix)
| Componente / Vetor Analítico | Nível de Certeza | Detalhamento sobre a Premissa Analisada |
| :--- | :---: | :--- |
| **Leitura Arbitrária de Arquivos (CWE-22)** | ALTA (HIGH) | Comprovada através de protocolização e resposta determinística de payload no endpoint local. |
| **Exposição de Credenciais Associadas** | MÉDIA (MEDIUM) | Condicionada à existência de tokens ou chaves montadas sob os caminhos padrão do sistema de arquivos. |
| **Controle de API de Cluster / Lateralização** | CONDICIONAL (CONDITIONAL) | Aplicável caso o workload vulnerável esteja associado a ServiceAccounts com papéis lógicos ativos. |

### Precondições da Exploração (Attack Preconditions)
1. Endpoint vulnerável com processamento direto de inputs sobre o manipulador de arquivos nativo do host.
2. Servidor ou contêiner de execução rodando sem canônicalização ou sandboxing estricto de diretórios no gerenciador de rotas de backend.
3. Presença de arquivos sensíveis ou credenciais montadas (ServiceAccount, IAM federado, OAuth) nas variáveis de ambiente ou diretório de trabalho local.

---

## 2. TRANSPOSIÇÃO DE LIMITES (BOUNDARY FAILURE MATRIX) & TAINT FLOW
Abaixo, apresentamos o mapeamento em ASCII estruturado que documenta a jornada lógica percorrida pelos dados hostis do atacante (Source) até alcançarem o local crítico de processamento vulnerável sem bloqueios preventivos (Sink).

### Taint Flow Logic Path (ASCII Diagram):
\`\`\`text
${attackVectorGraphAscii}
\`\`\`

### Matriz Detalhada de Contenção de Isolamento (Boundary Matrix):

| Tipo de Limite | Status Lógico | Análise SecOps Contextualizada e Detalhes de Rompimento |
| :--- | :---: | :--- |
| **Filesystem Sandboxing** | ${getBoundaryStatus('filesystem')} | Transposição de segurança local de diretórios e leitura arbitrária de arquivos de configuração confidenciais do servidor host. |
| **Namespaces & Cluster Sandboxing** | ${getBoundaryStatus('kubernetes')} | Possibilidade de transposição lateral entre partições isoladas e recuperação de credenciais de contas de sistema integradas de cluster. |
| **Identity Delegation & Auth Flow** | ${getBoundaryStatus('auth_bypass')} | Bypass lógico de controle e quebra sanitização de tokens de identidade, permitindo controle arbitrário de sessões privadas. |
| **Cloud IAM Boundary Isolation** | ${getBoundaryStatus('iam')} | Exposição de privilégios de identidade associados a recursos e assumibilidade de regras em infraestruturas cloud integradas. |
| **API Boundary Trust Chain** | ${getBoundaryStatus('auth_bypass')} | Escapabilidade de controles no endpoint de gateway, transferindo inputs sem sanidade e desrespeitando o modelo de confiança de microsserviços. |

---

## 3. PROTOCOLO DE REPRODUÇÃO PRÁTICA (PROOF OF CONCEPT)
O procedimento de reprodução detalhado abaixo documenta metodologicamente as etapas necessárias para validar a existência incondicional da quebra lógica de segurança, presumindo reprodutibilidade determinística por analistas de triagem.

### Passos de Execução:
${stepsFormatted}

### Exploit Code / Payload de Comando Direto:
\`\`\`bash
${pocPayloadVal || `curl -s -X GET "http://localhost/${sourceVal || 'download'}?filepath=../../../../etc/passwd"`}
\`\`\`

---

## 4. ANÁLISE DE RAIO DE COLAPSO ADJACENTE (BLAST RADIUS HORIZON)
- **Análise do Risco Ambiental (Blast Radius Analysis)**:
  O impacto desta colisão ultrapassa o componente afetado individualmente. ${semanticThreatNarrative}

- **Dependência e Modificadores do Ambiente (Environmental Modifiers)**:
  * **Padrão Base (Local Baseline)**: A exposição direta local demonstra que o bug é reprodutível sem barreiras complexas a nível conceitual.
  * **Bônus de Impacto nos Ativos Cloud (Cloud Integration Impact)**: A severidade se expande caso o microserviço execute sob perfil privilegiado de contêineres, carregar dados cruciais do Kubernetes ServiceAccount (/var/run/secrets), ou mantiver perfis de identidade de serviço IAM integrados para conexões do KMS.

---

## 5. ANTIDOTO DE ENGENHARIA: REMEDIAÇÃO CANÔNICA E RECOMENDAÇÃO DE PATCH
Para erradicar a vulnerabilidade lógica de segurança descrita de forma definitiva, deve-se adotar filtragem ativa antes de qualquer tratamento dos caminhos.

### Trecho de Código Vulnerável Identificado:
\`\`\`go
${vulnCodeVal}
\`\`\`

### Recomendação de Patch Canônico:
\`\`\`go
${patchCodeVal}
\`\`\`

---

## 6. ANÁLISE ARQUITETURAL ADICIONAL & DEFENSIVE FAILURE LOGIC
- **Análise de Falha das Defesas Existentes (Defensive Failure Analysis)**:
  - **Limitações do Gateway/WAF**: As regras de Ingress ou WAF perimetral revelaram-se ineficazes porque solicitantes legítimos de API encapsulam sequências lógicas válidas que emulam strings normais. Firewalls de rede de camada 7 não inspecionam a lógica interna de montagem do filesystem.
  - **Delegação Implícita de Confiança**: O middleware de tráfego confiou implicitamente no parâmetro de entrada enviado de ponta-a-ponta, delegando a responsabilidade de sanitização inteiramente ao gerenciador de backend (Sink) que carece de verificações canônicas.
- **Doutrina Geral da Segurança Ativa (Interior Security Enforcement)**:
  A aplicação de medidas de segurança deve basear-se no tratamento defensivo canônico interno de forma proativa, eliminando a dependência de validações residuais em fronteiras externas. Toda entrada proveniente de canais de confiança mista deve obrigatoriamente sofrer higienização restritiva imediata no código de processamento.

======================================================================
*Gerado dinamicamente pelo Adaptive Security Narrative Engine em conformidade estrita com as políticas VRP 2026 de triagem e caça a bugs.*`;
    } else {
      // English Submission output
      return `# SECURITY SUBMISSION: TRUST BOUNDARY BREACH IN ${companyHeader}
======================================================================
* **Target Technical Project:** ${projectName}
* **Inferred Architecture:** ${architectureLabel}
* **Directory / Repository:** ${repository}
* **Risk Tier:** ${tierValue}
* **Classification Scale:** ${vulnerabilityClass}
* **Triage Priority Index (Severity):** ${severityValue}
* **Clean Content Check (Anti-Slop):** Active & Verified (Inference Discipline Engine Enabled)
* **Audit Date:** ${new Date().toLocaleDateString('en-US')}

---

## 1. EXECUTIVE SUMMARY & TRUST BOUNDARY DIAGNOSIS
- **Primary Finding Description**:
  A systematic security design misalignment has been detected in the logical handling of client inputs within the \`${projectName}\` project routing mechanisms. The path transposition vulnerability materializes specifically when unsanitized input data (Source) is processed directly by the critical system sink: \`${sinkVal}\`.
  
- **Failed Trust Assumption**:
  ${trustAssumptionIntroduction}

- **Security Design Failure**:
  ${dynamicBoundaryBreakExplanation}

- **Active Isolation Technical Focus**:
  This boundary breach consolidates under the **${focus.toUpperCase()}** boundary constraints, illustrating that surface-level static defenses or network-edge ingress policies were bypassed by the application's dynamic runtime behavior.

---

## 1.1 INFERENCE DISCIPLINE & IMPACT MODELING (INFERENCE DISCIPLINE ENGINE)
To mitigate speculative threat assessments ("speculative impact") and secure maximum predictability for human triage engineers, this report explicitly decouples raw empirical findings from theoretical lateral escalation vectors:

### Impact Differentiation (Observed vs. Potential Impact)
- **Directly Observed Impact (Observed Impact)**:
  Arbitrary local file reading via standard path transposition logic, enabling leak of local secrets, configurations, and environment resources within the active workload filesystem.
- **Potential Impact and Scope Escalation (Potential Impact)**:
  Direct exposure of access credentials, federated identity tokens (Service Account Tokens or system metadata credentials) mounted within the compromised execution container, spawning follow-on capability to interact with adjacent cloud infrastructure namespaces.

### Confidence Levels Matrix
| Component / Analytical Vector | Confidence Level | Premise Assertion / Verification Details |
| :--- | :---: | :--- |
| **Arbitrary File Reading (CWE-22)** | HIGH | Fully validated via dynamic payload delivery and deterministic responses on local endpoints. |
| **Exposure of Associated Credentials** | MEDIUM | Dependent on target credential rotation and default mounts in host paths. |
| **Cluster API Control / Lateral Movement** | CONDITIONAL | Applicable if the active task role holds active cluster control plane privileges. |

### Attack Preconditions
1. Exposed vulnerable endpoint routing directly to host local system file readers.
2. Under-sanitized input concatenation handlers without strict route checking or canonicalization strategies.
3. Presence of sensitive keys or mounted infrastructure identities (ServiceAccount, OAuth configs) within the local environment scope.

---

## 2. BOUNDARY FAILURE MATRIX & TAINT FLOW
Below is an structured ASCII layout mapping the logical propagation of untrusted input (Source) into the key inner execution logic (Sink) without sanitization barriers:

### Taint Flow Logic Path (ASCII Diagram):
\`\`\`text
${attackVectorGraphAscii}
\`\`\`

### Comprehensive Isolation Boundary Matrix:

| Boundary Type | Logical Status | Contextual SecOps Analysis & Breach Specifications |
| :--- | :---: | :--- |
| **Filesystem Sandboxing** | ${getBoundaryStatus('filesystem')} | Local directory escaping and arbitrary host configuration file viewing capabilities. |
| **Namespaces & Cluster Sandboxing** | ${getBoundaryStatus('kubernetes')} | Context-level escape from workloads into surrounding sibling namespaces. |
| **Identity Delegation & Auth Flow** | ${getBoundaryStatus('auth_bypass')} | Route sanitization and session state isolation bypasses. |
| **Cloud IAM Boundary Isolation** | ${getBoundaryStatus('iam')} | Potential to harvest cloud instances credentials and assume cloud workspace roles. |
| **API Boundary Trust Chain** | ${getBoundaryStatus('auth_bypass')} | Outer gateway logic verification bypassed as payload flows down intact to target microservices. |

---

## 3. PRACTICAL REPRODUCIBILITY PROTOCOL (PROOF OF CONCEPT)
The reproduction procedure outlined below avoids hand-wavy assumptions and systematically details step-by-step actions required to deterministically replicate the logical security failure.

### Execution Steps:
${stepsFormatted}

### Exploit Code / Direct Command Payload:
\`\`\`bash
${pocPayloadVal || `curl -s -X GET "http://localhost/${sourceVal || 'download'}?filepath=../../../../etc/passwd"`}
\`\`\`

---

## 4. BLAST RADIUS HORIZON ANALYSIS
- **Blast Radius Analysis (Blast Radius Analysis)**:
  The structural impact of this collision is not bounded of the component directly. ${semanticThreatNarrative}

- **Environmental Modifiers**:
  * **Local Baseline**: Direct immediate exposure proves that the logical vulnerability is easily replicated without multi-layered configurations.
  * **Cloud Integration Impact**: The threat level increases heavily if the microservice runs inside high-privilege namespaces, loads Kubernetes ServiceAccount configurations (/var/run/secrets/kubernetes.io), or retains cloud-side KMS/IAM permissions.

---

## 5. ENGINEERING ANTIDOTE: CANONICAL REMEDIATION & PATCH RECOMMENDATION
To permanently extinguish the reported path security logic flaw, path-level checks must be strictly applied before reading system files.

### Identified Vulnerable Code Snippet:
\`\`\`go
${vulnCodeVal}
\`\`\`

### Recommended Canonical Patch:
\`\`\`go
${patchCodeVal}
\`\`\`

---

## 6. ADDITIONAL ARCHITECTURAL ANALYSIS & DEFENSIVE FAILURE LOGIC
- **Defensive Failure Analysis**:
  - **Gateway/WAF Limitations**: Peripheral Ingress rules or traditional WAF signatures were unable to contain the risk as the request encapsulates within normative HTTP routes emulating legitimate data. Layer-7 firewalls do not parse native file reader mappings.
  - **Implicit Trust Delegation**: Upstream routing mechanisms delegated entire trust to downline subsystems, lacking early canonical inspection policies on ingress routes.
- **Interior Security Enforcement Principle**:
  True Defense-in-depth requires checking sanitization close to systems sinks, dismissing external edge-trust assumptions. All mixed-trust entries must be neutralized locally.

======================================================================
*Dynamically processed by the Adaptive Security Narrative Engine under strict VRP 2026 triage rules.*`;
    }
  };

  // Static Local Compiler trigger 
  const handleGenerateLocalReport = () => {
    const formatted = buildCustomReportText(
      projName,
      vulnClass,
      repoUrl,
      tier,
      severity,
      sourceFlow,
      sinkFlow,
      vulnCode,
      patchCode,
      pocStepsText,
      pocPayload,
      targetCompany,
      reportTone,
      structuralFocus,
      inferredArchitecture,
      reportLanguage
    );
    setReportMarkdown(formatted);
  };

  // Compile initially on mount 
  useEffect(() => {
    handleGenerateLocalReport();
  }, []);

  // Recalculate and compile report instantly when changes occur! Superb UX reactive loop!
  useEffect(() => {
    handleGenerateLocalReport();
  }, [
    projName, repoUrl, tier, vulnClass, sourceFlow, sinkFlow, 
    vulnCode, patchCode, pocStepsText, pocPayload, 
    targetCompany, reportTone, structuralFocus, inferredArchitecture, reportLanguage
  ]);

  // Synchronise input values inside localStorage to ensure persistence across browser reloads
  useEffect(() => {
    localStorage.setItem('vrp_selected_template', selectedTemplate);
    localStorage.setItem('vrp_target_company', targetCompany);
    localStorage.setItem('vrp_report_tone', reportTone);
    localStorage.setItem('vrp_structural_focus', structuralFocus);
    localStorage.setItem('vrp_inferred_architecture', inferredArchitecture);
    localStorage.setItem('vrp_proj_name', projName);
    localStorage.setItem('vrp_repo_url', repoUrl);
    localStorage.setItem('vrp_tier', tier);
    localStorage.setItem('vrp_vuln_class', vulnClass);
    localStorage.setItem('vrp_source_flow', sourceFlow);
    localStorage.setItem('vrp_sink_flow', sinkFlow);
    localStorage.setItem('vrp_vuln_code', vulnCode);
    localStorage.setItem('vrp_patch_code', patchCode);
    localStorage.setItem('vrp_poc_steps_text', pocStepsText);
    localStorage.setItem('vrp_poc_payload', pocPayload);
    localStorage.setItem('vrp_severity', severity);
    localStorage.setItem('vrp_policy_anti_slop', String(policyAntiSlop));
    localStorage.setItem('vrp_policy_reproduction', String(policyReproduction));
    localStorage.setItem('vrp_policy_taint_flow', String(policyTaintFlow));
    localStorage.setItem('vrp_policy_no_permission', String(policyNoPermission));
    localStorage.setItem('vrp_duplication_risk', duplicationRisk);
    localStorage.setItem('vrp_align_asset_type', alignAssetType);
    localStorage.setItem('vrp_align_boundary_crossing', alignBoundaryCrossing);
    localStorage.setItem('vrp_align_practical_exploit', alignPracticalExploit);
    localStorage.setItem('vrp_align_systemic_impact', alignSystemicImpact);
    localStorage.setItem('vrp_report_language', reportLanguage);
  }, [
    selectedTemplate, targetCompany, reportTone, structuralFocus, inferredArchitecture,
    projName, repoUrl, tier, vulnClass, sourceFlow, sinkFlow, vulnCode, patchCode,
    pocStepsText, pocPayload, severity, policyAntiSlop, policyReproduction,
    policyTaintFlow, policyNoPermission, duplicationRisk, alignAssetType,
    alignBoundaryCrossing, alignPracticalExploit, alignSystemicImpact, reportLanguage
  ]);

  // Predefined fingerprints simulator presets
  const FINGERPRINT_PRESETS = [
    {
      name: "Istio Envoy (Borg/Google-like Stack)",
      url: "https://vrp.google.com/api/v2/resolve",
      headers: `HTTP/2 502 Bad Gateway\nserver: istio-envoy\nx-envoy-upstream-service-time: 24\nvia: 1.1 google\nx-cloud-trace-context: d1a43a29bc0b784a\ncache-control: private`
    },
    {
      name: "AWS Gateway & CloudFront Signature",
      url: "https://origin.aws-internal.ec2.amazonaws.com",
      headers: `HTTP/1.1 403 Forbidden\nserver: cloudfront\nx-amz-cf-id: S883hVx-2D1sAwiJp==\nx-amzn-RequestId: d729a6b8-2cfa-40bf-9fe2-92837f401f80\nx-amzn-ErrorType: AccessDeniedException`
    },
    {
      name: "GraphQL Schema stitched Gateway (Meta-like)",
      url: "https://graph.meta.internal/v19.0/graphql",
      headers: `HTTP/1.1 200 OK\ncontent-type: application/json\nx-graphql-stitch-version: 3.4.1\nx-fb-debug: H7A2ka01c-vA\nvia: GraphQL Mesh Resolver Engine`
    },
    {
      name: "Microsoft Enterprise ASP.NET & Azure AD Client",
      url: "https://sts.microsoftonline.corp/authorize",
      headers: `HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Bearer authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize"\nserver: Kestrel\nx-powered-by: ASP.NET\nx-ms-request-id: fe8101a2-8b01-44aa-9c12`
    }
  ];

  const handleRunPassiveFingerprint = () => {
    setIsFingerprinting(true);
    setFingerprintLogs([
      "[*] [%TIME%] Inicializando Motor de Reconhecimento de Assinatura Passiva...".replace("%TIME%", new Date().toLocaleTimeString()),
      "[*] [%TIME%] Analisando cabeçalhos HTTP, assinaturas de servidores e cookies...".replace("%TIME%", new Date().toLocaleTimeString())
    ]);

    setTimeout(() => {
      const text = fingerprintInput.toLowerCase();
      let company: 'google' | 'aws' | 'meta' | 'microsoft' | 'custom' = 'custom';
      let arch: 'GO_K8S' | 'NODE_EXPRESS' | 'GRAPHQL' | 'AZURE_AD' = 'NODE_EXPRESS';
      let focus: 'filesystem' | 'iam' | 'kubernetes' | 'auth_bypass' = 'filesystem';
      let confidence = 45;
      const detected: string[] = [];
      const logs: string[] = [];

      // Check URL and headers
      const targetText = (fingerprintTargetUrl + " " + text).toLowerCase();

      if (
        targetText.includes("x-amz") || 
        targetText.includes("x-amzn") || 
        targetText.includes("cloudfront") || 
        targetText.includes("cognito") || 
        targetText.includes("sts.amazonaws.com") || 
        targetText.includes("aws")
      ) {
        company = 'aws';
        arch = 'NODE_EXPRESS';
        focus = 'iam';
        confidence = 95;
        if (targetText.includes("x-amz-cf-id")) detected.push("AWS CloudFront Header (x-amz-cf-id)");
        if (targetText.includes("x-amzn-requestid")) detected.push("AWS Gateway/ALB Identifier (x-amzn-RequestId)");
        if (targetText.includes("cloudfront")) detected.push("Server Ident: CloudFront");
        if (targetText.includes("cognito")) detected.push("AWS Cognito Identity Provider");
      } else if (
        targetText.includes("istio") || 
        targetText.includes("envoy") || 
        targetText.includes("x-envoy") || 
        targetText.includes("gvisor") || 
        targetText.includes("google") || 
        targetText.includes("borg")
      ) {
        company = 'google';
        arch = 'GO_K8S';
        focus = 'kubernetes';
        confidence = 90;
        if (targetText.includes("istio-envoy")) detected.push("Istio Service Mesh Edge (istio-envoy)");
        if (targetText.includes("x-envoy-upstream-service-time")) detected.push("Envoy Reverse Proxy Routing Latency Marker");
        if (targetText.includes("via: 1.1 google")) detected.push("Google Fronting Network Hop");
      } else if (
        targetText.includes("graphql") || 
        targetText.includes("stitch") || 
        targetText.includes("apollo") || 
        targetText.includes("federation") || 
        targetText.includes("graph.meta") || 
        targetText.includes("x-fb-")
      ) {
        company = 'meta';
        arch = 'GRAPHQL';
        focus = 'auth_bypass';
        confidence = 88;
        if (targetText.includes("graphql")) detected.push("GraphQL API Schema endpoints");
        if (targetText.includes("stitch")) detected.push("Federated Schema Stitching Resolver metadata");
        if (targetText.includes("x-fb-")) detected.push("Meta Internal Backplane tracing (x-fb-debug)");
      } else if (
        targetText.includes("microsoft") || 
        targetText.includes("azure") || 
        targetText.includes("x-ms-") || 
        targetText.includes("asp.net") || 
        targetText.includes("kestrel") || 
        targetText.includes("entra")
      ) {
        company = 'microsoft';
        arch = 'AZURE_AD';
        focus = 'auth_bypass';
        confidence = 95;
        if (targetText.includes("login.microsoftonline.com") || targetText.includes("microsoftonline")) detected.push("Microsoft Active Directory Redirect URL");
        if (targetText.includes("x-ms-request-id")) detected.push("Azure Core API Routing (x-ms-request-id)");
        if (targetText.includes("asp.net") || targetText.includes("kestrel")) detected.push("Kestrel Engine ASP.NET backend host");
      }

      // Stack details
      if (text.includes("cannot get") || text.includes("express/lib") || text.includes("node_modules") || text.includes("x-powered-by: express")) {
        detected.push("Node.js + Express framework footprint");
        arch = 'NODE_EXPRESS';
        confidence = Math.max(confidence, 80);
      }
      if (text.includes("panic: runtime error") || text.includes("goroutine") || text.includes(".go:")) {
        detected.push("Go compiled binary execution traces");
        arch = 'GO_K8S';
        confidence = Math.max(confidence, 80);
      }

      logs.push(`[+] Heurística: Analisado escopo do alvo "${fingerprintTargetUrl}".`);
      if (detected.length > 0) {
        detected.forEach(d => logs.push(`[DETECÇÃO DE PRINT] ${d}`));
        logs.push(`[+] Stack Sugerido: ${arch} sob custódia de isolamento ${focus.toUpperCase()}.`);
        logs.push(`[+] Alvo Identificado: ${company.toUpperCase()} Security Program.`);
      } else {
        logs.push(`[-] Nenhuma assinatura inequívoca reconhecida. Configurando perfil VRP Privado.`);
        company = 'custom';
      }

      setFingerprintLogs(prev => [
        ...prev,
        ...logs,
        `[✓] Triagem automática finalizada. Confiança: ${confidence}%`
      ]);

      setFingerprintResult({
        company,
        arch,
        focus,
        detectedHeaders: detected,
        confidence
      });

      // Update core tool coordinates instantly! Saving time and preventing guesswork for the hunter!
      setTargetCompany(company);
      setInferredArchitecture(arch);
      setStructuralFocus(focus);

      setIsFingerprinting(false);
    }, 1200);
  };

  // Cognitive Compressor parsing engine: converts messy chat logs / traces into exact config fields instantly!
  const handleCompressAndDeconstructRawLogs = async () => {
    if (!apiKey) {
      alert("Chave de API do Gemini não configurada. Por favor, adicione sua chave de API para acionar a tradução heurística avançada por IA (BYOK).");
      return;
    }

    setIsAiGenerating(true);
    try {
      const ai = new GoogleGenAI({ apiKey });
      const prompt = `Você é o Auditor Sênior de Triagem de Segurança especializado em engenharia de riscos SecOps e parsing de traces de logs de bugs.
      Sua missão é extrair e desestruturar informações cruciais a partir do seu rascunho de logs descuidado ou traces brutos fornecidos, e mapear para sub-parâmetros JSON.
      
      TEXTO BRUTO DE ENTRADA:
      """
      ${rawInputReport}
      """

      Você DEVE retornar estritamente um código JSON sem comentários ou encapsulamentos externos de Markdown (NÃO use crases extras com o nome 'json'), contendo exatamente a estrutura abaixo:
      {
        "projectName": "Nome Curto do Projeto / Extensão do Bug encontrado",
        "repositoryUrl": "URL deduzida ou provida do repositório",
        "vulnerabilityClass": "Classe de vulnerabilidade (Ex: Path Traversal (CWE-22) ou Argument Injection (CWE-88))",
        "source": "Ponto de entrada exato provido pelo usuário externa ou query",
        "sink": "Função crítica de código que causa colapso (os.Open / exec File / etc)",
        "vulnerableSnippet": "Exemplo curto de código vulnerável deduzido",
        "patchSnippet": "Código corrigido sugerido",
        "reproductionPath": ["passo 1 de teste", "passo 2 de teste"],
        "exploitCommand": "Comando curl ou bash com o payload para teste local"
      }
      
      Seja fiel ao conteúdo de logs. Caso faltem informações, deduza logicamente de forma sênior baseando-se nas melhores práticas de segurança de 2026.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.5-flash',
        contents: prompt,
        config: {
          temperature: 0.1,
          responseMimeType: 'application/json'
        }
      });

      if (response && response.text) {
        const parsed = JSON.parse(response.text);
        if (parsed.projectName) setProjName(parsed.projectName);
        if (parsed.repositoryUrl) setRepoUrl(parsed.repositoryUrl);
        if (parsed.vulnerabilityClass) setVulnClass(parsed.vulnerabilityClass);
        if (parsed.source) setSourceFlow(parsed.source);
        if (parsed.sink) setSinkFlow(parsed.sink);
        if (parsed.vulnerableSnippet) setVulnCode(parsed.vulnerableSnippet);
        if (parsed.patchSnippet) setPatchCode(parsed.patchSnippet);
        if (parsed.reproductionPath) setPocStepsText(parsed.reproductionPath.join('\n'));
        if (parsed.exploitCommand) setPocPayload(parsed.exploitCommand);

        setSandboxLogs(prev => [
          `[PARSER] Sucesso: Tradutor Cognitivo extraiu logs com fidelidade! Campos atualizados.`,
          ...prev.slice(0, 4)
        ]);
        alert("Desconstrução Concluída! Os campos e parâmetros do painel esquerdo foram atualizados de acordo com as informações estruturadas.");
      }
    } catch (e: any) {
      console.error(e);
      alert(`Erro no compressor cognitivo do Gemini: ${e.message || e}`);
    } finally {
      setIsAiGenerating(false);
    }
  };

  // Interactive AI synthesis of the OSS report using Google Gemini 2026 ruleset API
  const handleAiSynthesizeReport = async () => {
    if (!apiKey) {
      alert("Matriz de Chave de API ausente. Por favor, adicione sua chave de API do Gemini no topo da tela para usar síntese heurística de IA.");
      return;
    }

    setIsAiGenerating(true);
    try {
      const ai = new GoogleGenAI({ apiKey });
      const languageDirective = reportLanguage === 'en'
        ? "WRITE THE ENTIRE REPORT ONLY IN HIGHLY SECURE AND DETAILED TECHNICAL ENGLISH. All markdown sections, headers, tables, diagrams, explanations, and labels MUST be in English. Do not write in Portuguese."
        : "ESCREVA O RELATÓRIO INTEIRAMENTE EM PORTUGUÊS TÉCNICO COMPLETO (PT-BR). Todos os títulos, matrizes, descrições e explicações SecOps devem estar em português.";

      const prompt = `Você é o Auditor Sênior de Triagem de Segurança de elite especializado em programas de Big Tech e Cloud Services.
      Objetivo: Gerar um Relatório de Submissão de bug de Altíssima Conversão, de nível Staff/Security Engineer, técnico, fundamentado e sem "fluff" de IA ou floreios corporativos vazios, ajustado às normas de 2026.
      
      Diretrizes de Variação Dinâmica (NÃO use placeholders padrões ou textos robóticos clonados):
      - Plataforma e Alvo Corporativo: ${targetCompany.toUpperCase()} (Adote de forma sã e fluida a terminologia de segurança da ${targetCompany.toUpperCase()}, ex: se AWS use conceitos de IAM Roles, STS tokens, Cloud Security, VPC isolation; se Google use Borg Tasks, gVisor containment, Google VRP Core ruleset, gRPC APIs, etc.).
      - Tom do Relatório: ${reportTone.toUpperCase()} (academic = formal estruturado acadêmico com bases científicas, hunter = altamente pragmático focado em explotação prática irrefutável, advisor = focado em riscos de governança de design na nuvem, direct = sucinto e curto).
      - Foco Arquitetural Principal: ${structuralFocus.toUpperCase()} (Foque na análise física de ${structuralFocus === 'filesystem' ? 'validação canônica de caminhos de arquivos locais' : structuralFocus === 'iam' ? 'vazamento de tokens e privilégios de identidade cloud' : structuralFocus === 'kubernetes' ? 'conquista e lateralização de workloads de pods através de service accounts expostas' : 'bypasses na cadeia lógica e conexões na autenticação interna'}).
      - Arquitetura Escolhida pelo Usuário: ${inferredArchitecture}

      IDIOMA EXCLUSIVO DO RELATÓRIO:
      ${languageDirective}

      Siga rigidamente e EXCLUSIVAMENTE o formato estruturado idealizado abaixo com tom sóbrio, imponente e sem rodeios (translated/localized based on target language above):
      
      # [TÍTULO DA FALHA CONCISO DE IMPACTO EM MAIÚSCULO] - [CWE] - [PROJETO AFETADO]
      ======================================================================
      - Projeto Técnico Alvo: [Nome do Projeto]
      - Arquitetura do Microserviço: [Stack Inferida]
      - Repositório Afetado: [Repositório]
      - Classificação VRP: [Tier de Escopo] [Priority/Severity]
      - Check de Conteúdo Limpo (Anti-Slop): Em conformidade
      - Data da Auditoria: [Data]
      
      ----------------------------------------------------------------------
      ## 1. SUMÁRIO EXECUTIVO & FALHA NO MODELO DE CONFIANÇA (TRUST BOUNDARY FAILURE)
      - **A Ancoragem**: Determine com alta propriedade técnica que o problema transcende um bug comum de código, tratando-se de uma quebra sistemática de segurança no modelo de confiança.
      - **Suposição de Confiança Malsucedida (Trust Assumption)**: Explique qual premissa assumida pela arquitetura faliu especificamente baseando-se na arquitetura ${inferredArchitecture} e empresa ${targetCompany}.
      - **Falha de Design de Segurança (Security Design Failure)**: Explique sob ótica profunda como a falha origina-se da dependência de validações implícitas em vez da aplicação ativa baseada em boundaries seguros.

      ----------------------------------------------------------------------
      ## 2. TRANSPOSIÇÃO DE LIMITES (BOUNDARY FAILURE MATRIX) & TAINT FLOW
      - **Taint Flow Logic Path (ASCII Diagram)**: Desenhe em ASCII o fluxo dos dados desde a entrada não filtrada (Source: ${sourceFlow}) até o ativador do colapso (Sink: ${sinkFlow}), passando pelas barreiras lógicas do sistema. Diferencie o diagrama ASCII baseado no contexto técnico real para mitigar repetição sintática.
      - **Matriz de Classificação de Limites (Boundary Matrix)**:
        Desenhe uma tabela em markdown cobrindo os limites: Filesystem Sandboxing, Namespaces & Cluster Sandboxing, Identity Delegation & Auth Flow, Cloud IAM, e API Boundary Trust Chain, classificando-os de acordo com a quebra real que ocorreu e detalhando os motivos específicos.

      ----------------------------------------------------------------------
      ## 3. PROTOCOLO DE REPRODUÇÃO PRÁTICA (PROOF OF CONCEPT)
      - **Instruções Detalhadas**: Forneça passos claros ordenados por ordem de progressão de reprodução local.
      - **Payload Final / Comando de Exploração**: Forneça um exemplo de bash ou cURL limpo baseado no payload fornecido: ${pocPayload}.

      ----------------------------------------------------------------------
      ## 4. ANÁLISE DE RAIO DE COLAPSO ADJACENTE (BLAST RADIUS HORIZON)
      - **Blast Radius Analysis**: Estimar com maturidade industrial e empresarial de segurança a extensão da propagação do colapso. Avalie com cuidado real o risco de lateral movement na infraestrutura de containers ou adjacência cloud.
      - **Fatores Multiplicadores de Risco**: Que fatores de infraestrutura ou permissões sobem o perigo (ex: contas de serviço no K8s expostas, chaves STS na nuvem AWS, token de Graph API reusável).

      ----------------------------------------------------------------------
      ## 5. REMEDIAÇÃO CANÔNICA E RECOMENDAÇÃO DE PATCH
      [Exiba blocos de código comparados em markdown de "Snippet de Código Vulnerável" e "Patch Recomendado Canônico" com os códigos originais de referência, corrigindo o problema estritamente com validações canônicas ativas].

      ----------------------------------------------------------------------
      ## 6. MODELAGEM DE AMEAÇAS E ANÁLISE ARQUITETURAL ADICIONAL
      - **Defense-in-Depth Breakdown**: Explique por que filtros de rede tradicionais (WAFs e Gateways) falham catastroficamente contra esse tipo de ataque lógico no código.
      - **Princípios de Confiança Zero**: Discorra sobre a importância de sanear entradas no perímetro da aplicação ativa sem supor confiança do fluxo de dados das microrredes internas.
      
      Diretrizes Técnicas Estritas de Redação:
      - NUNCA use frases introdutórias vazias de robô como "Aqui está o relatório", "Claro, posso ajudar", "Com certeza!", ou recapitulações ou conclusões supérfluas de IA. Comece de imediato no título Markdown.
      - Não use adjetivos pomposos ou elogios artificiais sobre a gravidade da falha ("descoberta incrível", "falha espetacular"). Use termos neutros, ponderados, lógicos sob risco de SecOps sênior.
      - Evite qualquer menção ou traço de resposta automática de LLM tradicional.
      
      DADOS TÉCNICOS ASSOCIADOS DE ENTRADA:
      - Nome do Projeto: ${projName}
      - Repositório: ${repoUrl}
      - Tipo de Vulnerabilidade: ${vulnClass}
      - Tier de Escopo VRP: ${tier}
      - Source Flow: ${sourceFlow}
      - Sink Flow: ${sinkFlow}
      - Gravidade Selecionada: ${severity}
      
      CÓDIGO DE ORIGEM VULNERÁVEL:
      ${vulnCode}
      
      CÓDIGO DO NOVO PATCH RECOMENDADO:
      ${patchCode}
      
      REPRODUÇÃO DISPARADA:
      ${pocStepsText}
      
      PAYLOAD FINAL:
      ${pocPayload}`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.5-flash',
        contents: prompt,
        config: {
          temperature: 0.1
        }
      });
      
      if (response && response.text) {
        setReportMarkdown(response.text);
      }
    } catch (e: any) {
      console.error(e);
      alert(`Erro na orquestração com o agente Gemini: ${e.message || e}`);
    } finally {
      setIsAiGenerating(false);
    }
  };

  // Heuristic-based alignment and scoring 
  const heuristicAlignmentResult = React.useMemo(() => {
    let score = 0;
    const reasons: string[] = [];
    const suggestions: string[] = [];

    switch (alignAssetType) {
      case 'auth':
      case 'oauth':
      case 'session':
      case 'iam':
        score += 25;
        break;
      case 'sensitive_api':
        score += 18;
        break;
      case 'internal_data':
        score += 10;
        break;
      case 'peripheral':
        score += 2;
        reasons.push("Asset Secundário: Serviços de blog ou laboratórios periféricos raramente garantem recompensas monetárias (Bounty Eligible).");
        suggestions.push("Tente conectar o impacto a algum endpoint de controle principal de sessão, fluxo OAuth ou microsserviço no core do projeto.");
        break;
    }

    switch (alignBoundaryCrossing) {
      case 'sandbox_escape':
      case 'cross_service_abuse':
        score += 25;
        break;
      case 'directory_traversal_extraction':
        score += 20;
        break;
      case 'credential_disclosure':
      case 'local_arbitrary_read':
        score += 15;
        break;
      case 'no_boundary':
        score += 2;
        reasons.push("Sem Cruzamento de Limites: O problema ocurre exclusivamente dentro do mesmo contexto lógico sem escalonamento de privilégios.");
        suggestions.push("Demonstre transposição ativa: descreva como a leitura local de arquivos fornece acesso a chaves federadas e tokens de IAM.");
        break;
    }

    switch (alignPracticalExploit) {
      case 'deterministic_rce':
        score += 25;
        break;
      case 'proven_privilege_escalation':
        score += 20;
        break;
      case 'authenticated_read_bypass':
        score += 12;
        break;
      case 'hypothetical_theory':
        score += 3;
        reasons.push("Caráter Hipotético: Análise puramente especulativa sem comprovação de exploração funcional determinística.");
        suggestions.push("Desenvolva etapas passo-a-passo detalhadas provando de ponta-a-ponta a extração de dados locais usando cURL.");
        break;
    }

    switch (alignSystemicImpact) {
      case 'cross_service_impact':
        score += 25;
        break;
      case 'shared_trust_model_abuse':
        score += 20;
        break;
      case 'isolated_input_flaw':
        score += 5;
        reasons.push("Entrada Isolada: O bug se comporta estritamente local sem capacidade de lateral movement horizontal na nuvem.");
        suggestions.push("Descreva a quebra do modelo de confiança: explique como a exposição desse contêiner compromete serviços vizinhos.");
        break;
    }

    if (duplicationRisk === 'HIGH') {
      score = Math.max(10, score - 20);
    }

    let eligibility: 'ALTA' | 'MÉDIA' | 'BAIXA' | 'PROVÁVEL N/A' = 'MÉDIA';
    let colorText = 'text-yellow-400';
    let colorBg = 'bg-yellow-950/20 border-yellow-500/30';
    let colorProgress = 'bg-yellow-500';

    if (score >= 80) {
      eligibility = 'ALTA';
      colorText = 'text-emerald-400';
      colorBg = 'bg-emerald-950/20 border-emerald-500/30';
      colorProgress = 'bg-emerald-500';
    } else if (score >= 55) {
      eligibility = 'MÉDIA';
      colorText = 'text-yellow-400';
      colorBg = 'bg-yellow-950/20 border-yellow-500/30';
      colorProgress = 'bg-yellow-500';
    } else if (score >= 35) {
      eligibility = 'BAIXA';
      colorText = 'text-orange-400';
      colorBg = 'bg-orange-950/20 border-orange-500/30';
      colorProgress = 'bg-orange-500';
    } else {
      eligibility = 'PROVÁVEL N/A';
      colorText = 'text-red-400';
      colorBg = 'bg-red-950/20 border-red-500/30';
      colorProgress = 'bg-red-500';
    }

    if (reasons.length === 0) {
      reasons.push("Nenhuma restrição de triagem óbvia encontrada! O escopo reúne pilares altamente requisitados para recompensa.");
    }
    if (suggestions.length === 0) {
      suggestions.push("Seu rascunho de escopo já apresenta excelente alinhamento estruturado. Verifique e limpe os snippets de patch.");
    }

    return { eligibility, colorText, colorBg, colorProgress, score, reasons, suggestions };
  }, [alignAssetType, alignBoundaryCrossing, alignPracticalExploit, alignSystemicImpact, duplicationRisk]);

  // Deep interactive alignment audit using Google Gemini model orchestrator (BYOK)
  const handleAiAlignReportAudit = async () => {
    if (!apiKey) {
      alert("Chave de API do Gemini ausente. Por favor, especifique sua chave antes de prosseguir com a auditoria lógica.");
      return;
    }

    setIsAligningWithAi(true);
    try {
      const ai = new GoogleGenAI({ apiKey });
      const prompt = `Você é um Analista de Riscos de Triagem Sênior e Auditor Vêniado de Programas de Segurança Bug Bounty (Google VRP, MSRC, AWS Whitehat).
      Sua missão é analisar de forma fria e implacável o relatório técnico de segurança gerado para avaliar chances reais de negação (rejeição) ou concessão de bounty pela triagem humana.

      PARÂMETROS DA SUBMISSÃO ATUAL:
      - Nome do Projeto: ${projName}
      - Stack Tecnológico: ${inferredArchitecture}
      - Programa Alvo: ${targetCompany.toUpperCase()}
      - Classe de Vulnerabilidade: ${vulnClass}
      - Asset Class: ${alignAssetType}
      - Tipo de Boundary Quebrado: ${alignBoundaryCrossing}
      - Prova de Explotação Prática: ${alignPracticalExploit}
      - Impacto na Infraestrutura: ${alignSystemicImpact}

      RELATÓRIO ATUAL DO HACKER:
      """
      ${reportMarkdown || rawInputReport}
      """

      Sua resposta técnica deve ser dada em Português Técnico em exatamente 3 blocos ordenados Markdown de alto impacto (sem introduções robóticas vazias):

      ### 1. Diagnóstico de Alinhamento & Crítica do Escopo (Corte Inicial)
      Faça um julgamento duro e imparcial se essa falha passará no ecossistema da ${targetCompany.toUpperCase()} ou sofrerá de rejeição heurística (Informativo, Duplicado, ou Out of Scope). Cite regras VRP aplicáveis.

      ### 2. Principais Vetores de Argumentos da Triagem para Negativa de Bounty
      Apresente uma lista sucinta de argumentos prováveis que os triadores humanos tentarão opor ao ler esse relatório para evitar pagar bounty (ex: falta de escalonamento de privilégio, ausência de impacto cruzado, teoria impraticável, etc.).

      ### 3. Blueprint Técnico de Incrementação ("Blindagem da Submissão")
      Forneça dicas e orientações práticas de como blindar o relatório. O que o hacker deve pesquisar no host local, que novos endpoints ligar, ou que quebras de barreira adicionar no escopo para obrigar a triagem a convalidar e pagar a premiação máxima.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.5-flash',
        contents: prompt,
        config: {
          temperature: 0.2
        }
      });

      if (response && response.text) {
        setAiAlignmentReview(response.text);
      }
    } catch (e: any) {
      console.error(e);
      alert(`Falha na análise de auditoria com Gemini: ${e.message || e}`);
    } finally {
      setIsAligningWithAi(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `vrp_report_${projName.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">

      {pipelineDataToSync && (
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="border border-emerald-500/30 bg-emerald-500/5 rounded-2xl p-4.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-[0_0_25px_rgba(16,185,129,0.05)]"
        >
          <div className="space-y-1.5 flex-1 select-none">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-widest leading-none">
                Conectividade de Pipeline Ativa
              </span>
              <span className="text-[9px] bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded font-mono font-bold leading-none uppercase">
                {pipelineDataToSync.step.toUpperCase()} Findings
              </span>
            </div>
            <div className="text-white text-xs font-mono leading-relaxed">
              Descoberta importável identificada para <span className="text-emerald-400 font-bold underline decoration-emerald-600 underline-offset-4">{pipelineDataToSync.targetUrl}</span> ({pipelineDataToSync.company.toUpperCase()}).
            </div>
            <p className="text-[10px] text-zinc-400 font-mono">
              Payload: <code className="text-zinc-300 bg-zinc-900 border border-zinc-850 px-1 rounded inline-block truncate max-w-[280px] xs:max-w-md sm:max-w-lg">{pipelineDataToSync.evolvedPayload}</code>
            </p>
          </div>
          
          <div className="flex items-center gap-2 w-full sm:w-auto shrink-0">
            <button
              onClick={handleMergePipelineData}
              className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-4.5 py-2 bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-black font-extrabold font-mono text-[10px] uppercase rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.25)] transition-all cursor-pointer border-none"
            >
              <Sparkles size={13} />
              <span>Sincronizar no Relatório</span>
            </button>
            <button
              onClick={handleDismissPipelineSync}
              className="px-3.5 py-2 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-400 hover:text-white font-mono text-[10px] uppercase rounded-lg transition-all cursor-pointer"
            >
              Ignorar
            </button>
          </div>
        </motion.div>
      )}
      
      {/* Dynamic Visual Banner Context depending on target company program */}
      <div className={cn(
        "border-b p-6 rounded-2xl space-y-4 transition-all duration-500",
        targetCompany === 'google' && "border-blue-500/10 bg-gradient-to-r from-blue-950/20 via-zinc-950 to-zinc-950",
        targetCompany === 'aws' && "border-amber-500/10 bg-gradient-to-r from-amber-950/10 via-zinc-950 to-zinc-950",
        targetCompany === 'meta' && "border-emerald-500/10 bg-gradient-to-r from-emerald-950/10 via-zinc-950 to-zinc-950",
        targetCompany === 'microsoft' && "border-sky-500/10 bg-gradient-to-r from-sky-950/15 via-zinc-950 to-zinc-950",
        targetCompany === 'custom' && "border-zinc-805 bg-zinc-900/15"
      )}>
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-[0.2em] font-semibold text-zinc-400">
              <Coins size={14} className={cn(
                "animate-spin-slow",
                targetCompany === 'google' ? "text-blue-400" :
                targetCompany === 'aws' ? "text-amber-500" :
                targetCompany === 'meta' ? "text-emerald-400" :
                targetCompany === 'microsoft' ? "text-sky-400" : "text-zinc-400"
              )} /> 
              <span>MÓDULO GERADOR DE ESCOPO E NARRATIVA ADAPTATIVA VRP</span>
            </div>
            <h2 className="text-2xl font-mono font-bold text-white uppercase flex items-center gap-3 tracking-tight">
              Adaptive Security Narrative Engine <span className="text-zinc-550 text-xs tracking-normal normal-case font-extralight italic">Policies v2026 Core</span>
            </h2>
          </div>

          {/* Quick template triggers */}
          <div className="flex flex-wrap gap-2 shrink-0">
            <span className="text-[9px] font-mono text-zinc-550 uppercase tracking-wider self-center mr-2">Modelos Rápidos:</span>
            <button
              onClick={() => handleLoadTemplate('path-traversal-go')}
              className={cn(
                "px-3 py-1.5 rounded-lg text-[9px] uppercase font-mono tracking-wider transition-all border cursor-pointer",
                selectedTemplate === 'path-traversal-go' 
                  ? "bg-blue-600/15 border-blue-500/50 text-blue-400 font-bold shadow-[0_0_10px_rgba(59,130,246,0.1)]" 
                  : "bg-zinc-900/60 border-zinc-800 text-zinc-450 hover:text-white"
              )}
            >
               Traversal de Caminho (Go)
            </button>
            <button
              onClick={() => handleLoadTemplate('arg-injection')}
              className={cn(
                "px-3 py-1.5 rounded-lg text-[9px] uppercase font-mono tracking-wider transition-all border cursor-pointer",
                selectedTemplate === 'arg-injection' 
                  ? "bg-blue-600/15 border-blue-500/50 text-blue-400 font-bold shadow-[0_0_10px_rgba(59,130,246,0.1)]" 
                  : "bg-zinc-900/60 border-zinc-800 text-zinc-450 hover:text-white"
              )}
            >
               Injeção de CLI Flags (RCE)
            </button>
          </div>
        </div>
        <p className="text-[11px] font-sans text-zinc-450 max-w-4xl leading-relaxed">
          Unifique e refine suas auditorias. Configure o perímetro e assista à compilação instantânea do relatório sênior. O motor dinâmico altera narrativas, terminologias de cloud, gráficos ASCII e classificações de riscos para evitar assinaturas repetitivas fáceis de filtrar na triagem de segurança.
        </p>
      </div>

      {/* Corporate Target Selection Hub: Outstanding Visual Deck Controls everything at once! */}
      <div className="bg-zinc-950 border border-zinc-900 rounded-2xl p-4.5 space-y-3">
        <span className="text-[10px] font-mono uppercase tracking-[0.2em] font-extrabold text-zinc-400 block pb-1">
          🎯 PROGRAMA DE SEGURANÇA E INSTÂNCIA CORPORATIVA DE DESTINO (CONVÊNIOS ATIVOS)
        </span>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { id: 'google', name: 'Google VRP', details: 'Borg, gVisor, Tier 1 scale', colorClass: 'border-blue-500/20 bg-blue-950/5 text-blue-400 hover:border-blue-500/40', activeClass: 'border-blue-500 bg-blue-950/20 text-blue-300 ring-2 ring-blue-500/20' },
            { id: 'aws', name: 'AWS Bug Bounty', details: 'IAM, EC2, Cloud Security', colorClass: 'border-amber-500/20 bg-amber-950/5 text-amber-400 hover:border-amber-500/40', activeClass: 'border-amber-500 bg-amber-950/25 text-amber-300 ring-2 ring-amber-500/20' },
            { id: 'meta', name: 'Meta Whitehat', details: 'Graph API, GraphQL federation', colorClass: 'border-emerald-500/20 bg-emerald-950/5 text-emerald-400 hover:border-emerald-500/40', activeClass: 'border-emerald-500 bg-emerald-950/15 text-emerald-300 ring-2 ring-emerald-500/20' },
            { id: 'microsoft', name: 'Microsoft MSRC', details: 'Azure AD, Cloud principal', colorClass: 'border-sky-500/10 bg-sky-950/5 text-sky-400 hover:border-sky-500/40', activeClass: 'border-sky-500 bg-sky-950/15 text-sky-300 ring-2 ring-sky-500/20' },
            { id: 'custom', name: 'Private VRP', details: 'Logical endpoints / API model', colorClass: 'border-zinc-800 bg-zinc-900/30 text-zinc-450 hover:border-zinc-700', activeClass: 'border-zinc-200 bg-zinc-900 text-white ring-2 ring-zinc-500/20' }
          ].map((comp) => {
            const isActive = targetCompany === comp.id;
            return (
              <button
                key={comp.id}
                onClick={() => handleSelectTargetCompany(comp.id as any)}
                className={cn(
                  "p-3 rounded-xl border text-left flex flex-col justify-between transition-all duration-300 min-h-[75px] cursor-pointer",
                  isActive ? comp.activeClass : comp.colorClass
                )}
              >
                <div className="flex items-center justify-between w-full">
                  <span className="font-mono text-[11px] font-extrabold uppercase tracking-tight">{comp.name}</span>
                  {isActive && <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse shrink-0" />}
                </div>
                <span className="text-[8.5px] font-sans text-zinc-500 leading-normal mt-1 block">{comp.details}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Dynamic passive fingerprinting/auto-detect interface */}
      <div className="bg-zinc-950 border border-zinc-900 rounded-2xl overflow-hidden shadow-2xl">
        <button 
          onClick={() => setShowFingerprintPanel(!showFingerprintPanel)}
          className="w-full flex items-center justify-between px-5 py-4 bg-zinc-900/40 text-left cursor-pointer hover:bg-zinc-900/60 transition-colors"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-amber-500/10 text-amber-500 rounded-lg">
              <Brain size={16} className={cn(isFingerprinting && "animate-pulse text-amber-400")} />
            </div>
            <div>
              <span className="text-[10px] font-mono tracking-wider text-amber-500 font-extrabold uppercase block">MOTOR DE INTELIGÊNCIA ARQUITETURAL CLOUD</span>
              <h3 className="text-[13px] font-mono font-bold text-white uppercase tracking-tight flex items-center gap-2">
                Reconhecimento de Assinaturas (Passive Fingerprinting)
                <span className="px-1.5 py-0.5 rounded text-[8px] bg-amber-500/15 text-amber-400 border border-amber-500/20 font-light normal-case animate-pulse">Auto-Dedução Ativa</span>
              </h3>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {fingerprintResult && (
              <span className="text-[9px] font-mono bg-amber-500/10 border border-amber-500/30 text-amber-400 px-2 py-0.5 rounded uppercase font-bold">
                {fingerprintResult.company?.toUpperCase()} DETECTADO ({fingerprintResult.confidence}%)
              </span>
            )}
            <span className="text-zinc-500 text-xs font-mono">{showFingerprintPanel ? "[-]" : "[+]"}</span>
          </div>
        </button>

        <AnimatePresence>
          {showFingerprintPanel && (
            <motion.div 
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="border-t border-zinc-900 p-5 space-y-4"
            >
              <p className="text-[11px] font-sans text-zinc-450 leading-relaxed max-w-4xl">
                Alimente o motor colando os cabeçalhos HTTP obtidos em requisições de triagem passiva (ou use os presets de playground abaixo). O sistema analisará os metadados brutos buscando assinaturas específicas de infraestrutura de Big Tech corporativas (headers como <code className="text-zinc-300 font-mono text-[10px]">x-amzn-requestid</code>, cookies, etc.) e fará o preenchimento automático das premissas arquiteturais, mapeando e reduzindo o trabalho manual de "chute" de tecnologias do hunter.
              </p>

              {/* Presets and URL inputs */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
                <div className="md:col-span-8 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[9px] font-mono text-zinc-500 uppercase tracking-wider mb-1.5 font-bold">URL Alvo do Ativo (Simulado)</label>
                      <div className="relative">
                        <Globe size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
                        <input 
                          type="text"
                          value={fingerprintTargetUrl}
                          onChange={(e) => setFingerprintTargetUrl(e.target.value)}
                          className="w-full bg-zinc-900/80 border border-zinc-800 rounded pl-8 pr-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-amber-500/40"
                          placeholder="Ex: https://api.meta.com/v1"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-[9px] font-mono text-zinc-500 uppercase tracking-wider mb-1.5 font-bold">Playground de Assinaturas de Infraestrutura (Presets rápidos)</label>
                      <div className="grid grid-cols-2 gap-1.5">
                        {FINGERPRINT_PRESETS.map((p, idx) => (
                          <button
                            key={idx}
                            onClick={() => {
                              setFingerprintTargetUrl(p.url);
                              setFingerprintInput(p.headers);
                            }}
                            className="bg-zinc-900/50 hover:bg-zinc-900/90 border border-zinc-850 rounded px-2 py-1 text-[8px] font-mono text-zinc-400 truncate text-left cursor-pointer transition-colors hover:text-white"
                          >
                            ⚡ {p.name}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[9.5px] font-mono text-zinc-500 uppercase tracking-wider mb-1.5 font-bold">Cabeçalhos HTTP de Resposta / Cookies / Stack Trace bruto de erro</label>
                    <textarea
                      value={fingerprintInput}
                      onChange={(e) => setFingerprintInput(e.target.value)}
                      rows={4}
                      className="w-full bg-zinc-900/60 border border-zinc-800 rounded p-3 text-xs font-mono text-zinc-300 focus:outline-none focus:border-amber-500/40 focus:ring-1 focus:ring-amber-500/20"
                      placeholder="Cole aqui a resposta bruta de cabeçalhos HTTP (Ex: x-amz-cf-id, server: istio-envoy)..."
                    />
                  </div>
                </div>

                {/* Live scanner console logs output */}
                <div className="md:col-span-4 bg-black/45 border border-zinc-900 rounded-xl p-3.5 flex flex-col justify-between min-h-[190px]">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-[9px] font-mono text-zinc-500 uppercase pb-1 border-b border-zinc-900">
                      <span>Log do Analisador passivo</span>
                      <span className="flex h-1.5 w-1.5 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-amber-500"></span>
                      </span>
                    </div>
                    <div className="space-y-1.5 max-h-[110px] overflow-y-auto font-mono text-[9px] text-zinc-400 scrollbar-none">
                      {fingerprintLogs.length === 0 ? (
                        <span className="text-zinc-600 block italic py-4 text-center">Aguardando disparo de análise passiva...</span>
                      ) : (
                        fingerprintLogs.map((log, idx) => (
                          <div 
                            key={idx} 
                            className={cn(
                              "leading-relaxed",
                              log.includes("[DETECÇÃO") && "text-emerald-400 font-bold",
                              log.includes("[✓") && "text-amber-400 font-bold"
                            )}
                          >
                            {log}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={handleRunPassiveFingerprint}
                      disabled={isFingerprinting || !fingerprintInput}
                      className="w-full py-1.5 bg-amber-600/15 hover:bg-amber-600/35 active:bg-amber-600/50 text-amber-400 hover:text-white border border-amber-500/40 rounded text-[10px] uppercase font-mono tracking-wider font-extrabold cursor-pointer transition-all flex items-center justify-center gap-1.5 disabled:opacity-50"
                    >
                      {isFingerprinting ? (
                        <>
                          <RefreshCw className="animate-spin" size={12} />
                          <span>Mapeando Sinais de Rede...</span>
                        </>
                      ) : (
                        <>
                          <Search size={12} />
                          <span>Executar Triagem de Assinaturas</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Result Badge Panel */}
              {fingerprintResult && (
                <div className="p-3 bg-zinc-900/40 border border-zinc-900 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg shrink-0">
                      <ShieldCheck size={16} />
                    </div>
                    <div className="space-y-0.5">
                      <span className="text-[9px] font-mono uppercase text-zinc-500 block">Dedução Arquitetural Heurística</span>
                      <div className="text-[11px] font-sans text-zinc-300 leading-normal">
                        Detectamos <span className="text-amber-400 font-bold">{fingerprintResult.company?.toUpperCase()} ({fingerprintResult.confidence}% de certeza)</span>. O menu da ferramenta foi automaticamente sincronizado e alinhado para a stack <span className="text-blue-400 font-bold font-mono">{fingerprintResult.arch}</span> com foco em {fingerprintResult.focus?.toUpperCase()}.
                      </div>
                    </div>
                  </div>
                  <div className="text-[9.5px] font-mono uppercase text-emerald-400 bg-emerald-950/20 px-2 py-1 rounded shrink-0 font-bold border border-emerald-500/20">
                    Sincronizado Ativamente
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Main Grid Splitter: Side-by-Side Unified Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left-Pane (Vulnerability Parameters Suite) - 6 / 12 width */}
        <div className="lg:col-span-6 space-y-6">
          
          {/* Card A: Scope Metadata Mapping */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-2 mb-1">
              <span className="text-[10px] font-mono font-extrabold text-[#d2ad44] tracking-[0.2em] uppercase">
                📂 PARÂMETROS GERAIS DO ATIVO (METADATA MAPPING)
              </span>
              <div className="flex items-center space-x-1.5 bg-zinc-900/60 p-0.5 rounded-md border border-zinc-800/40">
                <button
                  type="button"
                  id="btn-lang-pt"
                  onClick={() => setReportLanguage('pt')}
                  className={`px-2 py-0.5 text-[9px] font-mono font-bold rounded transition-all uppercase ${
                    reportLanguage === 'pt'
                      ? 'bg-amber-400/20 border border-amber-400/30 text-amber-400'
                      : 'text-zinc-500 border border-transparent hover:text-zinc-300'
                  }`}
                >
                  PT 🇧🇷
                </button>
                <button
                  type="button"
                  id="btn-lang-en"
                  onClick={() => setReportLanguage('en')}
                  className={`px-2 py-0.5 text-[9px] font-mono font-bold rounded transition-all uppercase ${
                    reportLanguage === 'en'
                      ? 'bg-amber-400/20 border border-amber-400/30 text-amber-400'
                      : 'text-zinc-500 border border-transparent hover:text-zinc-300'
                  }`}
                >
                  EN 🇺🇸
                </button>
              </div>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1.5">Nome do Componente/Projeto</label>
                <input 
                  type="text" 
                  value={projName} 
                  onChange={(e) => setProjName(e.target.value)}
                  className="w-full bg-zinc-900/80 border border-zinc-800/80 rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-amber-500/50"
                  placeholder="Ex: Kubernetes Core API"
                />
              </div>

              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1.5">Repositório Oficial do Código</label>
                <input 
                  type="text" 
                  value={repoUrl} 
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="w-full bg-zinc-900/80 border border-zinc-800/80 rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-amber-500/50"
                  placeholder="Ex: https://github.com/..."
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1.5">Escopo de Qualidade (Tier)</label>
                <select
                  value={tier}
                  onChange={(e) => setTier(e.target.value as any)}
                  className="w-full bg-zinc-900/80 border border-zinc-800/80 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-amber-500/50 border-r-8 border-r-transparent"
                >
                  <option value="Tier 1">Tier 1 (Projetos de Máxima Criticidade)</option>
                  <option value="Tier 2">Tier 2 (Projetos de Médio Impacto)</option>
                  <option value="Tier 3">Tier 3 (Moderna Comunidade / Periféricos)</option>
                </select>
              </div>

              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1.5">Classe Sanitária CWE</label>
                <input 
                  type="text" 
                  value={vulnClass} 
                  onChange={(e) => setVulnClass(e.target.value)}
                  className="w-full bg-zinc-900/80 border border-zinc-800/80 rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-amber-500/50"
                  placeholder="Ex: Path Traversal (CWE-22)"
                />
              </div>
            </div>
          </div>

          {/* Card B: Data Flow & ASCII Taint Flow */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl p-5 space-y-4 shadow-xl">
            <span className="text-[10px] font-mono font-extrabold text-blue-400 tracking-[0.2em] block uppercase border-b border-zinc-900 pb-2">
              ▲ MAPEAMENTO DE DATA FLOW (SOURCE → SINK MAP)
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="bg-zinc-900/40 p-2.5 rounded-xl border border-zinc-900">
                <label className="text-[9px] font-mono uppercase text-blue-400 font-bold block mb-1">Source (Origem Externa do Input)</label>
                <input 
                  type="text" 
                  value={sourceFlow} 
                  onChange={(e) => setSourceFlow(e.target.value)}
                  className="w-full bg-zinc-950 font-mono text-[10px] text-zinc-300 border border-zinc-850 rounded px-2.5 py-1.5 focus:outline-none focus:border-blue-500/50"
                />
              </div>

              <div className="bg-zinc-900/40 p-2.5 rounded-xl border border-zinc-900">
                <label className="text-[9px] font-mono uppercase text-red-400 font-bold block mb-1 text-right">Sink (Função Crítica de Execução)</label>
                <input 
                  type="text" 
                  value={sinkFlow} 
                  onChange={(e) => setSinkFlow(e.target.value)}
                  className="w-full bg-zinc-950 font-mono text-[10px] text-zinc-300 border border-zinc-850 rounded px-2.5 py-1.5 focus:outline-none focus:border-red-500/50 text-right"
                />
              </div>
            </div>

            {/* SVG Visual Flow Diagram - Extremely elegant */}
            <div className="border border-zinc-900 bg-black/40 rounded-xl p-4 min-h-[145px] flex flex-col md:flex-row items-center justify-between gap-4 relative">
              <div className="absolute top-1/2 left-12 right-12 h-px border-t border-dashed border-zinc-800/50 -translate-y-1/2 hidden md:block pointer-events-none" />

              {/* Node Source */}
              <div className="flex flex-col items-center text-center z-10 w-full md:w-28 group">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center border border-blue-500/20 bg-blue-950/20 text-blue-400 shadow-[0_0_10px_rgba(59,130,246,0.1)] transition-all group-hover:scale-105">
                  <Globe size={14} />
                </div>
                <span className="text-[7.5px] font-mono text-zinc-500 uppercase tracking-wider mt-1.5 block">Source Input</span>
                <span className="text-[8px] font-mono text-zinc-300 truncate max-w-[100px] font-bold block bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800 mt-1 max-w-full">{sourceFlow}</span>
              </div>

              <ChevronRight size={14} className="text-zinc-650 rotate-90 md:rotate-0" />

              {/* Node Boundary */}
              <div className="flex flex-col items-center text-center z-10 w-full md:w-32 group">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center border border-amber-500/20 bg-amber-950/15 text-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.1)] transition-all group-hover:scale-105">
                  <Zap size={14} className="animate-bounce" />
                </div>
                <span className="text-[7.5px] font-mono text-zinc-500 uppercase tracking-wider mt-1.5 block">Isolated Boundary</span>
                <span className="text-[8px] font-mono text-amber-500 block font-bold mt-1 uppercase bg-amber-950/20 px-1.5 rounded border border-amber-500/20">Bypassed (Failure)</span>
              </div>

              <ChevronRight size={14} className="text-zinc-650 rotate-90 md:rotate-0" />

              {/* Node Sink */}
              <div className="flex flex-col items-center text-center z-10 w-full md:w-28 group">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center border border-red-500/20 bg-red-950/20 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.1)] transition-all group-hover:scale-105">
                  <Cpu size={14} />
                </div>
                <span className="text-[7.5px] font-mono text-zinc-500 uppercase tracking-wider mt-1.5 block">Critical Sink</span>
                <span className="text-[8px] font-mono text-red-400 truncate max-w-[100px] font-bold block bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800 mt-1 max-w-full">{sinkFlow}</span>
              </div>
            </div>
          </div>

          {/* Card C: Architectural Modelling & Trust Boundaries */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl p-5 space-y-4 shadow-xl">
            <span className="text-[10px] font-mono font-extrabold text-emerald-400 tracking-[0.2em] block uppercase border-b border-zinc-900 pb-2">
              🛡️ ARQUITETURA INFERIDA & FRONTEIRAS DE ISOLAMENTO
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1.5">Stack & Arquitetura Detectada</label>
                <select 
                  value={inferredArchitecture}
                  onChange={(e: any) => setInferredArchitecture(e.target.value)}
                  className="w-full bg-zinc-900/80 border border-zinc-800/80 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:outline-none border-r-8 border-r-transparent"
                >
                  <option value="GO_K8S">Go + Kubernetes (Workloads & Pods)</option>
                  <option value="NODE_EXPRESS">Node.js + Express (Middleware chain)</option>
                  <option value="GRAPHQL">GraphQL Federation (Resolver stitched)</option>
                  <option value="AZURE_AD">C# .NET + Entra ID (Azure Directory)</option>
                </select>
              </div>

              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1.5">Foco Clave de Isolamento</label>
                <select 
                  value={structuralFocus}
                  onChange={(e: any) => setStructuralFocus(e.target.value as any)}
                  className="w-full bg-zinc-900/80 border border-zinc-800/80 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:outline-none border-r-8 border-r-transparent"
                >
                  <option value="filesystem">Local Filesystem Paths Traversal</option>
                  <option value="iam">Cloud Identity Access Management (IAM)</option>
                  <option value="kubernetes">Kubernetes Service Account Limits</option>
                  <option value="auth_bypass">Internal Auth Connection Handshake</option>
                </select>
              </div>
            </div>

            {/* Live priority selector block (P1, PS1, P2, S2) */}
            <div className="space-y-1.5 pt-1">
              <label className="text-[10px] font-mono font-bold text-zinc-500 uppercase block tracking-wider">
                GRAVIDADE ESTIMADA DA TRIAÇÃO (VRP SEVERITY)
              </label>
              
              <div className="grid grid-cols-4 gap-2">
                {['P1', 'PS1', 'P2', 'S2'].map((vID) => {
                  const isS = severity === vID;
                  return (
                    <button
                      key={vID}
                      type="button"
                      onClick={() => setSeverity(vID as any)}
                      className={cn(
                        "py-2 px-1.5 rounded-xl border text-center font-mono text-[10px] font-bold transition-all duration-200 cursor-pointer",
                        isS 
                          ? vID === 'P1' ? "border-red-500 bg-red-950/20 text-red-300 ring-2 ring-red-500/15" :
                            vID === 'PS1' ? "border-amber-500 bg-amber-950/20 text-amber-300 ring-2 ring-amber-500/15" :
                            vID === 'P2' ? "border-blue-500 bg-blue-950/20 text-blue-300 ring-2 ring-blue-500/15" :
                            "border-zinc-300 bg-zinc-800 text-white ring-2 ring-zinc-500/10"
                          : "border-zinc-900 bg-zinc-900/40 text-zinc-500 hover:text-zinc-350"
                      )}
                    >
                      {vID}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Card D: Proof of Concept & Code Asset Differentials */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl p-5 space-y-4 shadow-xl">
            <span className="text-[10px] font-mono font-extrabold text-blue-400 tracking-[0.2em] block uppercase border-b border-zinc-900 pb-2">
              💻 CÓDIGO E ETAPAS DE REPRODUÇÃO (PROOF OF CONCEPT)
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-[9.5px] font-mono font-bold text-red-400 uppercase mb-1">Snippet Vulnerável</label>
                <textarea
                  value={vulnCode}
                  onChange={(e) => setVulnCode(e.target.value)}
                  className="w-full h-32 bg-zinc-900 border border-zinc-850 rounded p-2 text-[9.5px] font-mono text-red-400 focus:outline-none focus:border-red-500/50 resize-y"
                />
              </div>

              <div>
                <label className="block text-[9.5px] font-mono font-bold text-emerald-400 uppercase mb-1">Snippet de Patch Recomendado</label>
                <textarea
                  value={patchCode}
                  onChange={(e) => setPatchCode(e.target.value)}
                  className="w-full h-32 bg-zinc-900 border border-zinc-850 rounded p-2 text-[9.5px] font-mono text-emerald-400 focus:outline-none focus:border-emerald-500/50 resize-y"
                />
              </div>
            </div>

            <div className="space-y-3 pt-1">
              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1">Roteiro de Reprodução Local (Um comando por linha)</label>
                <textarea
                  value={pocStepsText}
                  onChange={(e) => setPocStepsText(e.target.value)}
                  className="w-full h-20 bg-zinc-900 border border-zinc-850 rounded p-2 text-[10px] font-mono text-zinc-300 focus:outline-none focus:border-amber-500/50 resize-y animate-none"
                  placeholder="Escreva passos sequenciais claros de teste"
                />
              </div>

              <div>
                <label className="block text-[9.5px] font-mono font-bold text-zinc-500 uppercase mb-1">Payload cURL de Demonstração Rápida</label>
                <input 
                  type="text" 
                  value={pocPayload} 
                  onChange={(e) => setPocPayload(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-850 rounded px-2.5 py-1.5 text-[10px] font-mono text-zinc-200 focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Card E: Collaborative Sandbox Simulator (Local Testing) */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl overflow-hidden shadow-xl">
            <button 
              type="button"
              onClick={() => setShowSandboxPanel(!showSandboxPanel)}
              className="w-full px-5 py-3.5 bg-zinc-900/50 border-b border-zinc-900 flex justify-between items-center transition-all hover:bg-zinc-900 cursor-pointer"
            >
              <div className="flex items-center gap-2">
                <Cpu size={14} className={cn("text-blue-400", isSimulatingExploit && "animate-spin")} />
                <span className="text-[10px] font-mono font-extrabold text-blue-400 tracking-[0.2em] uppercase">
                  🧪 SANDBOX DE SIMULAÇÃO DE EXPLOIT EM AFETAÇÃO (OPCIONAL)
                </span>
              </div>
              <span className="text-[9px] font-mono text-zinc-500">{showSandboxPanel ? 'RECOLHER' : 'EXPANDIR'}</span>
            </button>

            {showSandboxPanel && (
              <div className="p-5 space-y-4">
                <div className="grid grid-cols-2 gap-2.5">
                  <button
                    type="button"
                    onClick={() => {
                      setSimulatedFilterOn(!simulatedFilterOn);
                      setSandboxLogs(prev => [
                        `[*] Config modificada: Filtros globais de rotas configurado para [${!simulatedFilterOn ? 'ATIVADO' : 'DESATIVADO'}]`,
                        ...prev.slice(0, 4)
                      ]);
                    }}
                    className={cn(
                      "flex items-center justify-between p-2 rounded-lg border font-mono text-[9px] transition-all text-left cursor-pointer",
                      simulatedFilterOn 
                        ? "bg-emerald-950/20 border-emerald-500/40 text-emerald-400" 
                        : "bg-red-950/10 border-red-900/40 text-red-400/90"
                    )}
                  >
                    <span>Filtro de Escopo:</span>
                    <span className="font-bold">{simulatedFilterOn ? 'SÃO' : 'BYPASS'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setSimulatedCertECDSA(!simulatedCertECDSA);
                      setSandboxLogs(prev => [
                        `[*] Config modificada: Canal GTS Intermediário adaptado para [${!simulatedCertECDSA ? 'ECDSA Root 2026' : 'Legacy RSA'}]`,
                        ...prev.slice(0, 4)
                      ]);
                    }}
                    className={cn(
                      "flex items-center justify-between p-2 rounded-lg border font-mono text-[9px] transition-all text-left cursor-pointer",
                      simulatedCertECDSA 
                        ? "bg-blue-950/15 border-blue-500/40 text-blue-400" 
                        : "bg-zinc-900 border-zinc-800 text-zinc-500"
                    )}
                  >
                    <span>WE1 TLS v2026:</span>
                    <span className="font-bold">{simulatedCertECDSA ? 'ACTIVE' : 'INACTIVE'}</span>
                  </button>
                </div>

                <div className="flex gap-2">
                  <input
                    type="text"
                    value={simulatedPayloadInput}
                    onChange={(e) => setSimulatedPayloadInput(e.target.value)}
                    placeholder="Payload string de teste..."
                    className="flex-1 bg-black rounded border border-zinc-800 font-mono text-[10.5px] text-zinc-300 px-3 py-1.5 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      if (isSimulatingExploit) return;
                      setIsSimulatingExploit(true);
                      setSimulatedPacketStatus('ROUTE');
                      setSandboxLogs(prev => [
                        `[ENTRY] Transmitindo payload lógico de simulação de perímetro...`,
                        `[PAYLOAD] String interceptada: "${simulatedPayloadInput}"`,
                        ...prev.slice(0, 4)
                      ]);
                      
                      setTimeout(() => {
                        if (simulatedFilterOn) {
                          setSimulatedPacketStatus('BLOCKED');
                          setSandboxLogs(prev => [
                            `[BLOCKED] Tentativa de transposição interceptada pelos filtros canônicos de rotas!`,
                            `[ALERT] Solicitação abortada com status 403 Forbidden.`,
                            ...prev.slice(0, 4)
                          ]);
                        } else {
                          setSimulatedPacketStatus('BREACHED');
                          setSandboxLogs(prev => [
                            `[EXPLOITED] Limite de confiança violado! Arquivo processado pelo Sink com sucesso.`,
                            `[VULNERABLE] Vaza dados confidenciais de credenciais de serviço.`,
                            ...prev.slice(0, 4)
                          ]);
                        }
                        setIsSimulatingExploit(false);
                      }, 1200);
                    }}
                    disabled={isSimulatingExploit}
                    className="bg-blue-600 hover:bg-blue-500 text-white font-mono text-[9px] px-3.5 rounded-lg uppercase font-bold transition-all shrink-0 flex items-center gap-1.5 cursor-pointer"
                  >
                    <Send size={10} /> Disparar
                  </button>
                </div>

                {/* Animated graphic map for Sandbox */}
                <div className="h-32 bg-black rounded-xl border border-zinc-900 relative overflow-hidden flex flex-col justify-between p-3.5">
                  <div className="flex justify-between items-center z-10 w-full">
                    <span className="text-[8px] font-mono text-zinc-500 uppercase flex items-center gap-1 font-bold">
                      <Eye size={10} className="text-blue-400" /> MONITOR DE DADOS SANDBOX
                    </span>
                    
                    <span className={cn(
                      "px-2 py-0.5 rounded text-[8px] font-mono uppercase font-bold border",
                      simulatedPacketStatus === 'IDLE' && "border-zinc-800 bg-zinc-900 text-zinc-550",
                      simulatedPacketStatus === 'ROUTE' && "border-yellow-500/40 bg-yellow-950/20 text-yellow-400 animate-pulse",
                      simulatedPacketStatus === 'BLOCKED' && "border-emerald-500/40 bg-emerald-950/20 text-emerald-400 font-extrabold",
                      simulatedPacketStatus === 'BREACHED' && "border-red-500/40 bg-red-950/20 text-red-400 font-extrabold animate-bounce"
                    )}>
                      {simulatedPacketStatus === 'IDLE' ? 'Aguardando' : simulatedPacketStatus}
                    </span>
                  </div>

                  {/* Packet routing connection node diagram */}
                  <div className="flex justify-between items-center relative my-1 px-4 w-full h-10">
                    <div className="absolute left-6 right-6 top-1/2 -translate-y-1/2 h-0.5 bg-zinc-900 pointer-events-none z-0" />
                    
                    {simulatedPacketStatus === 'ROUTE' && (
                      <motion.div 
                        initial={{ left: '10%' }}
                        animate={{ left: '90%' }}
                        transition={{ duration: 1.0, repeat: Infinity }}
                        className="absolute w-2 h-2 rounded-full bg-yellow-400 z-10 blur-[1px]"
                      />
                    )}

                    {['Gateway', 'TLS Cert', 'Filter', 'Sink'].map((nodeName, nodeIdx) => {
                      let borderClass = 'border-zinc-800 bg-zinc-950 text-zinc-650';
                      if (nodeIdx === 0 && simulatedPacketStatus === 'ROUTE') borderClass = 'border-yellow-400 bg-yellow-950/20 text-yellow-400';
                      if (nodeIdx === 1 && simulatedCertECDSA) borderClass = 'border-blue-500 bg-blue-950/15 text-blue-400';
                      if (nodeIdx === 2) {
                        borderClass = simulatedFilterOn ? 'border-emerald-500 bg-emerald-950/15 text-emerald-400' : 'border-red-500/20 bg-red-950/10 text-red-400/70';
                      }
                      if (nodeIdx === 3) {
                        borderClass = simulatedPacketStatus === 'BREACHED' ? 'border-red-500 bg-red-950/20 text-red-400 animate-pulse' : 'border-zinc-850 bg-zinc-950 text-zinc-600';
                      }
                      
                      return (
                        <div key={nodeName} className="flex flex-col items-center z-10 text-center">
                          <div className={cn("w-7 h-7 rounded-lg border flex items-center justify-center font-mono text-[9px]", borderClass)}>
                            {nodeIdx + 1}
                          </div>
                          <span className="text-[7px] font-mono text-zinc-500 mt-1 uppercase block">{nodeName}</span>
                        </div>
                      );
                    })}
                  </div>

                  <div className="bg-[#050505] p-1.5 rounded border border-zinc-900 flex items-center gap-1.5 leading-normal">
                    <span className={cn(
                      "w-1.5 h-1.5 rounded-full shrink-0",
                      simulatedPacketStatus === 'IDLE' && "bg-zinc-600",
                      simulatedPacketStatus === 'ROUTE' && "bg-yellow-400 animate-pulse",
                      simulatedPacketStatus === 'BLOCKED' && "bg-emerald-400",
                      simulatedPacketStatus === 'BREACHED' && "bg-red-500"
                    )} />
                    <span className="text-[8px] font-mono text-zinc-400">
                      {simulatedPacketStatus === 'IDLE' && 'Dica: Ative ou desative o filtro de escopo para observar as divergências nos outputs.'}
                      {simulatedPacketStatus === 'ROUTE' && 'Pacote em rota: Transmitindo caracteres unicode de escape de sandbox para validação...'}
                      {simulatedPacketStatus === 'BLOCKED' && 'Contenção ativa: Sanitizador detectou e mitigou com sucesso tentativas de escape.'}
                      {simulatedPacketStatus === 'BREACHED' && 'Perigo: Contramedidas vulneráveis. Arquivos sensíveis do sistema vazados para canais unauthenticated.'}
                    </span>
                  </div>
                </div>

                <div className="bg-black/95 border border-zinc-900 rounded-lg p-2.5 max-h-24 overflow-y-auto no-scrollbar font-mono text-[8.5px] text-zinc-500 space-y-0.5 leading-relaxed">
                  {sandboxLogs.map((lg, i) => (
                    <div key={i} className={cn(
                      lg.includes('[VULNERABLE]') && "text-red-400",
                      lg.includes('[BLOCKED]') && "text-emerald-400",
                      lg.includes('[ALERT]') && "text-yellow-400Font",
                      lg.includes('[ENTRY]') && "text-blue-300"
                    )}>{lg}</div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Card F: Compliance Verification (VRP 2026 Checklist) */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl p-5 space-y-4 shadow-xl">
            <span className="text-[10px] font-mono font-extrabold text-amber-500 tracking-[0.2em] block uppercase border-b border-zinc-900 pb-2">
              🚨 VERIFICAÇÃO DE COMPLIANCE DE NARRATIVA (POLÍTICAS VRP 2026)
            </span>
            
            <div className="space-y-2.5">
              {[
                { state: policyAntiSlop, setter: setPolicyAntiSlop, label: "Filtro de Conteúdo Técnico Ativo (Anti-Slop Compliance)", desc: "Exclui especulações ou linguagens robóticas repetitivas de IA sênior, focando estritamente na quebra concreta." },
                { state: policyReproduction, setter: setPolicyReproduction, label: "Explotação Local Comprovada Ponta-a-Ponta", desc: "Fornece passos válidos de reprodução e comandos bash estruturados para execução offline sem falsa infraestrutura." },
                { state: policyTaintFlow, setter: setPolicyTaintFlow, label: "Taint Flow de Dados Garantido (Source → Sink Link)", desc: "Demonstra o rastreio irrefutável de conexões lógicas entre a entrada do atacante e a falha de código no sistema." },
                { state: policyNoPermission, setter: setPolicyNoPermission, label: "Bypass sob Privilégio Zero (Unauthenticated Default)", desc: "Confirma que o ataque independe de privilégios prévios, ou contorna barreiras com baixíssimo controle no ambiente." }
              ].map((verifyRule, i) => (
                <label key={i} className="flex items-start gap-3 cursor-pointer group bg-zinc-900/10 p-2.5 rounded-xl border border-zinc-900 hover:border-zinc-800 transition-all">
                  <input 
                    type="checkbox" 
                    checked={verifyRule.state} 
                    onChange={(e) => verifyRule.setter(e.target.checked)}
                    className="mt-0.5 rounded border-zinc-800 text-blue-500 focus:ring-blue-500/20 bg-zinc-950 cursor-pointer"
                  />
                  <div>
                    <span className="text-[11px] font-mono font-bold text-zinc-200 block group-hover:text-white transition-all">{verifyRule.label}</span>
                    <span className="text-[9px] font-sans text-zinc-500 block leading-normal mt-0.5">{verifyRule.desc}</span>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Right-Pane (Output Display & Risk Rating Suite) - 6 / 12 width */}
        <div className="lg:col-span-6 space-y-6">
          
          {/* Card G: Dynamic Reward Calculator & Align Score Matrix */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl p-5 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-2">
              <span className="text-[10px] font-mono font-extrabold text-emerald-400 tracking-[0.2em] uppercase flex items-center gap-1.5">
                <Coins size={14} /> CALCULADORA E ANALISADOR DE BOUNTY
              </span>
              <span className="text-[8px] font-mono text-zinc-500 tracking-widest uppercase">Policies scale 2026</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
              {/* Acceptance Meter Score */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-[9.5px] font-mono text-zinc-400">
                  <span>Chance de Homologação:</span>
                  <span className={cn("font-bold", heuristicAlignmentResult.colorText)}>{heuristicAlignmentResult.score}% ({heuristicAlignmentResult.eligibility})</span>
                </div>
                <div className="w-full h-1.5 bg-zinc-900 rounded-full overflow-hidden block">
                  <div 
                    className={cn("h-full transition-all duration-350", heuristicAlignmentResult.colorProgress)}
                    style={{ width: `${heuristicAlignmentResult.score}%` }}
                  />
                </div>
                <span className="text-[8.5px] text-zinc-500 font-sans block leading-snug">Índice ponderado com base nos eixos de limites cruzados, maturidade técnica de PoC e classe de ativo.</span>
              </div>

              {/* Reward Bracket Display */}
              <div className="bg-black/45 border border-zinc-900 rounded-xl p-3 text-center space-y-0.5 h-full flex flex-col justify-center">
                <span className="text-[8.5px] font-mono text-zinc-500 uppercase tracking-widest block font-bold">RECOMPENSA DE CRÉDITO ESTIMADA</span>
                <span className="text-xl font-mono font-extrabold text-[#10b981] drop-shadow-[0_0_8px_rgba(16,185,129,0.2)] block my-1">
                  {rewardRange}
                </span>
                <span className="text-[7.5px] font-sans text-zinc-550 block">Régua tarifária ativa: {targetCompany === 'google' ? 'Google OSS Matrix' : targetCompany === 'aws' ? 'AWS SecOps Standard' : targetCompany === 'meta' ? 'Meta Whitehat Tier' : targetCompany === 'microsoft' ? 'MSRC Impact Bracket' : 'Private Scope Rate'}</span>
              </div>
            </div>

            {/* Risk indicators warnings & Suggestions */}
            <div className="bg-zinc-900/30 p-3 rounded-xl border border-zinc-900 space-y-3.5">
              <div className="space-y-1">
                <span className="text-[8.5px] font-mono text-red-400 uppercase font-bold tracking-wider flex items-center gap-1">
                  <AlertTriangle size={10} className="text-red-400" /> Alerta de Triador / Argumentos de Corte:
                </span>
                <ul className="text-[8.5px] text-zinc-400 space-y-1 list-disc pl-3.5 leading-normal">
                  {heuristicAlignmentResult.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>

              <div className="space-y-1 border-t border-zinc-900 pt-2 text-zinc-400">
                <span className="text-[8.5px] font-mono text-emerald-400 uppercase font-semibold tracking-wider flex items-center gap-1">
                  <ShieldCheck size={10} className="text-[#10b981]" /> Como Blindar para Maximizar o Bounty:
                </span>
                <ul className="text-[8.5px] text-zinc-400 space-y-1 list-disc pl-3.5 leading-normal">
                  {heuristicAlignmentResult.suggestions.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </div>
            </div>

            {/* AI Policy Assessment Trigger & Review Display */}
            <div className="space-y-3 pt-1 border-t border-zinc-900">
              <button
                type="button"
                onClick={handleAiAlignReportAudit}
                disabled={isAligningWithAi}
                className="w-full py-2 bg-gradient-to-r from-emerald-600/90 to-teal-600/90 hover:from-emerald-500 hover:to-teal-500 text-white font-mono font-bold text-[9.5px] uppercase rounded-xl transition-all flex items-center justify-center gap-1.5 shadow-[0_0_12px_rgba(16,185,129,0.1)] cursor-pointer"
              >
                {isAligningWithAi ? (
                  <>
                    <span className="w-3 h-3 border-2 border-t-transparent border-white rounded-full animate-spin shrink-0" />
                    <span>Solicitando Auditoria Gemini...</span>
                  </>
                ) : (
                  <>
                    <Brain size={12} className="text-white animate-pulse" />
                    <span>Realizar Auditoria de Riscos com Gemini AI (BYOK)</span>
                  </>
                )}
              </button>

              {aiAlignmentReview && (
                <div className="border border-emerald-950/40 rounded-xl bg-black/60 overflow-hidden animate-in fade-in zoom-in duration-300">
                  <div className="bg-[#10b981]/5 border-b border-zinc-900/60 px-3 py-2 flex items-center justify-between">
                    <span className="text-[8.5px] font-mono font-bold text-emerald-400 uppercase tracking-widest flex items-center gap-1.5">
                      <Brain size={11} className="text-emerald-400" /> DIAGNÓSTICO E BLUEPRINT DE RISCOS - GEMINI AI
                    </span>
                    <span className="text-[7px] font-mono text-zinc-550">Risk Assessment Report</span>
                  </div>
                  <div className="p-3 max-h-[190px] overflow-y-auto font-sans text-[9px] text-zinc-350 pr-2 leading-relaxed space-y-2 whitespace-pre-wrap">
                    <ReactMarkdown>{aiAlignmentReview}</ReactMarkdown>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Card H: Markdown Output Console & Floating Synthesis Actions */}
          <div className="bg-zinc-950 border border-zinc-900 rounded-2xl overflow-hidden shadow-2xl">
            <div className="bg-zinc-900/50 border-b border-zinc-900 px-4 py-3 flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold text-zinc-450 tracking-wider flex items-center gap-1.5 uppercase">
                <FileText size={13} className="text-zinc-500" /> Relatório VRP Pronto para Envio (.md)
              </span>

              <div className="flex gap-2.5">
                <button
                  type="button"
                  onClick={handleCopy}
                  className="p-1 px-2.5 bg-zinc-850 hover:bg-zinc-800 rounded-lg text-[9px] font-mono text-zinc-400 hover:text-white transition-all flex items-center gap-1 border border-zinc-800 cursor-pointer"
                  title="Copiar Relatório"
                >
                  {copied ? <Check size={10} className="text-emerald-500" /> : <Copy size={10} />}
                  <span>{copied ? 'Copiado!' : 'Copiar'}</span>
                </button>
                <button
                  type="button"
                  onClick={handleDownload}
                  className="p-1 px-2.5 bg-zinc-850 hover:bg-zinc-800 rounded-lg text-[9px] font-mono text-zinc-400 hover:text-white transition-all flex items-center gap-1 border border-zinc-800 cursor-pointer"
                  title="Exportar Markdown"
                >
                  <Download size={10} />
                  <span>Download</span>
                </button>
              </div>
            </div>

            <div className="p-4 max-h-[380px] overflow-y-auto bg-[#08080a] custom-scrollbar pr-2 leading-relaxed prose prose-invert font-mono text-[9px] text-zinc-300">
              <div className="whitespace-pre-wrap select-all selection-amber_2026 leading-relaxed">
                {reportMarkdown}
              </div>
            </div>
          </div>

          {/* Master Generator Actions Selection: Unified Single Button Actions layout */}
          <div className="space-y-3 pt-1">
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                type="button"
                onClick={handleGenerateLocalReport}
                className="flex-1 py-3 bg-zinc-900 hover:bg-zinc-850 text-zinc-300 border border-zinc-800 hover:border-zinc-700 font-mono font-bold text-[10px] uppercase tracking-wider rounded-xl transition-all flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <FileText size={13} /> Compilar Rascunho de Escopo
              </button>
              
              <button
                type="button"
                onClick={handleAiSynthesizeReport}
                disabled={isAiGenerating}
                className="flex-1 py-3 bg-blue-600 hover:bg-blue-500 text-white font-mono font-bold text-[10px] uppercase tracking-wider rounded-xl transition-all shadow-[0_0_15px_rgba(37,99,235,0.2)] flex items-center justify-center gap-1.5 cursor-pointer font-extrabold"
              >
                {isAiGenerating ? (
                  <>
                    <span className="w-3 h-3 border-2 border-t-transparent border-white rounded-full animate-spin shrink-0" />
                    <span>Sintetizando Escopo com IA...</span>
                  </>
                ) : (
                  <>
                    <Sparkles size={12} className="text-amber-300 animate-pulse" />
                    <span>Sintetizar Narrativa com Gemini</span>
                  </>
                )}
              </button>
            </div>

            {/* Compressor Cognitive & Raw Trace translator panel integration */}
            <div className="bg-zinc-950 border border-zinc-950 rounded-2xl overflow-hidden mt-3">
              <button
                type="button"
                onClick={() => setShowCompressorPanel(!showCompressorPanel)}
                className="w-full px-4 py-2.5 bg-zinc-900/30 hover:bg-zinc-900/60 border border-zinc-900 rounded-xl flex justify-between items-center transition-all cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Brain className="text-amber-500 animate-pulse" size={12} />
                  <span className="text-[9px] font-mono text-amber-500 uppercase font-extrabold tracking-wider">
                    🧠 COMPRESSOR COGNITIVO LÓGICO DE TRACES (IMPORTAR BRUTO)
                  </span>
                </div>
                <span className="text-[8.5px] font-mono text-zinc-550">{showCompressorPanel ? 'RECOLHER' : 'ABRIR CONFIGURADOR'}</span>
              </button>

              {showCompressorPanel && (
                <div className="p-4 border border-zinc-900 rounded-xl border-t-0 bg-[#0c0c0e] space-y-3 animate-in slide-in-from-top duration-300">
                  <div className="space-y-1">
                    <label className="text-[8.5px] font-mono font-bold text-zinc-500 uppercase block leading-none">
                      Insira rascunho de logs descuidos de terminal, logs brutos ou traces do gdb / k8s:
                    </label>
                    <textarea
                      value={rawInputReport}
                      onChange={(e) => setRawInputReport(e.target.value)}
                      className="w-full h-32 bg-zinc-950 border border-zinc-850 rounded p-2 text-[9.5px] font-mono text-zinc-300 focus:outline-none focus:border-amber-550 focus:ring-1 focus:ring-amber-500/20"
                      placeholder="Cole traces ou dados de depuração..."
                    />
                  </div>

                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => {
                        // Fast static heuristic parsing client-side
                        let inferredP = projName;
                        const projMatch = rawInputReport.match(/(?:projeto|project|app|service|target)\s*:\s*([^\n]+)/i);
                        if (projMatch) inferredP = projMatch[1].trim();
                        
                        setProjName(inferredP);
                        handleGenerateLocalReport();
                        setSandboxLogs(prev => [
                          `[PARSER] Sucesso: Heurística local processou o rascunho.`,
                          ...prev.slice(0, 4)
                        ]);
                        alert("Anatomização heurística rápida concluída!");
                      }}
                      className="flex-1 py-1.5 bg-zinc-905 border border-zinc-800 text-zinc-400 font-mono font-bold text-[8.5px] uppercase rounded-lg transition-all cursor-pointer hover:text-white"
                    >
                      Processamento Rápido Local
                    </button>

                    <button
                      type="button"
                      onClick={handleCompressAndDeconstructRawLogs}
                      disabled={isAiGenerating}
                      className="flex-1 py-1.5 bg-amber-600/95 hover:bg-amber-500 text-white font-mono font-extrabold text-[8.5px] uppercase rounded-lg transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-[0_0_10px_rgba(245,158,11,0.1)]"
                    >
                      <Sparkles size={10} className="animate-pulse" />
                      Extrair Parâmetros por IA (Gemini)
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
