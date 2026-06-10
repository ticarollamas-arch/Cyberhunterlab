export interface AnalysisResult {
  vulnerabilidade: string | null;
  tipo: string | null;
  evidencia: string;
  linhas_afetadas: string[];
  impacto: 'baixo' | 'medio' | 'alto' | 'critico';
  severidade: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  vrp_category: 'S0' | 'S1' | 'S2' | 'C0' | 'C1' | 'A1' | 'A2' | 'A3' | 'A4' | 'A5' | 'A6' | 'OSS_Supply_Chain' | 'OSS_Product' | 'Outro';
  triage_priority: 'P0' | 'P1' | 'P2' | 'P3' | 'P4';
  risco_duplicata: 'baixo' | 'medio' | 'alto';
  patch_corrige: boolean;
  regressao_detectada: boolean;
  confianca: number;
  status: 'confirmado' | 'inconclusivo';
  justificativa: string;
  estrategia_hunting: string;
  source: string | null;
  sink: string | null;
  fluxo_confirmado: boolean;
  sanitizacao: string;
  impacto_real: boolean;
  modelagem_ataque: string;
  oss_vrp_tier?: 'OT0' | 'OT1' | 'OT2' | 'OT3' | null;
  poc_reproducao?: string;
  poc_passos: string[];
  policy_violada: string;
  relatorio_markdown: string;
  target_platform: 'google_vrp' | 'hackerone';
  telemetria: {
    latencia_ms: number;
    modelo: string;
    throughput_tokens: number;
    pipeline: string;
  };
}

export interface VerificationResult {
  is_valid: boolean;
  found_assumptions: string[];
  evidence_exists: boolean;
  final_confidence: number;
  final_status: 'confirmado' | 'inconclusivo';
  feedback: string;
}

export interface SecurityAnalysis {
  id: string;
  timestamp: string;
  code_before?: string;
  code_after?: string;
  diff?: string;
  result: AnalysisResult;
  verification?: VerificationResult;
}
