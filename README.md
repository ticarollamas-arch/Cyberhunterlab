# 👑 Bancada Prompt & AI Patch Validator: Orquestrador de Engenharia e Blindagem de Instruções Sênior

> **Enterprise-Grade Vulnerability Remediation and
> Automated Patch Validation Engine**  
> *Uma suíte de engenharia de segurança de alta fidelidade e governança de contexto para auditorias de código e proteção contra bypasses lógicos (P0/P1/P2) sob diretrizes regulatórias Google VRP e HackerOne.*

---

## ⚡ Links Rápidos de Acesso e Demonstração

*   **🌐 [Demonstração ao Vivo (Production Preview)](https://ais-pre-k6yccizdgwocdze7c3pa4s-13767980963.us-west2.run.app)**: Instância ativa executando o barramento do portal e a interface corporativa de análise de segurança.
*   **⚡ [Remixar no Google AI Studio](https://ai.studio/build/00e287f6-a979-4348-b38c-551fe3514ad6)**: Clone o espaço de trabalho completo em sua conta para auditar os motores de IA e provisionar sua própria infraestrutura em containers.

---

## 🏗️ Visão Geral e Arquitetura do Sistema

O **AI Patch Validator** (Bancada Prompt) é uma plataforma de segurança projetada sob o paradigma **Zero Trust** para automatizar a triagem, análise e validação de patches de código-fonte. O sistema substitui validações manuais de risco por um pipeline determinístico que detecta falhas de lógica de negócios em fluxo de dados (*Source-to-Sink*), valida limites de privilégios de containers e mitiga desvios de integridade na nuvem.

### Pipeline de Orquestração Cognitiva (Data-Flow)

```
                                      [CÓDIGO DE ORIGEM / DIFF PATCH]
                                                     │
                                                     ▼
                                     [VALIDAÇÃO DE CONTRATOS (ZOD)]
                                                     │
                                                     ▼
                                    [ENGINE DE HISTÓRICO LOCAL (DEDUPE)]
                                                     │
                                                     ▼
                                   [ORCHESTRATOR COGNITIVE SANDBOX]
                                                     │
                    ┌────────────────────────────────┴────────────────────────────────┐
                    ▼                                                                 ▼
         [PIPELINE HIGH-SPEED (Flash)]                                   [PIPELINE REASONING (Pro)]
                    │                                                                 │
                    ▼                                                                 ▼
       [TRIAGEM RÁPIDA DE IMPACTO SRE]                                  [AUDITORIA MULTI-AGENTE (Dual)]
                    │                                                                 │
                    └────────────────────────────────┬────────────────────────────────┘
                                                     ▼
                                         [CIRCUIT BREAKER CONTROL]
                                                     │
                                                     ▼
                                       [WINSTON OBSERVABILITY SRE LOGS]
```

---

## 🛡️ Alinhamento: AWS Well-Architected Framework

Como arquiteto de soluções, esta aplicação foi desenhada respeitando rigorosamente os pilares de arquitetura de nuvem empresarial da **AWS Well-Architected Framework**:

### 1. Segurança (Security-by-Design & Zero Trust)
*   **Isolamento de Contexto (Cognitive Sandboxing)**: Restringe o escopo de interpretação do LLM estritamente às diretrizes de segurança de código fornecidas, usando metaprompting estruturado que rejeita instruções ofensivas e alucinações semânticas.
*   **Validação de Fronteiras de Confiança**: O motor analisa o impacto do patch em 6 dimensões de segurança:
    1.  *Filesystem Boundary* (Fronteira de arquivos, ex: CWE-22, path traversals).
    2.  *Identity Boundary* (Fronteira de identidade/tokens).
    3.  *Namespace Boundary* (Fronteira de orquestração de containers).
    4.  *Tenant Boundary* (Vazamento cross-account em multi-tenancy).
    5.  *Network Boundary* (Exposição de portas internas/SSRF).
    6.  *Service Trust Boundary* (Quebra de handshakes entre microsserviços).

### 2. Confiabilidade (Reliability & Fault Tolerance)
*   **Circuit Breaker & Retry Automático**: Implementação resiliente na comunicação com as APIs de IA externa. Se o serviço retornar limitação de taxa (HTTP 429 / *Resource Exhausted*), o sistema intercepta o erro através de um fluxo inteligente com **Backoff Exponencial** e recuo defensivo.
*   **Idempotência e Sanitização de Entrada**: Garante que o mesmo payload não sobrecarregue o modelo, validando o schema de saída estruturado em nível de engine.

### 3. Eficiência de Performance (Performance Efficiency)
*   **Estratégia de Model Split (Multi-Agent Cascade)**:
    *   **Gemini 3.5 Flash** é utilizado para triagem instantânea de menor latência (pipeline padrão, economia drástica de tokens e tempo de processamento).
    *   **Gemini 3.1 Pro com Reasoning Engine** é acionado sob demanda apenas quando há necessidade de verificação formal profunda contra falsos positivos.

### 4. Excelência Operacional (Operational Excellence)
*   **Telemetria SRE Embutida**: Cada análise gera métricas de latência em milissegundos, taxa de processamento de tokens e metadados sobre o pipeline utilizado.
*   **Logs Estruturados para CloudWatch/Datadog**: Emissão de logs padronizados via Winston para garantir indexação direta e observabilidade de auditoria de segurança.

### 5. Otimização de Custos (Cost Optimization)
*   **Mecanismo de Deduplicação Local**: O histórico de análises é verificado localmente antes do envio do payload para o provedor de IA, evitando chamadas repetidas de API para o mesmo Diff de código e otimizando o gasto operacional da infraestrutura.

---

## 🛠️ Stack Tecnológica de Alta Performance

*   **Runtime & Linguagem**: Node.js, TypeScript Estrito (CI/CD Compilado).
*   **Vite & React 19 SPA**: Interface de alto contraste projetada para analistas de segurança, livre de dependências redundantes e otimizada para renderização acelerada.
*   **Tailwind CSS v4**: Utilização de variáveis globais e tokens de design modernos diretamente compilados pelo compilador `@tailwindcss/vite`.
*   **Segurança Estática**: `javascript-obfuscator` nativo no pipeline de build do Vite para proteger a lógica proprietária do motor do analista de ataques reversos diretos no browser.

---

## 🧩 Módulos do Sistema e Capacidades

O painel central expõe uma suíte especializada que reflete todas as frentes de uma infraestrutura robusta de SecOps:

1.  **AI Patch Validator (Dual-Patch Analyzer)**: Entrada de códigos "Antes" e "Depois" para provar e auditar se a remediação inserida realmente remove o bug lógico ou se há riscos de regressão operacional.
2.  **DevSecOps Agentic Pipeline**: Interface de simulação de pipelines integrados que avaliam branches de código em tempo de Pull Request.
3.  **OSV Schema Module**: Conversor e validador de vulnerabilidades baseado no formato global de código aberto OSV (Open Source Vulnerability).
4.  **Reverse Architecture Engine**: Mapeador estático de software que projeta os fluxos e dependências estruturais de pacotes legados para documentação executiva.
5.  **CWE-22 Academy (Interactive Lab)**: Um ambiente de treinamento ativo contendo cenários de vulnerabilidade realistas (Python/Flask e Python CLI) focados em caminhos de arquivos relativos e sanitização rigorosa de inputs de SRE.

---

## 📊 Telemetria de Produção e Exemplo de Log SRE

Os eventos de análise gerados pela bancada são injetados no barramento de observabilidade no formato JSON estruturado abaixo, permitindo criação de alertas de anomalia no AWS CloudWatch:

```json
{
  "timestamp": "2026-07-12T17:06:05Z",
  "transaction_id": "TX_88A3B91C4",
  "level": "INFO",
  "service": "prompt-bench-orchestrator",
  "action": "PATCH_SECURITY_ANALYSIS",
  "metrics": {
    "latency_ms": 1420,
    "throughput_tokens_sec": 74.5,
    "model_utilized": "gemini-3.5-flash",
    "pipeline": "High-Speed Triage Scanner"
  },
  "security_verdict": {
    "vulnerabilidade": "Path Traversal Arbitrary File Write",
    "severidade": "CRITICAL",
    "cwe_id": "CWE-22",
    "patch_correct": true,
    "confianca": 0.98,
    "status": "confirmado"
  }
}
```

---

## 🚀 Configuração, Inicialização e Instalação

### Pré-requisitos
*   Node.js v18.0.0 ou superior.
*   NPM (gerenciador de pacotes padrão).

### Instalação e Desenvolvimento Local

1.  Clone este repositório de engenharia corporativa:
    ```bash
    git clone https://github.com/ana-caroline-lamas/bancada-prompt.git
    cd bancada-prompt
    ```

2.  Instale as dependências estruturadas:
    ```bash
    npm install
    ```

3.  Configure as variáveis de ambiente baseadas no `.env.example`:
    ```bash
    cp .env.example .env
    ```
    *Preencha a variável `GEMINI_API_KEY` com suas credenciais de produção.*

4.  Inicie o servidor de desenvolvimento local:
    ```bash
    npm run dev
    ```
    O console abrirá a aplicação em [http://localhost:3000](http://localhost:3000) de forma isolada.

5.  Compilação e build de produção:
    ```bash
    npm run build
    ```
    A build estática é gerada na pasta `dist/` pronta para ser servida em instâncias de CDN de alto desempenho ou empacotada em containers AWS ECS/Fargate de forma imutável.

---

> **Aviso de Isenção de Responsabilidade (Disclaimer)**: Este software executa análise estática de código e simulações com o propósito de blindagem de infraestrutura corporativa e treinamento defensivo. O uso em auditorias de sistemas terceiros deve seguir estritamente as políticas éticas de divulgação responsável.
