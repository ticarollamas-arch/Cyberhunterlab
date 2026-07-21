# 👑 GitHub Project Forge AI
## Enterprise AI Application Generator & Open Source Repository Builder

```text
 ██████╗ ██╗████████╗██╗  ██╗██╗   ██╗██████╗     ██████╗ ██████╗  ██████╗      ██████╗███████╗ ██████╗████████╗
██╔════╝ ██║╚══██╔══╝██║  ██║██║   ██║██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗    ██╔════╝██╔════╝██╔════╝╚══██╔══╝
██║  ███╗██║   ██║   ███████║██║   ██║██████╔╝    ██████╔╝██████╔╝██║   ██║    ██║     █████╗  ██║        ██║   
██║   ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗    ██╔═══╝ ██╔══██╗██║   ██║    ██║     ██╔══╝  ██║        ██║   
╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██████╔╝    ██║     ██║  ██║╚██████╔╝    ╚██████╗███████╗╚██████╗   ██║   
 ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝     ╚═╝     ╚═╝  ╚═╝ ╚══════╝     ╚═════╝╚══════╝ ╚═════╝   ╚═╝   
                                                                                                            
                         ███████╗ ██████╗ ██████╗  ██████╗ ███████╗                                         
                         ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝                                         
                         █████╗  ██║   ██║██████╔╝██║  ███╗█████╗                                           
                         ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝                                           
                         ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗                                         
                         ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚══════╝╚══════╝                                         
```

> **Enterprise-Grade Vulnerability Remediation, Automated Repository Bootstrapping, and Secure Code Engineering Platform.**  
> *Uma suíte arquitetada sob os pilares SOLID, Clean Architecture e Práticas de Segurança Sênior para empacotar, validar e auditar aplicações com barramentos cognitivos e pipeline DevSecOps.*

---

## ⚡ Guia de Inicialização Rápida (Clone & Setup)

Selecione um dos métodos abaixo para clonar, remixar ou rodar a aplicação instantaneamente em seu ambiente de desenvolvimento local ou em containers:

### 1. Clonar o Repositório Oficial (Git CLI)
```bash
# Clone o repositório
git clone https://github.com/ana-caroline-lamas/bancada-prompt.git

# Acesse o diretório do projeto
cd bancada-prompt

# Instale as dependências com integridade garantida
npm install
```

### 2. Remixagem Inteligente e Sandbox Isolado
Caso deseje clonar e rodar o espaço de desenvolvimento de forma rápida com uma arquitetura pronta, você pode estender este projeto sem marcas d'água externas. Use nossa estrutura desacoplada para portar o motor completo para qualquer nuvem (AWS/GCP) ou orquestrador local.

---

## 🏗️ Visão Geral & Arquitetura de Software

Esta plataforma foi desenvolvida utilizando padrões modernos de **Engenharia de Software Corporativa**. A separação de responsabilidades assegura que as regras de domínio permaneçam isoladas de detalhes de implementação de terceiros (como bibliotecas de UI e adaptadores de IA).

### Camadas da Clean Architecture Integrada

```
                 ┌─────────────────────────────────────────────────────────┐
                 │                  1. CAMADA DE INTERFACE                 │
                 │     (React 19 SPA, Tailwind v4, Componentes Modulares)  │
                 └────────────────────────────┬────────────────────────────┘
                                              │ (Ações do Usuário & State)
                                              ▼
                 ┌─────────────────────────────────────────────────────────┐
                 │                 2. SERVIÇOS & ADAPTADORES               │
                 │     (Orquestradores de LLM, Sanitizadores de Input)     │
                 └────────────────────────────┬────────────────────────────┘
                                              │ (Tipagem Estrita)
                                              ▼
                 ┌─────────────────────────────────────────────────────────┐
                 │                 3. NÚCLEO DE DOMÍNIO (TYPES)            │
                 │     (Esquemas Zod, Definições de Modelos e Entidades)   │
                 └─────────────────────────────────────────────────────────┘
```

- **Enterprise App Generator (`/src/components`)**: Suítes altamente desacopladas que modularizam as visões de auditoria, simuladores de CI/CD e laboratórios interativos.
- **Cognitive Engines (`/src/services/gemini.ts`)**: Implementação de barramento sênior resiliente com suporte a múltiplos modelos em cascata, controle de circuit-breaker integrado, tratamento automático de erros de permissão (`403 PERMISSION_DENIED`) com fallback determinístico para `gemini-flash-latest` e mecanismo de retry inteligente contra limites de taxa (`429`).
- **Domain Model (`/src/types.ts`)**: Tipagem estrita que governa as fronteiras de dados sem dependência de dependências runtime externas.

---

## 🛡️ Alinhamento AWS Well-Architected & DevSecOps

O projeto incorpora os mais rigorosos preceitos de qualidade de código e segurança corporativa:

### 1. Segurança e Governança (Security-by-Design)
- **Zero-Trust Input Validation**: Garantias de validação estática de dados e tratamento de erros de execução de modelos cognitivos antes da persistência em cache.
- **Logical Sandbox Defenses**: Mitigações integradas para avaliar falhas complexas como **CWE-22 (Path Traversal)**, vazamentos cross-tenant e integridade de microsserviços.

### 2. Confiabilidade & Observabilidade SRE
- **Mecanismo de Circuit Breaker**: Proteção contra falhas transitórias e rate limiting nas requisições do motor cognitivo através de recuos exponenciais de tempo (*exponential backoff*).
- **Barramento de Log Estruturado**: Métricas de análise padronizadas em formato JSON otimizado para agregadores de telemetria como CloudWatch, AWS Athena e Datadog:
  ```json
  {
    "timestamp": "2026-07-21T13:00:00Z",
    "level": "INFO",
    "service": "project-forge-orchestrator",
    "metrics": {
      "latency_ms": 1150,
      "model_utilized": "gemini-flash-latest",
      "pipeline": "Automated Code Analysis Pipeline"
    },
    "verdict": {
      "status": "APPROVED",
      "remediation_applied": true
    }
  }
  ```

---

## 🛠️ Stack Tecnológica Enterprise

- **Core & Runtime**: Node.js, TypeScript 5.x (estrito e tipado).
- **Frontend SPA**: React 19, Vite (com exclusão nativa de redundâncias), Tailwind CSS v4 para velocidade extrema e fidelidade visual.
- **Build & Obfuscation**: Pipeline configurado para minificar e proteger de forma nativa regras proprietárias no build de distribuição estática (`dist/`).
- **CI/CD Integrado**: GitHub Workflows prontos para Linting de código, validações SAST (Static Application Security Testing) e compilação limpa.

---

## 🚀 Como Executar Localmente

### Variáveis de Ambiente (`.env`)
Copie o arquivo de exemplo de ambiente corporativo e declare as credenciais de sua infraestrutura:
```bash
cp .env.example .env
```
Defina sua chave de API para o motor de IA (`GEMINI_API_KEY`) para habilitar recursos analíticos de auditoria automática. O sistema está projetado para aceitar chaves em BYOK de forma segura e local (as chaves de API nunca são expostas ao browser ou ao console).

### Executar em Desenvolvimento
```bash
npm run dev
```
Acesse a aplicação localmente no endereço padrão [http://localhost:3000](http://localhost:3000).

### Compilar e Empacotar para Produção
```bash
npm run build
```
Os artefatos compilados e compactados são gerados no diretório `/dist` prontos para entrega estática de ultra alta velocidade por CDN (AWS CloudFront, Cloudflare, Fastly) ou containers empacotados.

---

## 📋 Roadmap do Repositório

- [x] Arquitetura desacoplada e Clean Architecture.
- [x] Barramento resiliente de IA com Circuit Breaker e Fallback automático (403/429 mitigation).
- [x] Simuladores de auditoria estática e laboratório ativo CWE-22.
- [ ] Integração ativa com exportadores remotos em formato ZIP e API GitHub nativa.
- [ ] Módulos adicionais para geração automatizada de diagramas de arquitetura estrutural em formato Mermaid.js.

---

## 📄 Licença & Governança

Este projeto é disponibilizado sob a licença **MIT**. O código e os modelos de integração gerados operam de forma isolada e autônoma, livres de dependências externas proprietárias ou marcas d'água de editores de terceiros.

---

> **Aviso de Divulgação Responsável**: As ferramentas cognitivas integradas neste repositório têm fins estritamente defensivos, educativos e corporativos para validação contra falhas lógicas e estruturação ágil de novas aplicações limpas no GitHub.
