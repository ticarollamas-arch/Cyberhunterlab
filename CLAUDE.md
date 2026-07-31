# CLAUDE.md

Guidance for Claude / AI assistants working on this repository.

## Project summary

**GitHub Project Forge AI — Cyber Hunter Lab** is a single-page React 19 + Vite + TypeScript
application that runs client-side security-analysis workflows against Google Gemini. The user
supplies their own Gemini API key (BYOK), which is stored in `sessionStorage` and passed
directly to `@google/genai` from the browser — there is no application backend.

Alongside the SPA, the repo ships two auxiliary pieces that share the "Cyber Hunter Lab" brand
but are not wired into the Vite build:

- `cyber_hunter_lab_cli.py`, `cyber_engine_json.py` — standalone Python CLI report generators
  (Rich TUI, no runtime deps on the React app).
- `cwe22-academy/` — a separate `backend/` + `frontend/` scaffold used as reference material
  by the in-app CWE-22 Academy module. Do not assume the SPA imports from it.

## Directory map

```
/                              root SPA (Vite + React 19 + Tailwind v4)
  index.html                   Vite entrypoint, mounts /src/main.tsx
  vite.config.ts               React + Tailwind + javascript-obfuscator plugin
  src/main.tsx                 React root, StrictMode
  src/App.tsx                  Monolithic top-level UI (~900 lines, all views, all routing)
  src/types.ts                 Domain types (AnalysisResult, VerificationResult, SecurityAnalysis)
  src/services/gemini.ts       Sole Gemini adapter: analyzePatch() with fallback + retry
  src/lib/apiKey.tsx           ApiKeyProvider React context (session-scoped BYOK + model choice)
  src/lib/utils.ts             cn() = clsx + tailwind-merge
  src/components/              Feature modules — each file is a large self-contained view
    AgenticPipeline.tsx        Multi-step agentic scan flow
    AnalysisDashboard.tsx      Result rendering for analyzePatch output
    CWE22Academy.tsx           Educational path-traversal lab
    OSSVRPScopeGenerator.tsx   Google OSS VRP scope report (largest module)
    OSVSchemaModule.tsx        OSV.dev schema tooling
    ReverseArchEngine.tsx      Reverse-architecture analyzer
    UniversalReportGenerator.tsx  Freeform report writer
    VRPResourceHub.tsx         Static reference hub
    LandingPage.tsx / LoginPage.tsx / ApiKeySetup.tsx / CodeInput.tsx / MethodologyCard.tsx
    ui/Badge.tsx               Only shared primitive today
  cwe22-academy/               Independent reference bundle (NOT imported by src/)
  cyber_hunter_lab_cli.py      Python CLI (Rich)
  cyber_engine_json.py         Python JSON emitter
```

`src/App.tsx` is intentionally the single source of view routing and top-level state (persisted
to `localStorage` under `validator_*` and `lab_started` keys). Prefer extending it and its
component files over introducing a router.

## How to run

```bash
npm install
cp .env.example .env           # sets GEMINI_API_KEY (build-time default) and APP_URL
npm run dev                    # vite --port=3000 --host=0.0.0.0
npm run build                  # vite build (writes /dist, obfuscated in prod mode)
npm run preview                # serve the built /dist
npm run lint                   # tsc --noEmit — the only checker in CI
npm run clean                  # rm -rf dist
```

`GEMINI_API_KEY` in `.env` is injected via Vite's `define` (`process.env.GEMINI_API_KEY`) as a
build-time default; the actual runtime key almost always comes from the in-app `ApiKeySetup`
modal, which writes to `sessionStorage['gemini_api_key']`. Treat the env var as a fallback
only. There are no Node/Express processes or `npm start` — this app is pure static output.

## Gemini integration rules

`src/services/gemini.ts` is the only call site. Preserve these behaviors when editing:

- **Model selection:** default `gemini-3.5-flash` for high-speed triage;
  `gemini-3.1-pro-preview` when `useThinking` is set; verification pass always runs on
  `gemini-flash-latest`. User override comes through `useApiKey().selectedModel` and is
  restricted by the `GeminiModel` union in `src/lib/apiKey.tsx`.
- **Automatic 403 → flash fallback:** on `PERMISSION_DENIED` errors from a non-flash model,
  swap `currentModel` to `gemini-flash-latest` and retry immediately (no backoff).
- **Rate-limit (429) retry:** linear backoff `1000 * (i + 1)` ms, `maxRetries = 2`.
- **Structured output:** every call uses `responseMimeType: "application/json"` plus a
  `responseSchema` that mirrors the `AnalysisResult` / `VerificationResult` types. Do not
  loosen the schema; add fields on both the type and the schema together.
- **Verification skipped in fast mode:** if `useThinking` is false, `analyzePatch` returns
  `{ analysis, verification: undefined }` and never runs the second pass. Keep it that way
  unless a task explicitly asks for it.
- **BYOK ordering:** the per-call `userApiKey` argument wins over `process.env.GEMINI_API_KEY`.
- **HTTP header:** always include `User-Agent: 'aistudio-build'` on the `GoogleGenAI` client.

Report/system prompts live inline in `gemini.ts` as `SYSTEM_INSTRUCTION_*` constants. They
carry hard requirements (report language, "no AI slop", section titles) — edit surgically and
keep the section structure documented in the strings.

## Build hardening

`vite.config.ts` runs `vite-plugin-javascript-obfuscator` on the production build (`apply:
'build'`) with control-flow flattening, dead-code injection, debug-protection, and base64
string arrays. Do not turn these off casually — this is a shipping requirement, not a
debugging aid. When investigating a `dist/` issue, run `vite build --mode development` or
temporarily bypass the plugin locally rather than committing the flag change.

## Conventions and gotchas

- **TypeScript:** strict-ish `tsconfig.json` (target ES2022, `moduleResolution: bundler`,
  `noEmit`, `allowImportingTsExtensions`, path alias `@/* → ./*`). Do not add a build step
  for TS — Vite handles it.
- **Styling:** Tailwind v4 via `@tailwindcss/vite`. No PostCSS config file; use utility
  classes inline, animate via `motion/react`. Shared `cn()` helper lives in `src/lib/utils.ts`.
- **Icons:** `lucide-react` only.
- **Persistence:** app state persists to `localStorage` under `validator_*`, `lab_started`,
  and `vrp_auth` keys. API key + model live in `sessionStorage` under `gemini_api_key` and
  `gemini_selected_model`. Reset paths must clear both.
- **HMR:** `server.hmr` is toggled off when `DISABLE_HMR=true`. AI Studio sets this to stop
  file-watcher flicker during agent edits — do not remove the guard.
- **Language:** UI copy is a mix of Portuguese (pt-BR) and English; report bodies generated by
  Gemini are English by contract. Match the surrounding file rather than translating.
- **Component size:** several `src/components/*.tsx` files are 30k–150k lines of JSX. Prefer
  narrow edits over refactors; do not split them into smaller files unless the task asks.
- **Comments and docs:** don't create new markdown files unless asked. `README.md` and
  `cwe22-academy/CWE22_Remediation_Guide.md` are the only docs today; keep it that way.

## Python / auxiliary code

`cyber_hunter_lab_cli.py` and `cyber_engine_json.py` are standalone. They optionally import
`rich` (fallback to plain print if missing) and take no dependency on `npm`. Do not add them
to the Vite build or `package.json`. `cwe22-academy/` has its own `backend/` and `frontend/`
trees — leave them independent unless a task explicitly ties them into the SPA.

## Working in this repo

- Development branch for automated work is `claude/claude-md-docs-xwac4u`; the default branch
  is `main`.
- `npm run lint` (== `tsc --noEmit`) is the only automated check. Run it before committing.
- There is no test runner in this repo — do not fabricate one; call out missing coverage
  in the PR body instead.
- When adding a new Gemini-backed view, wire it through `src/App.tsx`'s `view` union and
  reuse `analyzePatch` (or add a sibling function in `src/services/gemini.ts` with the same
  retry/fallback shape).
