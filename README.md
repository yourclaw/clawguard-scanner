# @yourclaw/clawguard-scanner

Security scanner orchestrator for AI agent skills. This package coordinates
multiple scanning tools in parallel, scores severity, and produces structured
reports.

---

## Installation

```bash
npm install @yourclaw/clawguard-scanner
```

For local development as part of the ClawGuard project:

```bash
cd ../clawguard && make setup
```

---

## Usage

### Programmatic

```typescript
import { scanSkill } from "@yourclaw/clawguard-scanner";

const report = await scanSkill("/path/to/skill", {
  builtinOnly: false,       // set true to skip external tools
  skipAi: true,             // skip AI review
  format: "json",           // json | markdown | sarif
});

console.log(report.status);        // "passed" | "warning" | "blocked"
console.log(report.severityScore); // 0-100
console.log(report.findings);      // Finding[]
```

### Via the CLI

```bash
npx @yourclaw/clawguard-cli scan /path/to/skill
npx @yourclaw/clawguard-cli scan /path/to/skill --builtin-only --skip-ai
npx @yourclaw/clawguard-cli scan /path/to/skill --format sarif
```

---

## Scanner Adapters

The scanner runs multiple tools in parallel using `Promise.allSettled` for
graceful degradation. If an external tool is not installed, that scanner is
skipped without failing the overall scan.

| Adapter | Tool | What it scans | Required? |
| ------- | ---- | ------------- | --------- |
| **Builtin Pattern Matcher** | `@yourclaw/clawguard-rules` | Prompt injection, secrets, malware, permissions | Built-in |
| **Gitleaks** | [gitleaks](https://github.com/gitleaks/gitleaks) | Hardcoded secrets & credentials | Optional |
| **Semgrep** | [semgrep](https://semgrep.dev) | Custom code patterns (eval, shell injection) | Optional |
| **MCP-Scan** | [mcp-scan](https://github.com/anthropics/mcp-scan) | MCP server configuration issues | Optional |
| **npm audit** | npm | Known CVEs in dependencies | Optional |
| **AI Review** | Claude API | Ambiguous cases needing judgement | Optional |

### Check which tools are installed

```bash
npx @yourclaw/clawguard-cli doctor
```

---

## Severity Scoring

Findings are scored on a **0–100 scale** with category-based multipliers:

| Category | Multiplier |
| -------- | ---------- |
| Prompt injection | 2.0x |
| Malware | 1.5x |
| Secrets | 1.2x |
| Permissions | 1.0x |

Individual severity weights:

| Severity | Points |
| -------- | ------ |
| critical | 25 |
| high | 15 |
| medium | 8 |
| low | 3 |

The final score is capped at 100.

### Score → Recommendation

| Score | Status | Recommendation |
| ----- | ------ | -------------- |
| 0 | `passed` | `install` |
| 1–30 | `warning` | `install_with_warning` |
| 31–70 | `warning` | `prompt_user` |
| 71+ | `blocked` | `block` |

---

## Report Formats

### JSON (`--format json`)

Full machine-readable report with all findings, metadata, and scores.

### Markdown (`--format markdown`)

Human-readable report suitable for GitHub issues or PR comments.

### SARIF (`--format sarif`)

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) format for integration
with GitHub Code Scanning, VS Code, and other SARIF-compatible tools.

---

## Key Types

```typescript
interface Finding {
  id: string;           // e.g. "PI-001"
  severity: "critical" | "high" | "medium" | "low";
  category: string;     // e.g. "prompt-injection"
  message: string;
  file?: string;
  line?: number;
  scanner: string;      // which adapter found it
}

interface ScanReport {
  status: "passed" | "warning" | "blocked";
  severityScore: number;
  recommendation: string;
  findings: Finding[];
  metadata: SkillMetadata;
  scannedAt: string;
}
```

---

## Development

```bash
# Install dependencies
npm install

# Run tests
npm run test:run        # single run
npm test                # watch mode

# Build
npm run build

# Lint
npm run lint
```

### Adding a new scanner adapter

1. Create `src/scanners/my-adapter.ts`.
2. Implement the adapter function returning `Finding[]`.
3. Use `isCommandAvailable()` from `utils.ts` for graceful skip.
4. Register in `src/orchestrator.ts` inside `scannerTasks`.
5. Add tests in `test/`.

---

## Makefile

```bash
make install    # npm install
make build      # tsup build
make test       # vitest run
make lint       # biome check
make clean      # remove dist/ and node_modules/
```

---

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
