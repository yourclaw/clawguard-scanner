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
| **MCP-Scan** | [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) | MCP server configuration issues | Optional |
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

## Suppressing Findings (`.clawguard-ignore`)

The scanner supports a `.clawguard-ignore` JSON file for suppressing known
false positives. Place it in your skill directory (or any parent directory) and
the scanner will automatically discover it by walking up the directory tree.

This feature was introduced to support the
[YourClaw OpenClaw fork](https://github.com/yourclaw/openclaw) upstream sync
pipeline, where automated scans of upstream releases can surface false positives
that need to be documented and suppressed transparently. See
[PR #4](https://github.com/yourclaw/openclaw/pull/4) for the initial set of
suppressions and the analysis behind each one.

You can also pass an explicit path via the `ignoreFile` option:

```typescript
const report = await scanSkill("/path/to/skill", {
  ignoreFile: "/path/to/.clawguard-ignore",
});

// Suppressed findings are still available for auditing
console.log(report.suppressed);        // Finding[] (what was filtered out)
console.log(report.suppressionCount);  // number
```

### File format

```json
{
  "suppressions": [
    {
      "id": "unique-id-for-this-suppression",
      "rule": "the-rule-name-or-finding-id",
      "file": "path/fragment/to/match",
      "scanner": "semgrep",
      "justification": "Why this is a false positive",
      "addedBy": "your-name",
      "addedAt": "2026-03-02",
      "reference": "https://github.com/your-org/your-repo/pull/123"
    }
  ]
}
```

### Field reference

| Field | Required | Description |
| ----- | -------- | ----------- |
| `id` | Yes | Unique identifier for this suppression entry |
| `rule` | Yes | Must match the finding's `name` or `id` field |
| `file` | Yes | Substring match against the finding's file path |
| `scanner` | Yes | Which scanner produced the finding (`semgrep`, `clawguard-rules`, `gitleaks`, etc.) |
| `justification` | Yes | Explanation of why this finding is a false positive |
| `addedBy` | Yes | Person or bot that added the suppression |
| `addedAt` | Yes | Date the suppression was added (ISO 8601 date) |
| `reference` | No | URL to the PR, issue, or discussion that discovered and analyzed the finding |

### Matching logic

A finding is suppressed when **both** conditions are true:

1. `suppression.rule` equals the finding's `name` **or** `id`
2. The finding's file path **contains** `suppression.file` as a substring

### Audit trail

Every suppression should include a `reference` URL pointing to the PR or issue
where the finding was discovered, analyzed, and confirmed as a false positive.
This creates a transparent audit trail so that anyone reviewing suppressions
can understand the full context behind each decision.

For automated pipelines (e.g. upstream sync workflows), the `reference` should
link to the sync PR that first flagged the finding — giving future reviewers a
direct path to the scan results, code analysis, and team discussion.

### When to suppress vs. when to fix

Use suppressions **only** for confirmed false positives — cases where the
scanner flags code that is actually safe. If a finding points to a real issue,
fix the code instead of suppressing it.

Good reasons to suppress:
- A `shell: true` flag is used safely with hardcoded arguments (no user input)
- A unicode escape sequence is used for data formatting, not obfuscation
- A regex pattern triggers a secrets scanner but is not an actual secret

Bad reasons to suppress:
- The finding is inconvenient to fix right now
- You disagree with the rule's severity (file an issue on the rule instead)

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

## Contributing

See the main [CONTRIBUTING.md](https://github.com/yourclaw/clawguard/blob/main/CONTRIBUTING.md)
for guidelines. The scanner is a great place to contribute new integrations —
each adapter is a self-contained file in `src/scanners/`.

---

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
