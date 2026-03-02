// Core scanner
export { scanSkill } from "./orchestrator";
export type { ScanOptions } from "./orchestrator";

// Skill parser
export { parseSkill } from "./skill-parser";

// Severity scoring
export {
	scoreFindings,
	determineScanStatus,
	determineRecommendation,
} from "./severity-scorer";

// Suppression / ignore support
export { loadSuppressions, filterFindings } from "./ignore";

// Reporters
export { formatJSON } from "./reporters/json";
export { formatMarkdown } from "./reporters/markdown";
export { formatSARIF } from "./reporters/sarif";

// Individual scanners (for advanced use)
export { scanPromptInjection } from "./scanners/prompt-injection";
export { scanWithGitleaks } from "./scanners/gitleaks-adapter";
export { scanWithSemgrep } from "./scanners/semgrep-adapter";
export { scanWithMcpScan } from "./scanners/mcp-scan-adapter";
export { scanNpmAudit } from "./scanners/npm-audit-adapter";
export { scanWithAI, hasAmbiguousFindings } from "./scanners/ai-review";

// Types
export type {
	Finding,
	ScanReport,
	ScannerResult,
	ScanStatus,
	Severity,
	SeverityScore,
	SkillMetadata,
	Suppression,
	TrustLevel,
	Recommendation,
	FindingsCounts,
} from "./types";
