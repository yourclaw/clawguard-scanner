export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanStatus =
	| "passed"
	| "warning"
	| "failed"
	| "blocked"
	| "error";

export type TrustLevel = "verified" | "scanned" | "unscanned" | "blocked";

export type Recommendation =
	| "install"
	| "install_with_warning"
	| "block"
	| "prompt_user";

export interface Finding {
	id: string;
	name: string;
	severity: Severity;
	category: string;
	message: string;
	scanner: string;
	evidence?: string;
	lineNumber?: number;
	filePath?: string;
	reason?: string;
}

export interface SkillMetadata {
	name: string;
	slug: string;
	description?: string;
	author?: string;
	version?: string;
	permissions?: string[];
	urls?: string[];
	mcpReferences?: string[];
	referencesMCP: boolean;
	scriptFiles?: string[];
	rawContent: string;
	filePath: string;
}

export interface ScannerResult {
	scanner: string;
	status: "success" | "skipped" | "error";
	findings: Finding[];
	message?: string;
	durationMs: number;
	/** Raw scanner output log (stdout + stderr), GitHub Actions style */
	logs?: string;
}

export interface ScanReport {
	skill: SkillMetadata;
	findings: Finding[];
	scanners: ScannerResult[];
	score: SeverityScore;
	status: ScanStatus;
	recommendation: Recommendation;
	scannedAt: string;
	durationMs: number;
	/** Findings that were suppressed by a .clawguard-ignore file */
	suppressed?: Finding[];
	/** Number of findings suppressed */
	suppressionCount?: number;
}

export interface SeverityScore {
	total: number; // 0-100, lower is safer
	critical: number;
	high: number;
	medium: number;
	low: number;
	info: number;
}

export interface FindingsCounts {
	critical: number;
	high: number;
	medium: number;
	low: number;
	info: number;
}

export interface Suppression {
	id: string;
	rule: string;
	file: string;
	scanner: string;
	justification: string;
	addedBy: string;
	addedAt: string;
	/** URL to the PR or issue that discovered this false positive (for audit trail) */
	reference?: string;
}
