import type {
	Finding,
	ScanReport,
	ScannerResult,
	SkillMetadata,
} from "./types";
import { parseSkill } from "./skill-parser";
import {
	scoreFindings,
	determineScanStatus,
	determineRecommendation,
} from "./severity-scorer";
import { scanPromptInjection } from "./scanners/prompt-injection";
import { scanWithGitleaks } from "./scanners/gitleaks-adapter";
import { scanWithSemgrep } from "./scanners/semgrep-adapter";
import { scanWithMcpScan } from "./scanners/mcp-scan-adapter";
import { scanNpmAudit } from "./scanners/npm-audit-adapter";
import { scanWithAI, hasAmbiguousFindings } from "./scanners/ai-review";

export interface ScanOptions {
	/** Only run built-in scanners (no external tools) */
	builtinOnly?: boolean;
	/** Skip AI-assisted review */
	skipAI?: boolean;
	/** Timeout per scanner in milliseconds */
	scannerTimeout?: number;
	/** Custom semgrep config path */
	semgrepConfig?: string;
}

/**
 * Orchestrate all scanners against a skill, aggregate results into a ScanReport.
 * Uses Promise.allSettled so individual scanner failures don't block others.
 */
export async function scanSkill(
	skillPath: string,
	options: ScanOptions = {},
): Promise<ScanReport> {
	const start = Date.now();

	// Parse the skill first
	const skill = parseSkill(skillPath);

	// Always run our built-in scanner
	const scannerPromises: Array<Promise<ScannerResult>> = [
		scanPromptInjection(skill),
	];

	// External scanners (skip in builtin-only mode)
	if (!options.builtinOnly) {
		scannerPromises.push(
			scanWithGitleaks(skillPath),
			scanWithSemgrep(skillPath, options.semgrepConfig),
			scanWithMcpScan(skillPath),
			scanNpmAudit(skillPath),
		);
	}

	// Run all scanners in parallel
	const results = await Promise.allSettled(scannerPromises);

	// Collect results
	const scannerResults: ScannerResult[] = results.map((r, i) => {
		if (r.status === "fulfilled") {
			return r.value;
		}
		return {
			scanner: `scanner-${i}`,
			status: "error" as const,
			findings: [],
			message: `Scanner failed: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`,
			durationMs: 0,
		};
	});

	// Aggregate all findings
	let allFindings: Finding[] = scannerResults.flatMap((r) => r.findings);

	// AI review for ambiguous cases (optional)
	if (!options.skipAI && !options.builtinOnly && hasAmbiguousFindings(allFindings)) {
		const aiResult = await scanWithAI(skill, allFindings);
		scannerResults.push(aiResult);
		allFindings = allFindings.concat(aiResult.findings);
	}

	// Score and determine status
	const score = scoreFindings(allFindings);
	let status = determineScanStatus(score);

	// If a critical scanner errored, the scan is incomplete — don't mark as "passed"
	const CRITICAL_SCANNERS = new Set(["semgrep", "gitleaks"]);
	const hasCriticalError = scannerResults.some(
		(r) => r.status === "error" && CRITICAL_SCANNERS.has(r.scanner),
	);
	if (hasCriticalError && status === "passed") {
		status = "error";
	}

	const recommendation = determineRecommendation(status);

	return {
		skill,
		findings: allFindings,
		scanners: scannerResults,
		score,
		status,
		recommendation,
		scannedAt: new Date().toISOString(),
		durationMs: Date.now() - start,
	};
}
