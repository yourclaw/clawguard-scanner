import { matchPatterns } from "@yourclaw/clawguard-rules";
import type { Finding, ScannerResult, SkillMetadata } from "../types";

/**
 * Scan a skill for prompt injection patterns using @yourclaw/clawguard-rules.
 * This is ClawGuard's core unique scanner — no external tool needed.
 */
export async function scanPromptInjection(
	skill: SkillMetadata,
): Promise<ScannerResult> {
	const start = Date.now();

	try {
		const ruleFindings = matchPatterns(skill.rawContent);
		const durationMs = Date.now() - start;

		const findings: Finding[] = ruleFindings.map((f) => ({
			id: f.id,
			name: f.name,
			severity: f.severity,
			category: f.category,
			message: f.reason,
			scanner: "clawguard-rules",
			evidence: f.matchedText,
			lineNumber: f.lineNumber,
			filePath: skill.filePath,
			reason: f.reason,
		}));

		const logLines: string[] = [];
		const ts = new Date().toISOString();
		logLines.push(`[${ts}] Running @yourclaw/clawguard-rules pattern matcher`);
		logLines.push(`Scanning: ${skill.filePath}`);
		logLines.push(`Content length: ${skill.rawContent.length} chars`);
		logLines.push(`Patterns matched: ${ruleFindings.length}`);
		if (ruleFindings.length > 0) {
			for (const f of ruleFindings) {
				logLines.push(`  [${f.severity}] ${f.id}: ${f.reason}`);
			}
		}
		logLines.push(`Completed in ${durationMs}ms`);

		return {
			scanner: "clawguard-rules",
			status: "success",
			findings,
			durationMs,
			logs: logLines.join("\n"),
		};
	} catch (error) {
		const durationMs = Date.now() - start;
		const ts = new Date().toISOString();
		return {
			scanner: "clawguard-rules",
			status: "error",
			findings: [],
			message: `Error scanning with ClawGuard rules: ${error instanceof Error ? error.message : String(error)}`,
			durationMs,
			logs: `[${ts}] Running @yourclaw/clawguard-rules pattern matcher\n::error::${error instanceof Error ? error.message : String(error)}\nCompleted in ${durationMs}ms`,
		};
	}
}
