import type { Finding, ScannerResult, Severity } from "../types";
import { isCommandAvailable, runCommand, formatLogs } from "./utils";

function mapSeverity(sev: string | undefined): Severity {
	switch (sev?.toLowerCase()) {
		case "critical":
			return "critical";
		case "high":
			return "high";
		case "medium":
			return "medium";
		case "low":
			return "low";
		default:
			return "info";
	}
}

/**
 * Scan a skill directory using mcp-scan's --skills mode.
 * This scans SKILL.md and related files for prompt injection, malware,
 * secrets, and other agent-specific vulnerabilities.
 *
 * Runs on ALL skills — not just MCP-referencing ones.
 * Gracefully skips if mcp-scan is not installed.
 */
export async function scanWithMcpScan(
	skillPath: string,
): Promise<ScannerResult> {
	const start = Date.now();

	const available = await isCommandAvailable("mcp-scan");
	if (!available) {
		return {
			scanner: "mcp-scan",
			status: "skipped",
			findings: [],
			message:
				"mcp-scan not installed — skipping skill scanning. Install with: pip install mcp-scan",
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "which",
				args: ["mcp-scan"],
				durationMs: Date.now() - start,
				error: "mcp-scan not found in PATH",
			}),
		};
	}

	const args = ["--skills", skillPath, "--json"];

	try {
		// Use --skills to scan the skill directory for agent-specific threats
		// mcp-scan does AI analysis so it needs a generous timeout
		const result = await runCommand("mcp-scan", args, { timeout: 300_000 });

		const findings = parseMcpScanOutput(result.stdout);

		return {
			scanner: "mcp-scan",
			status: "success",
			findings,
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "mcp-scan",
				args,
				stdout: result.stdout,
				stderr: result.stderr,
				durationMs: Date.now() - start,
				exitCode: 0,
			}),
		};
	} catch (error) {
		// mcp-scan exits non-zero when it finds issues — try to parse stdout
		const err = error as { stdout?: string; stderr?: string; exitCode?: number | string; killed?: boolean };
		const elapsed = Date.now() - start;

		if (err.stdout) {
			const findings = parseMcpScanOutput(err.stdout);
			if (findings.length > 0) {
				return {
					scanner: "mcp-scan",
					status: "success",
					findings,
					durationMs: elapsed,
					logs: formatLogs({
						command: "mcp-scan",
						args,
						stdout: err.stdout,
						stderr: err.stderr,
						durationMs: elapsed,
						exitCode: err.exitCode,
					}),
				};
			}
		}

		const isTimeout = err.exitCode === null || err.exitCode === undefined || err.killed;
		const reason = isTimeout
			? `mcp-scan timed out after ${Math.round(elapsed / 1000)}s (limit: 300s)`
			: `mcp-scan error: ${error instanceof Error ? error.message : String(error)}`;

		return {
			scanner: "mcp-scan",
			status: "error",
			findings: [],
			message: reason,
			durationMs: elapsed,
			logs: formatLogs({
				command: "mcp-scan",
				args,
				stdout: err.stdout,
				stderr: err.stderr,
				durationMs: elapsed,
				exitCode: err.exitCode,
				error: reason,
			}),
		};
	}
}

/**
 * Parse mcp-scan JSON output into findings.
 * The output is structured as: { "<path>": { issues: [...], labels: [...], ... } }
 */
function parseMcpScanOutput(stdout: string): Finding[] {
	const findings: Finding[] = [];
	try {
		const parsed = JSON.parse(stdout);

		// Handle the nested path structure: { "/tmp/path": { issues: [...] } }
		const entries = typeof parsed === "object" && !Array.isArray(parsed) ? Object.values(parsed) : [parsed];

		for (const entry of entries) {
			const entryObj = entry as Record<string, unknown>;

			// Extract issues from the entry (the actual mcp-scan format)
			const issues = (entryObj?.issues ?? []) as Array<Record<string, unknown>>;
			for (const issue of issues) {
				const code = (issue.code as string) ?? "UNKNOWN";
				const message = (issue.message as string) ?? "MCP issue detected";
				const extraData = issue.extra_data as Record<string, unknown> | null;
				const riskScore = extraData?.risk_score as number | undefined;
				const issueSeverity = (extraData?.severity as string) ?? (riskScore != null && riskScore >= 0.7 ? "high" : riskScore != null && riskScore >= 0.4 ? "medium" : "low");

				findings.push({
					id: `MCP-${code}`,
					name: code,
					severity: mapSeverity(issueSeverity),
					category: "mcp",
					message,
					scanner: "mcp-scan",
					evidence: extraData?.reason as string | undefined,
				});
			}

			// Also try flat array formats (findings/results)
			const flatItems = (entryObj?.findings ?? entryObj?.results ?? []) as Array<Record<string, unknown>>;
			for (const item of flatItems) {
				if (item.finding || item.issue || item.message || item.description) {
					findings.push({
						id: `MCP-${(item.id as string) ?? (item.rule_id as string) ?? "UNKNOWN"}`,
						name: (item.name as string) ?? (item.finding as string) ?? "MCP Security Issue",
						severity: mapSeverity(item.severity as string),
						category: (item.category as string) ?? "mcp",
						message: (item.description as string) ?? (item.message as string) ?? "MCP issue detected",
						scanner: "mcp-scan",
						evidence: (item.evidence as string) ?? (item.snippet as string),
						filePath: (item.file as string) ?? (item.filePath as string),
						lineNumber: (item.line as number) ?? (item.lineNumber as number),
					});
				}
			}
		}
	} catch {
		// Non-JSON output — mcp-scan may print status text when no issues found
	}
	return findings;
}
