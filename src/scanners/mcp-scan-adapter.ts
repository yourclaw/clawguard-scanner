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
		const result = await runCommand("mcp-scan", args);

		const findings: Finding[] = [];
		try {
			const parsed = JSON.parse(result.stdout);

			// mcp-scan --skills outputs skill analysis results
			// Handle array of findings or object with findings/issues
			const items = Array.isArray(parsed)
				? parsed
				: parsed.findings ?? parsed.issues ?? parsed.results ?? [];

			for (const item of items) {
				if (item.finding || item.issue || item.message || item.description) {
					findings.push({
						id: `MCP-${item.id ?? item.rule_id ?? "UNKNOWN"}`,
						name: item.name ?? item.finding ?? item.title ?? "MCP Security Issue",
						severity: mapSeverity(item.severity),
						category: item.category ?? "mcp",
						message:
							item.description ?? item.message ?? item.finding ?? "MCP issue detected",
						scanner: "mcp-scan",
						evidence: item.evidence ?? item.snippet,
						filePath: item.file ?? item.filePath,
						lineNumber: item.line ?? item.lineNumber,
					});
				}
			}
		} catch {
			// Non-JSON output — mcp-scan may print status text when no issues found
		}

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
		// mcp-scan exits non-zero when it finds issues — parse stdout
		const err = error as { stdout?: string; stderr?: string; exitCode?: number };
		if (err.stdout) {
			try {
				const parsed = JSON.parse(err.stdout);
				const items = Array.isArray(parsed)
					? parsed
					: parsed.findings ?? parsed.issues ?? parsed.results ?? [];

				const findings: Finding[] = items
					.filter(
						(item: Record<string, unknown>) =>
							item.finding || item.issue || item.message || item.description,
					)
					.map((item: Record<string, unknown>) => ({
						id: `MCP-${(item.id as string) ?? (item.rule_id as string) ?? "UNKNOWN"}`,
						name:
							(item.name as string) ??
							(item.finding as string) ??
							(item.title as string) ??
							"MCP Security Issue",
						severity: mapSeverity(item.severity as string),
						category: (item.category as string) ?? "mcp",
						message:
							(item.description as string) ??
							(item.message as string) ??
							(item.finding as string) ??
							"MCP issue detected",
						scanner: "mcp-scan",
						evidence: (item.evidence as string) ?? (item.snippet as string),
						filePath: (item.file as string) ?? (item.filePath as string),
						lineNumber: (item.line as number) ?? (item.lineNumber as number),
					}));

				if (findings.length > 0) {
					return {
						scanner: "mcp-scan",
						status: "success",
						findings,
						durationMs: Date.now() - start,
						logs: formatLogs({
							command: "mcp-scan",
							args,
							stdout: err.stdout,
							stderr: err.stderr,
							durationMs: Date.now() - start,
							exitCode: err.exitCode,
						}),
					};
				}
			} catch {
				// Fall through
			}
		}

		return {
			scanner: "mcp-scan",
			status: "error",
			findings: [],
			message: `mcp-scan error: ${error instanceof Error ? error.message : String(error)}`,
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "mcp-scan",
				args,
				stdout: err.stdout,
				stderr: err.stderr,
				durationMs: Date.now() - start,
				exitCode: err.exitCode,
				error: error instanceof Error ? error.message : String(error),
			}),
		};
	}
}
