import type { Finding, ScannerResult, Severity } from "../types";
import { isCommandAvailable, runCommand, formatLogs } from "./utils";

interface SemgrepResult {
	results?: Array<{
		check_id: string;
		path: string;
		start: { line: number };
		extra: {
			message: string;
			severity: string;
			metadata?: {
				"clawguard-id"?: string;
				category?: string;
				cwe?: string;
			};
		};
	}>;
}

function mapSemgrepSeverity(sev: string): Severity {
	switch (sev.toUpperCase()) {
		case "ERROR":
			return "high";
		case "WARNING":
			return "medium";
		case "INFO":
			return "low";
		default:
			return "info";
	}
}

/**
 * Scan with semgrep using ClawGuard's custom rules.
 * Gracefully skips if semgrep is not installed.
 */
export async function scanWithSemgrep(
	skillPath: string,
	configPath?: string,
): Promise<ScannerResult> {
	const start = Date.now();

	const available = await isCommandAvailable("semgrep");
	if (!available) {
		return {
			scanner: "semgrep",
			status: "skipped",
			findings: [],
			message: "semgrep not installed — skipping custom SAST scan",
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "which",
				args: ["semgrep"],
				durationMs: Date.now() - start,
				error: "semgrep not found in PATH",
			}),
		};
	}

	try {
		const args = ["scan", "--json", "--quiet"];
		if (configPath) {
			args.push("--config", configPath);
		} else {
			args.push("--config", "auto");
		}
		args.push(skillPath);

		const result = await runCommand("semgrep", args, { timeout: 180_000 });

		let parsed: SemgrepResult;
		try {
			parsed = JSON.parse(result.stdout) as SemgrepResult;
		} catch {
			return {
				scanner: "semgrep",
				status: "success",
				findings: [],
				durationMs: Date.now() - start,
				logs: formatLogs({
					command: "semgrep",
					args,
					stdout: result.stdout,
					stderr: result.stderr,
					durationMs: Date.now() - start,
					exitCode: 0,
				}),
			};
		}

		const findings: Finding[] = (parsed.results ?? []).map((r) => ({
			id: r.extra.metadata?.["clawguard-id"] ?? r.check_id,
			name: r.check_id,
			severity: mapSemgrepSeverity(r.extra.severity),
			category: r.extra.metadata?.category ?? "code",
			message: r.extra.message,
			scanner: "semgrep",
			lineNumber: r.start.line,
			filePath: r.path,
		}));

		return {
			scanner: "semgrep",
			status: "success",
			findings,
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "semgrep",
				args,
				stdout: result.stdout,
				stderr: result.stderr,
				durationMs: Date.now() - start,
				exitCode: 0,
			}),
		};
	} catch (error) {
		const err = error as { stdout?: string; stderr?: string; exitCode?: number | string; killed?: boolean };
		const elapsed = Date.now() - start;
		const isTimeout = err.exitCode === null || err.exitCode === undefined || err.killed;
		const reason = isTimeout
			? `semgrep timed out after ${Math.round(elapsed / 1000)}s (limit: 180s)`
			: `semgrep error: ${error instanceof Error ? error.message : String(error)}`;
		return {
			scanner: "semgrep",
			status: "error",
			findings: [],
			message: reason,
			durationMs: elapsed,
			logs: formatLogs({
				command: "semgrep",
				args: ["scan", "--json", "--quiet", configPath ? `--config ${configPath}` : "--config auto", skillPath],
				stdout: err.stdout,
				stderr: err.stderr,
				durationMs: elapsed,
				exitCode: err.exitCode,
				error: reason,
			}),
		};
	}
}
