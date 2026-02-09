import type { Finding, ScannerResult } from "../types";
import { isCommandAvailable, runCommand, formatLogs } from "./utils";

interface GitleaksMatch {
	Description: string;
	File: string;
	StartLine: number;
	EndLine: number;
	Match: string;
	Secret: string;
	RuleID: string;
}

/**
 * Scan a skill directory using gitleaks for secret detection.
 * Gracefully skips if gitleaks is not installed.
 */
export async function scanWithGitleaks(
	skillPath: string,
): Promise<ScannerResult> {
	const start = Date.now();

	const available = await isCommandAvailable("gitleaks");
	if (!available) {
		return {
			scanner: "gitleaks",
			status: "skipped",
			findings: [],
			message: "gitleaks CLI not installed — skipping secret detection scan",
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "which",
				args: ["gitleaks"],
				durationMs: Date.now() - start,
				error: "gitleaks not found in PATH",
			}),
		};
	}

	const args = [
		"detect",
		"--source",
		skillPath,
		"--report-format",
		"json",
		"--report-path",
		"/dev/stdout",
		"--no-git",
	];

	try {
		const result = await runCommand("gitleaks", args);

		// gitleaks exits with code 1 if leaks are found
		let matches: GitleaksMatch[] = [];
		try {
			matches = JSON.parse(result.stdout) as GitleaksMatch[];
		} catch {
			// No JSON output means no leaks (or exit 0)
		}

		const findings: Finding[] = matches.map((m) => ({
			id: `GITLEAKS-${m.RuleID}`,
			name: m.Description,
			severity: "critical" as const,
			category: "secrets",
			message: `Secret detected: ${m.Description}`,
			scanner: "gitleaks",
			evidence: m.Secret ? `${m.Secret.substring(0, 8)}...` : undefined,
			lineNumber: m.StartLine,
			filePath: m.File,
		}));

		return {
			scanner: "gitleaks",
			status: "success",
			findings,
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "gitleaks",
				args,
				stdout: result.stdout,
				stderr: result.stderr,
				durationMs: Date.now() - start,
				exitCode: 0,
			}),
		};
	} catch (error) {
		// gitleaks returns exit code 1 when leaks are found
		const err = error as { stdout?: string; stderr?: string; exitCode?: number };
		if (err.exitCode === 1 && err.stdout) {
			try {
				const matches = JSON.parse(err.stdout) as GitleaksMatch[];
				const findings: Finding[] = matches.map((m) => ({
					id: `GITLEAKS-${m.RuleID}`,
					name: m.Description,
					severity: "critical" as const,
					category: "secrets",
					message: `Secret detected: ${m.Description}`,
					scanner: "gitleaks",
					evidence: m.Secret ? `${m.Secret.substring(0, 8)}...` : undefined,
					lineNumber: m.StartLine,
					filePath: m.File,
				}));
				return {
					scanner: "gitleaks",
					status: "success",
					findings,
					durationMs: Date.now() - start,
					logs: formatLogs({
						command: "gitleaks",
						args,
						stdout: err.stdout,
						stderr: err.stderr,
						durationMs: Date.now() - start,
						exitCode: 1,
					}),
				};
			} catch {
				// Fall through to error
			}
		}

		// Exit code 1 with no stdout = no leaks found (gitleaks quirk)
		if (err.exitCode === 1 && !err.stdout?.trim()) {
			return {
				scanner: "gitleaks",
				status: "success",
				findings: [],
				durationMs: Date.now() - start,
				logs: formatLogs({
					command: "gitleaks",
					args,
					stdout: err.stdout,
					stderr: err.stderr,
					durationMs: Date.now() - start,
					exitCode: 1,
				}),
			};
		}

		return {
			scanner: "gitleaks",
			status: "error",
			findings: [],
			message: `gitleaks error: ${error instanceof Error ? error.message : String(error)}`,
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "gitleaks",
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
