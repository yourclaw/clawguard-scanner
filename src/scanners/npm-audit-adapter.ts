import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding, ScannerResult, Severity } from "../types";
import { isCommandAvailable, runCommand, formatLogs } from "./utils";

interface NpmAuditAdvisory {
	name: string;
	severity: string;
	title: string;
	url: string;
	id: number;
	overview?: string;
}

interface NpmAuditResult {
	advisories?: Record<string, NpmAuditAdvisory>;
	vulnerabilities?: Record<
		string,
		{
			name: string;
			severity: string;
			via: Array<{ title?: string; url?: string }>;
		}
	>;
}

function mapNpmSeverity(sev: string): Severity {
	switch (sev.toLowerCase()) {
		case "critical":
			return "critical";
		case "high":
			return "high";
		case "moderate":
			return "medium";
		case "low":
			return "low";
		default:
			return "info";
	}
}

/**
 * Run npm audit on skill directory if it has a package.json.
 * Gracefully skips if npm is not available or no package.json exists.
 */
export async function scanNpmAudit(
	skillPath: string,
): Promise<ScannerResult> {
	const start = Date.now();

	const packageJsonPath = join(skillPath, "package.json");
	if (!existsSync(packageJsonPath)) {
		return {
			scanner: "npm-audit",
			status: "skipped",
			findings: [],
			message: "No package.json found — skipping npm audit",
			durationMs: Date.now() - start,
			logs: `No package.json found at ${packageJsonPath}\nSkipping npm audit.`,
		};
	}

	const available = await isCommandAvailable("npm");
	if (!available) {
		return {
			scanner: "npm-audit",
			status: "skipped",
			findings: [],
			message: "npm not available — skipping audit",
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "which",
				args: ["npm"],
				durationMs: Date.now() - start,
				error: "npm not found in PATH",
			}),
		};
	}

	const args = ["audit", "--json", "--prefix", skillPath];

	try {
		const result = await runCommand("npm", args);

		let parsed: NpmAuditResult;
		try {
			parsed = JSON.parse(result.stdout) as NpmAuditResult;
		} catch {
			return {
				scanner: "npm-audit",
				status: "success",
				findings: [],
				durationMs: Date.now() - start,
				logs: formatLogs({
					command: "npm",
					args,
					stdout: result.stdout,
					stderr: result.stderr,
					durationMs: Date.now() - start,
					exitCode: 0,
				}),
			};
		}

		const findings: Finding[] = [];

		// npm v7+ format (vulnerabilities)
		if (parsed.vulnerabilities) {
			for (const [name, vuln] of Object.entries(parsed.vulnerabilities)) {
				const firstVia = vuln.via?.[0];
				findings.push({
					id: `NPM-${name}`,
					name: firstVia?.title ?? `Vulnerability in ${name}`,
					severity: mapNpmSeverity(vuln.severity),
					category: "dependencies",
					message: firstVia?.title ?? `Security issue in ${name}`,
					scanner: "npm-audit",
					evidence: name,
				});
			}
		}

		// npm v6 format (advisories)
		if (parsed.advisories) {
			for (const advisory of Object.values(parsed.advisories)) {
				findings.push({
					id: `NPM-${advisory.id}`,
					name: advisory.title,
					severity: mapNpmSeverity(advisory.severity),
					category: "dependencies",
					message: advisory.overview ?? advisory.title,
					scanner: "npm-audit",
					evidence: advisory.name,
				});
			}
		}

		return {
			scanner: "npm-audit",
			status: "success",
			findings,
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "npm",
				args,
				stdout: result.stdout,
				stderr: result.stderr,
				durationMs: Date.now() - start,
				exitCode: 0,
			}),
		};
	} catch (error) {
		// npm audit exits non-zero when vulnerabilities found
		const err = error as { stdout?: string; stderr?: string; exitCode?: number };
		if (err.stdout) {
			try {
				const parsed = JSON.parse(err.stdout) as NpmAuditResult;
				const findings: Finding[] = [];
				if (parsed.vulnerabilities) {
					for (const [name, vuln] of Object.entries(parsed.vulnerabilities)) {
						findings.push({
							id: `NPM-${name}`,
							name: `Vulnerability in ${name}`,
							severity: mapNpmSeverity(vuln.severity),
							category: "dependencies",
							message: `Security issue in ${name}`,
							scanner: "npm-audit",
							evidence: name,
						});
					}
				}
				return {
					scanner: "npm-audit",
					status: "success",
					findings,
					durationMs: Date.now() - start,
					logs: formatLogs({
						command: "npm",
						args,
						stdout: err.stdout,
						stderr: err.stderr,
						durationMs: Date.now() - start,
						exitCode: err.exitCode,
					}),
				};
			} catch {
				// Fall through
			}
		}

		return {
			scanner: "npm-audit",
			status: "error",
			findings: [],
			message: `npm audit error: ${error instanceof Error ? error.message : String(error)}`,
			durationMs: Date.now() - start,
			logs: formatLogs({
				command: "npm",
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
