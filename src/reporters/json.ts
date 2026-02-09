import type { ScanReport } from "../types";

/**
 * Format scan report as JSON (machine-readable).
 */
export function formatJSON(report: ScanReport): string {
	return JSON.stringify(
		{
			skill: {
				name: report.skill.name,
				slug: report.skill.slug,
				description: report.skill.description,
				author: report.skill.author,
				version: report.skill.version,
				filePath: report.skill.filePath,
			},
			status: report.status,
			recommendation: report.recommendation,
			score: report.score,
			findings: report.findings.map((f) => ({
				id: f.id,
				name: f.name,
				severity: f.severity,
				category: f.category,
				message: f.message,
				scanner: f.scanner,
				evidence: f.evidence,
				lineNumber: f.lineNumber,
				filePath: f.filePath,
			})),
			scanners: report.scanners.map((s) => ({
				scanner: s.scanner,
				status: s.status,
				findingCount: s.findings.length,
				message: s.message,
				durationMs: s.durationMs,
			})),
			scannedAt: report.scannedAt,
			durationMs: report.durationMs,
		},
		null,
		2,
	);
}
