import type { ScanReport } from "../types";

const SEVERITY_TO_SARIF: Record<string, string> = {
	critical: "error",
	high: "error",
	medium: "warning",
	low: "note",
	info: "note",
};

/**
 * Format scan report as SARIF (Static Analysis Results Interchange Format).
 * Compatible with GitHub Code Scanning.
 */
export function formatSARIF(report: ScanReport): string {
	const sarif = {
		$schema:
			"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "ClawGuard",
						informationUri: "https://clawguard.sh",
						version: "0.1.0",
						rules: report.findings.map((f) => ({
							id: f.id,
							name: f.name,
							shortDescription: { text: f.message },
							defaultConfiguration: {
								level: SEVERITY_TO_SARIF[f.severity] ?? "warning",
							},
							properties: {
								category: f.category,
								severity: f.severity,
							},
						})),
					},
				},
				results: report.findings.map((f) => ({
					ruleId: f.id,
					level: SEVERITY_TO_SARIF[f.severity] ?? "warning",
					message: { text: f.message },
					locations: f.filePath
						? [
								{
									physicalLocation: {
										artifactLocation: { uri: f.filePath },
										region: f.lineNumber
											? { startLine: f.lineNumber }
											: undefined,
									},
								},
							]
						: [],
				})),
			},
		],
	};

	return JSON.stringify(sarif, null, 2);
}
