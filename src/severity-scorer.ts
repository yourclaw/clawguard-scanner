import type { Finding, SeverityScore, ScanStatus, Recommendation } from "./types";

const SEVERITY_WEIGHTS: Record<string, number> = {
	critical: 25,
	high: 10,
	medium: 3,
	low: 1,
	info: 0,
};

// Prompt injection findings are weighted 2x (most dangerous for skills)
const CATEGORY_MULTIPLIERS: Record<string, number> = {
	"prompt-injection": 2.0,
	malware: 1.5,
	secrets: 1.0,
	permissions: 0.8,
	dependencies: 0.8,
};

/**
 * Calculate a composite severity score (0-100) from findings.
 * Lower = safer, higher = more dangerous.
 */
export function scoreFindings(findings: Finding[]): SeverityScore {
	const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

	let rawScore = 0;

	for (const finding of findings) {
		const sev = finding.severity;
		if (sev in counts) {
			counts[sev as keyof typeof counts]++;
		}

		const baseWeight = SEVERITY_WEIGHTS[sev] ?? 0;
		const categoryMultiplier = CATEGORY_MULTIPLIERS[finding.category] ?? 1.0;
		rawScore += baseWeight * categoryMultiplier;
	}

	// Cap at 100
	const total = Math.min(100, Math.round(rawScore));

	return {
		total,
		...counts,
	};
}

/**
 * Determine scan status based on the severity score and findings.
 */
export function determineScanStatus(score: SeverityScore): ScanStatus {
	if (score.critical > 0) return "failed";
	if (score.high >= 3) return "failed";
	if (score.high > 0 || score.medium >= 5) return "warning";
	if (score.total > 0) return "warning";
	return "passed";
}

/**
 * Generate a recommendation based on scan status.
 */
export function determineRecommendation(status: ScanStatus): Recommendation {
	switch (status) {
		case "passed":
			return "install";
		case "warning":
			return "install_with_warning";
		case "failed":
		case "blocked":
			return "block";
		case "error":
			return "prompt_user";
	}
}
