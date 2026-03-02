import { readFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import type { Finding, Suppression } from "./types";

const IGNORE_FILENAME = ".clawguard-ignore";

interface IgnoreFile {
	suppressions: Suppression[];
}

/**
 * Walk up from `startDir` looking for a `.clawguard-ignore` file.
 * Returns the absolute path if found, or undefined.
 */
function findIgnoreFile(startDir: string): string | undefined {
	let dir = resolve(startDir);

	// Walk up at most 20 levels to avoid infinite loops on weird file systems
	for (let i = 0; i < 20; i++) {
		const candidate = join(dir, IGNORE_FILENAME);
		if (existsSync(candidate)) {
			return candidate;
		}
		const parent = dirname(dir);
		if (parent === dir) {
			// Reached filesystem root
			break;
		}
		dir = parent;
	}

	return undefined;
}

/**
 * Load suppressions from a `.clawguard-ignore` JSON file.
 *
 * If `ignoreFilePath` is provided, it reads that file directly.
 * Otherwise, walks up from the current directory looking for `.clawguard-ignore`.
 *
 * Returns an empty array if no file is found or the file cannot be parsed.
 */
export function loadSuppressions(
	ignoreFilePath?: string,
	searchDir?: string,
): Suppression[] {
	const filePath = ignoreFilePath ?? findIgnoreFile(searchDir ?? process.cwd());

	if (!filePath) {
		return [];
	}

	try {
		const raw = readFileSync(filePath, "utf-8");
		const parsed = JSON.parse(raw) as IgnoreFile;

		if (!parsed.suppressions || !Array.isArray(parsed.suppressions)) {
			return [];
		}

		return parsed.suppressions;
	} catch {
		// File not found, not readable, or invalid JSON — silently return empty
		return [];
	}
}

/**
 * A finding is suppressed if there exists a suppression where:
 * - `suppression.rule` matches `finding.name` or `finding.id`
 * - AND `filePath` contains `suppression.file`
 */
function isSuppressed(
	finding: Finding,
	suppressions: Suppression[],
	filePath: string,
): boolean {
	return suppressions.some(
		(s) =>
			(s.rule === finding.name || s.rule === finding.id) &&
			filePath.includes(s.file),
	);
}

/**
 * Separate findings into active and suppressed based on suppressions.
 *
 * @param findings - All findings from scanners
 * @param suppressions - Suppressions loaded from `.clawguard-ignore`
 * @param filePath - The file path being scanned (used for `suppression.file` matching)
 * @returns Object with `findings` (active, not suppressed) and `suppressed` arrays
 */
export function filterFindings(
	findings: Finding[],
	suppressions: Suppression[],
	filePath: string,
): { findings: Finding[]; suppressed: Finding[] } {
	if (suppressions.length === 0) {
		return { findings, suppressed: [] };
	}

	const active: Finding[] = [];
	const suppressed: Finding[] = [];

	for (const finding of findings) {
		// Use the finding's own filePath if available, otherwise fall back to the
		// scan-level filePath (the skill path)
		const effectivePath = finding.filePath ?? filePath;

		if (isSuppressed(finding, suppressions, effectivePath)) {
			suppressed.push(finding);
		} else {
			active.push(finding);
		}
	}

	return { findings: active, suppressed };
}
