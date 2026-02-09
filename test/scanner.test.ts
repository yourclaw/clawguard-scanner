import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { scanSkill, parseSkill, scoreFindings, formatJSON, formatMarkdown } from "../src/index";
import type { Finding } from "../src/index";

const FIXTURES_DIR = resolve(__dirname, "..", "..", "clawguard-rules", "test-fixtures");

describe("Skill Parser", () => {
	it("should parse a benign skill with frontmatter", () => {
		const skill = parseSkill(resolve(FIXTURES_DIR, "benign", "memory-manager-skill"));
		expect(skill.name).toBe("memory-manager");
		expect(skill.slug).toBe("memory-manager");
		expect(skill.author).toBe("openclaw");
		expect(skill.version).toBe("1.2.3");
		expect(skill.permissions.length).toBeGreaterThan(0);
		expect(skill.rawContent).toBeTruthy();
	});

	it("should parse a malicious skill", () => {
		const skill = parseSkill(resolve(FIXTURES_DIR, "malicious", "data-exfiltration-skill"));
		expect(skill.name).toBe("helpful-data-sync");
		expect(skill.urls.length).toBeGreaterThan(0);
	});

	it("should throw for nonexistent path", () => {
		expect(() => parseSkill("/nonexistent/path")).toThrow();
	});
});

describe("Severity Scorer", () => {
	it("should score no findings as 0", () => {
		const score = scoreFindings([]);
		expect(score.total).toBe(0);
		expect(score.critical).toBe(0);
	});

	it("should score critical findings heavily", () => {
		const findings: Finding[] = [
			{
				id: "TEST-001",
				name: "Test",
				severity: "critical",
				category: "prompt-injection",
				message: "Critical issue",
				scanner: "test",
			},
		];
		const score = scoreFindings(findings);
		expect(score.total).toBeGreaterThan(30);
		expect(score.critical).toBe(1);
	});

	it("should weight prompt injection higher", () => {
		const piFindings: Finding[] = [
			{
				id: "PI-1",
				name: "PI",
				severity: "high",
				category: "prompt-injection",
				message: "Injection",
				scanner: "test",
			},
		];
		const codeFindings: Finding[] = [
			{
				id: "CODE-1",
				name: "Code",
				severity: "high",
				category: "code",
				message: "Code issue",
				scanner: "test",
			},
		];
		const piScore = scoreFindings(piFindings);
		const codeScore = scoreFindings(codeFindings);
		expect(piScore.total).toBeGreaterThan(codeScore.total);
	});

	it("should cap at 100", () => {
		const findings: Finding[] = Array.from({ length: 20 }, (_, i) => ({
			id: `TEST-${i}`,
			name: "Test",
			severity: "critical" as const,
			category: "malware",
			message: "Critical malware",
			scanner: "test",
		}));
		const score = scoreFindings(findings);
		expect(score.total).toBeLessThanOrEqual(100);
	});
});

describe("Full Scan (builtin only)", () => {
	it("should scan a malicious skill and find issues", async () => {
		const report = await scanSkill(
			resolve(FIXTURES_DIR, "malicious", "data-exfiltration-skill"),
			{ builtinOnly: true, skipAI: true },
		);

		expect(report.status).toBe("failed");
		expect(report.recommendation).toBe("block");
		expect(report.findings.length).toBeGreaterThan(0);
		expect(report.score.critical).toBeGreaterThan(0);
		expect(report.skill.name).toBe("helpful-data-sync");
	});

	it("should scan a benign skill with no findings", async () => {
		const report = await scanSkill(
			resolve(FIXTURES_DIR, "benign", "memory-manager-skill"),
			{ builtinOnly: true, skipAI: true },
		);

		expect(report.status).toBe("passed");
		expect(report.recommendation).toBe("install");
		expect(report.findings.length).toBe(0);
		expect(report.score.total).toBe(0);
	});

	it("should include scanner metadata", async () => {
		const report = await scanSkill(
			resolve(FIXTURES_DIR, "benign", "memory-manager-skill"),
			{ builtinOnly: true, skipAI: true },
		);

		expect(report.scanners.length).toBeGreaterThan(0);
		expect(report.scanners[0].scanner).toBe("clawguard-rules");
		expect(report.scannedAt).toBeTruthy();
		expect(report.durationMs).toBeGreaterThanOrEqual(0);
	});
});

describe("Reporters", () => {
	it("should format as JSON", async () => {
		const report = await scanSkill(
			resolve(FIXTURES_DIR, "malicious", "prompt-override-skill"),
			{ builtinOnly: true, skipAI: true },
		);
		const json = formatJSON(report);
		const parsed = JSON.parse(json);
		expect(parsed.skill.name).toBe("super-assistant");
		expect(parsed.status).toBe("failed");
		expect(parsed.findings.length).toBeGreaterThan(0);
	});

	it("should format as Markdown", async () => {
		const report = await scanSkill(
			resolve(FIXTURES_DIR, "malicious", "prompt-override-skill"),
			{ builtinOnly: true, skipAI: true },
		);
		const md = formatMarkdown(report);
		expect(md).toContain("# ClawGuard Security Report");
		expect(md).toContain("super-assistant");
		expect(md).toContain("FAILED");
	});
});
