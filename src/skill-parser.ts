import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, basename } from "node:path";
import { parse as parseYaml } from "yaml";
import type { SkillMetadata } from "./types";

// URL extraction regex
const URL_REGEX =
	/https?:\/\/[^\s"'`\])<>,;]+/gi;

// MCP reference patterns
const MCP_PATTERNS = [
	/mcp[-_]?server/gi,
	/mcp:\/\//gi,
	/\bmcp\b.*\bserver\b/gi,
	/stdio.*transport/gi,
	/sse.*transport/gi,
];

// Shell command patterns
const SHELL_PATTERNS = [
	/\b(?:exec|system|spawn|popen)\s*\(/gi,
	/\b(?:child_process|subprocess|os\.system)\b/gi,
	/`[^`]*(?:curl|wget|bash|sh|rm|chmod|kill)\s/gi,
	/\$\([^)]*(?:curl|wget|bash|sh)\b/gi,
];

// Sensitive file path patterns
const SENSITIVE_PATHS = [
	/~\/\.ssh\//gi,
	/~\/\.aws\//gi,
	/~\/\.gnupg\//gi,
	/\/etc\/(?:shadow|passwd)/gi,
	/\.env\b/gi,
	/~\/\.netrc/gi,
	/~\/\.npmrc/gi,
];

interface Frontmatter {
	name?: string;
	description?: string;
	author?: string;
	version?: string;
	permissions?: string | string[];
	[key: string]: unknown;
}

function parseFrontmatter(content: string): {
	frontmatter: Frontmatter;
	body: string;
} {
	const match = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/);
	if (!match) {
		return { frontmatter: {}, body: content };
	}
	try {
		const parsed = parseYaml(match[1]) as Frontmatter;
		return { frontmatter: parsed ?? {}, body: match[2] };
	} catch {
		return { frontmatter: {}, body: content };
	}
}

function extractUrls(content: string): string[] {
	const matches = content.match(URL_REGEX) ?? [];
	return [...new Set(matches)];
}

function detectMCPReferences(content: string): string[] {
	const refs: string[] = [];
	for (const pattern of MCP_PATTERNS) {
		pattern.lastIndex = 0;
		let match: RegExpExecArray | null;
		while (true) {
			match = pattern.exec(content);
			if (!match) break;
			refs.push(match[0]);
		}
	}
	return [...new Set(refs)];
}

function findScriptFiles(skillDir: string): string[] {
	const scripts: string[] = [];
	const extensions = [
		".js",
		".ts",
		".py",
		".sh",
		".bash",
		".rb",
		".pl",
		".mjs",
		".cjs",
	];

	try {
		const walk = (dir: string): void => {
			const entries = readdirSync(dir);
			for (const entry of entries) {
				if (entry === "node_modules" || entry === ".git") continue;
				const fullPath = join(dir, entry);
				try {
					const stat = statSync(fullPath);
					if (stat.isDirectory()) {
						walk(fullPath);
					} else if (extensions.some((ext) => entry.endsWith(ext))) {
						scripts.push(fullPath);
					}
				} catch {
					// Skip inaccessible files
				}
			}
		};
		walk(skillDir);
	} catch {
		// Directory might not exist or be readable
	}

	return scripts;
}

function slugify(name: string): string {
	return name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-|-$/g, "");
}

/**
 * Parse a skill directory, extracting metadata from SKILL.md and
 * discovering associated files.
 */
export function parseSkill(skillPath: string): SkillMetadata {
	const resolvedPath = resolve(skillPath);

	// Determine if this is a directory or a file
	let skillDir: string;
	let skillFile: string;

	try {
		const stat = statSync(resolvedPath);
		if (stat.isDirectory()) {
			skillDir = resolvedPath;
			skillFile = join(resolvedPath, "SKILL.md");
		} else {
			skillDir = resolve(resolvedPath, "..");
			skillFile = resolvedPath;
		}
	} catch {
		throw new Error(`Skill path not found: ${resolvedPath}`);
	}

	let rawContent: string;
	try {
		rawContent = readFileSync(skillFile, "utf-8");
	} catch {
		throw new Error(`Could not read skill file: ${skillFile}`);
	}

	const { frontmatter, body } = parseFrontmatter(rawContent);
	const urls = extractUrls(rawContent);
	const mcpReferences = detectMCPReferences(rawContent);
	const scriptFiles = findScriptFiles(skillDir);

	// Normalize permissions
	let permissions: string[] = [];
	if (Array.isArray(frontmatter.permissions)) {
		permissions = frontmatter.permissions.map(String);
	} else if (typeof frontmatter.permissions === "string") {
		permissions = [frontmatter.permissions];
	}

	const name =
		frontmatter.name ?? basename(skillDir) ?? basename(skillFile, ".md");

	return {
		name,
		slug: slugify(name),
		description: frontmatter.description
			? String(frontmatter.description)
			: undefined,
		author: frontmatter.author ? String(frontmatter.author) : undefined,
		version: frontmatter.version ? String(frontmatter.version) : undefined,
		permissions,
		urls,
		mcpReferences,
		referencesMCP: mcpReferences.length > 0,
		scriptFiles,
		rawContent,
		filePath: skillFile,
	};
}
