import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

interface CommandResult {
	stdout: string;
	stderr: string;
}

/**
 * Format scanner output into a GitHub Actions-style log string.
 * Includes command, stdout, stderr, and timing.
 */
export function formatLogs(opts: {
	command: string;
	args: string[];
	stdout?: string;
	stderr?: string;
	durationMs: number;
	exitCode?: number | string;
	error?: string;
}): string {
	const lines: string[] = [];
	const ts = new Date().toISOString();

	lines.push(`[${ts}] $ ${opts.command} ${opts.args.join(" ")}`);

	if (opts.stdout?.trim()) {
		for (const line of opts.stdout.trim().split("\n")) {
			lines.push(line);
		}
	}

	if (opts.stderr?.trim()) {
		lines.push("");
		lines.push("::warning::stderr output:");
		for (const line of opts.stderr.trim().split("\n")) {
			lines.push(line);
		}
	}

	if (opts.error) {
		lines.push("");
		lines.push(`::error::${opts.error}`);
	}

	if (opts.exitCode !== undefined) {
		lines.push("");
		lines.push(`Process exited with code ${opts.exitCode}`);
	}

	lines.push(`Completed in ${opts.durationMs}ms`);

	return lines.join("\n");
}

/**
 * Check if a CLI command is available on the system.
 */
export async function isCommandAvailable(command: string): Promise<boolean> {
	try {
		const whichCmd = process.platform === "win32" ? "where" : "which";
		await execFileAsync(whichCmd, [command]);
		return true;
	} catch {
		return false;
	}
}

/**
 * Run a CLI command and return stdout/stderr.
 * Throws on non-zero exit code (with stdout/stderr attached to error).
 */
export async function runCommand(
	command: string,
	args: string[],
	options?: { timeout?: number; cwd?: string },
): Promise<CommandResult> {
	try {
		const result = await execFileAsync(command, args, {
			timeout: options?.timeout ?? 60000,
			cwd: options?.cwd,
			maxBuffer: 10 * 1024 * 1024, // 10MB
		});
		return {
			stdout: result.stdout ?? "",
			stderr: result.stderr ?? "",
		};
	} catch (error) {
		const err = error as {
			stdout?: string;
			stderr?: string;
			code?: number | string;
		};
		// Attach stdout/stderr to the error for callers that need it
		const enrichedError = new Error(
			`Command '${command}' failed: ${err.stderr ?? err.stdout ?? "unknown error"}`,
		) as Error & {
			stdout: string;
			stderr: string;
			exitCode: number | string | undefined;
		};
		enrichedError.stdout = err.stdout ?? "";
		enrichedError.stderr = err.stderr ?? "";
		enrichedError.exitCode = err.code;
		throw enrichedError;
	}
}
