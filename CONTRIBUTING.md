# Contributing to ClawGuard Scanner

The scanner orchestrator coordinates multiple security tools in parallel. This
is a great place to contribute new scanner integrations.

For full contributing guidelines (setup, coding standards, PR process), see the
main [CONTRIBUTING.md](https://github.com/yourclaw/clawguard/blob/main/CONTRIBUTING.md).

---

## Adding a Scanner Adapter

1. Create `src/scanners/my-adapter.ts`.

2. Implement the adapter — it should:
   - Check if the external tool is available (use `isCommandAvailable()` from `utils.ts`)
   - Run the tool against the skill path
   - Parse output into `Finding[]`
   - Return an empty array if the tool is not installed (graceful skip)

3. Register your adapter in `src/orchestrator.ts` inside the `scannerTasks` array.

4. Add tests in `test/`.

5. Submit a PR.

See existing adapters in `src/scanners/` for examples (e.g., `gitleaks-adapter.ts`,
`semgrep-adapter.ts`).
