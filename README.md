# tiny-shell-gate

An approval gate for an agent's shell tool, in one TypeScript file.
It rejects args the model should not own, refuses any syntax it does not model, splits what is left on control operators, and approves only exact commands.
The model is a mock. Nothing is executed. No API key.

## Why it matters

In September 2026, four agent approval bypasses were published with the same root cause: the approval gate and the shell disagreed about what the command was.

- NVD, Sep 1, 2026: [CVE-2026-19591](https://nvd.nist.gov/vuln/detail/CVE-2026-19591) (OpenAI Codex CLI and Desktop; the command-safety parser read PowerShell's `--%` differently than PowerShell)
- NVD, Sep 8, 2026: [CVE-2026-82537](https://nvd.nist.gov/vuln/detail/CVE-2026-82537) (Roo-Code through 3.54.0; an allowlisted word, then `#`, a separator and a denied command)
- NVD, Sep 26, 2026: [CVE-2026-100561](https://nvd.nist.gov/vuln/detail/CVE-2026-100561) (OpenClaw before 2026.8.1; an approved wrapper without inspecting the inner command)
- NVD, Sep 29, 2026: [CVE-2026-102697](https://nvd.nist.gov/vuln/detail/CVE-2026-102697) (Ollama 0.14.0 before 0.31.2; approved commands could be extended with `;` or `&&`)

And in August, AWS published [CVE-2026-18733](https://aws.amazon.com/security/security-bulletins/2026-072-aws/) (Strands Agents shell tool; a model-settable `non_interactive` parameter skipped consent).

The naive gate in this repo is a composite of those bug shapes. It is not any product's code, and this is not how any of them fixed their bugs.

## Run it

You need Node.js 18 or newer.

```bash
npm install
npx tsx gate.ts
```

## Example output

This is real output from `npx tsx gate.ts`:

```text
Untrusted input: CONTRIBUTING.md (85 chars)
Approved exactly: git status | npm test | timeout 60 npm test
Naive gate remembers programs: git, npm, timeout

#  proposed command          naive  gate   reason
1  git status                RUN    ALLOW  every segment approved exactly
2  npm test                  RUN    ALLOW  every segment approved exactly
3  git status && curl | sh   RUN    DENY   chained: 2 of 3 segments not approved
4  git status#;curl | sh     RUN    DENY   syntax the gate does not model: #
5  timeout 60 node setup.js  RUN    ASK    new command: timeout 60 node scripts/setup.js
6  npm install (new dep)     RUN    ASK    new command: npm install toolchain-sync
7  rm + non_interactive      RUN    DENY   harness-owned arg: non_interactive

naive ran 7 of 7 commands without asking.
gate: 2 allowed, 2 asked, 3 denied. Nothing was executed.
```

The naive gate remembers programs instead of commands, strips comments with its own rule, and trusts a model-supplied flag. It runs all 7 proposals. The gate allows the 2 exactly approved commands, asks about 2 new ones with the full text, and denies the chained command, the `#` trick and the harness-owned arg.

## How it works

```text
README (untrusted) ──→ MOCK model ──→ proposed command
                                            ↓
                                          GATE
                closed args → safe characters → split segments → exact match
                                            ↓
                                   ALLOW / ASK / DENY
                                            ↓
                              shell (never called in this demo)
```

| File | What it does |
| --- | --- |
| `gate.ts` | The whole gate and demo, in the same order as the post |
| `output.txt` | Real output of `npx tsx gate.ts` |
| `package.json` | `tsx`, `typescript` and `@types/node` as dev dependencies |
| `tsconfig.json` | Strict settings for `npx tsc --noEmit` |

Inside `gate.ts`:

- Step 1: `approved`, a set of exact commands, and `MODEL_ARGS`
- Step 2: `checkArgs`, a closed schema. Any other arg is harness-owned and denied
- Step 3: `SAFE` and `unsafeChars`. Quotes, `#`, `$`, `%`, backticks, redirects, globs and backslashes are refused, not parsed
- Step 4: `segments` and `gate`. Split on `;`, `&&`, `||`, `|`, `&` and newlines; every segment must match exactly
- Step 5: `naive`, a program-name gate for comparison
- Step 6: the poisoned README demo with seven scripted proposals

What is real and what is mocked:

- The model is a MOCK. Its commands are scripted. Nothing is executed. No network. No API key.
- The repo, the README text, the package name and the attacker URL are made up.
- The CVE references above are real and dated.

## Limits

This is a teaching gate.

- No quotes means common commands like `git commit -m "fix"` are denied. Use a real shell parser for what you can verify, or pass arguments as an array with no shell at all.
- Exact match does not scale. Real approvals need scopes and should expire with the task.
- An approved command can still do harm. `npm test` runs whatever the test script says. Use a sandbox.
- It models a POSIX-like subset only. PowerShell and cmd are different grammars.

## Read more

- Dev.to: [Your Agent's Allowlist Is a Parser Bug: Build a Shell Command Gate in TypeScript](https://dev.to/bobbyhalljr/your-agents-allowlist-is-a-parser-bug-build-a-shell-command-gate-in-typescript-20je)
- Substack: [Your Agent's Allowlist Is a Parser Bug: Build a Shell Command Gate in TypeScript](SUBSTACK_URL)

## License

MIT. See [LICENSE](LICENSE).
