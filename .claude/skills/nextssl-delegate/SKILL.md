---
name: nextssl-delegate
description: Three-tier delegation for NextSSL work — haiku finds, sonnet verifies, opus decides. Use before any NextSSL task that splits into searches, per-algorithm imports, KAT checks, bug hunts, binding boilerplate or bulk mechanical edits, to cut cost while keeping crypto-grade accuracy.
---

# NextSSL three-tier delegation

Opus (the main session) plans, owns security decisions and gives final sign-off.
Cheaper models do the volume. Nothing a subagent reports is true until the next tier checks it.

## Tier 1 — `haiku` (find, collect, run)
Use `Agent` with `model: "haiku"`, `subagent_type: "Explore"` (read-only) or `"general-purpose"` (needs to write/run).
- Locate files, symbols, upstream sources, license headers, KAT vector files
- List every place an algorithm, macro or prefix is used
- Run builds/tests in Docker and report raw output (exit codes, failing vectors)
- Bug hunting sweeps: one category or one directory per agent, report suspects with file:line
- Mechanical edits from an exact pattern: renames, header boilerplate, CMake entries, algo.json rows

## Tier 2 — `sonnet` (verify, implement well-specified pieces)
Use `model: "sonnet"`.
- Re-check every haiku finding: confirm or reject each suspect with evidence
- Import one algorithm from a named upstream file into its plugin folder, wire it to the registry, add its KAT test
- Write binding glue for one language from an existing binding as the pattern
- Write/extend tests, fuzz harnesses, docs drafts

## Tier 3 — `opus` (main session; never delegated)
- Architecture, API shape, output/encoding format, registry design
- Anything touching secrets: constant-time code, key handling, RNG/DRBG, `.root` vs safe tier boundary
- Choosing upstream sources and checking their license compatibility
- Release signing, download/revocation logic
- Final review of every diff and re-running the tests before calling anything done

## When to add a delegation (situations)
| Situation | Send to |
|---|---|
| "Where is X / which files use Y" across many dirs | haiku Explore |
| Import N algorithms of the same family | one sonnet per algorithm (parallel), haiku first to find sources |
| A test run or Docker build matrix | haiku runs, opus reads failures |
| Bug hunt over a category | haiku sweep → sonnet confirm → opus fixes or approves |
| New language binding | sonnet, pattern = existing binding |
| Unclear bug, design choice, security boundary | keep on opus |

## Rules
1. Brief must be self-contained: exact paths, the pattern file to copy, the upstream source URL/commit, what done looks like, what NOT to touch. Subagents have no conversation context.
2. Independent pieces go out as parallel Agent calls in one message. Two writers never touch the same file; give writers `isolation: "worktree"` when overlap is possible.
3. Never let a subagent hand-write crypto primitives. They copy from the named upstream only and keep its license file.
4. Opus reads the diff and re-runs the tests (KAT + sanitizer) itself. A report is a claim, not proof.
5. If a cheap model fails the same piece twice, escalate one tier; do not loop.

## Skip delegation when
The job is a few tool calls, the brief would be longer than the change, or it depends on context only the main conversation has.
