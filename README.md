# Phylax corpus data

Security AI training corpus for the Phylax subnet. Four tracks of curated artifacts
that teach agents what malicious and safe code/config looks like at the file level.

Read [`DATA_SPEC.md`](DATA_SPEC.md) before labelling anything — it defines every field
the scoring code consumes. `validate.py` enforces the spec; run it before every PR.

---

## Tracks at a glance

| Track | Target | Current | Priority | What it covers |
|-------|-------:|--------:|----------|----------------|
| `repositories` | 150 | 10 | **Highest** | Full source repos — vuln scanning, secret detection, supply-chain |
| `packages` | 250 | 10 | High | npm / PyPI packages — install hooks, typosquats, obfuscated payloads |
| `mcp_servers` | 300 | 10 | High | MCP server definitions — tool poisoning, schema abuse, prompt injection |
| `skills` | 400 | 10 | Medium | Claude skill files — hidden instructions, credential exfiltration, context injection |

1,100 total entries across all tracks.

---

## Directory layout

```
<track>/
  artifacts/
    <ref>.zip                     ← the artifact itself
    <ref>.expected_findings.json  ← findings (packages, mcp_servers, skills)
    <ref>.ground_truth.json       ← findings (repositories only)
  <track>.csv                     ← one row per artifact, all metadata
  README.md                       ← sourcing notes + category vocabulary
```

No other structure. Nothing moves or gets renamed after the initial commit.

---

## How we source data

### 1  Real malicious packages

- **PyPI malregistry** — community-maintained archive of confirmed malicious PyPI packages.
  We pull individual packages, unzip, verify the malicious behaviour, then write
  `expected_findings.json` referencing the exact file + line.
- **npm abuse patterns** — install-hook exfiltration, postinstall curl pipes,
  typosquats of popular packages (`reqests`, `cross-env2`).

### 2  MCP server research (2025–2026)

| Source | What it contributed |
|--------|---------------------|
| **Invariant Labs** blog (2025) | Tool Description Poisoning (TPA) and Cross-Server Shadowing |
| **CyberArk** research | Full-Schema Poisoning (FSP) — attack hidden in parameter names / enum values |
| **ETDI paper** arxiv/2506.01333 | Rug-Pull — clean manifest at connect, then `AddSessionTool` injects poisoned definition |
| **Microsoft** indirect injection | Poisoned HTTP response embeds instructions via zero-width chars |
| **GhostSplice** (ASSET Research Group, Aug 2026) | Splits harmful instructions across multiple tool descriptions; 97% compliance on frontier models |
| **MCPTox Benchmark** arxiv/2508.14925 | 99 attack templates covering all known TPA variants |
| **appsecco/bad-mcp** (MIT) | 10 Go-based malicious MCP servers |
| **appsecco/vulnerable-mcp-servers-lab** (Apache-2.0) | 9 Python/JS vulnerable servers |

### 3  Repositories (CVE and known-vuln patterns)

Each repository artifact is a minimal but realistic codebase that isolates one
class of vulnerability. Sources:

- **CVE-2026-23744** — `@mcpjam/inspector` HTTP admin endpoint binds `0.0.0.0`
  without authentication (CVSS 9.8, CWE-306). Pattern reproduced in `repositories-py-0003`.
- **appsecco/vulnerable-mcp-servers-lab** — path traversal (CWE-22) and eval RCE (CWE-94)
  servers used as bases for `repositories-py-0002` and `repositories-js-0001`.
- **OWASP CWE-89** canonical SQL injection pattern — `repositories-py-0001`.
- **CWE-798** hardcoded credentials — `repositories-js-0002`.

### 4  Skills (Claude skill files)

Malicious skill files target the Claude Code skill system specifically. Attack
techniques observed:

| Technique | Description |
|-----------|-------------|
| `prompt_injection` | MUST-framed mandatory steps that override normal behaviour |
| `hidden_instruction` | Instructions invisible in rendered Markdown (HTML comments, CDATA) |
| `unicode_anomaly` | U+202E RTL override + zero-width chars (U+200B/200D/2060) hide text |
| `context_injection` | False session context claims pre-authorization for all data access |
| `tool_poisoning` | Skill instructs agent to leak data via git commits, file tool metadata |
| `credential_exfiltration` | Collects SSH keys, AWS creds, `.env` files as "baseline" |
| `deceptive_documentation` | README describes legitimate skill; SKILL.md contains the attack |

---

## Ref naming — immutable join key

```
packages-npm-0001        packages-pypi-0001
mcp_servers-0001
repositories-py-0001     repositories-js-0001
skills-0001
```

**Never reuse a ref, never renumber.** The ref is the join key between the zip,
the JSON file, and the CSV row. Changing it after merge corrupts scoring history.

---

## Ground truth format

```
packages, mcp_servers, skills   →  <ref>.expected_findings.json
repositories                    →  <ref>.ground_truth.json
```

### `expected_findings.json`

Array of finding objects. Every object **must** have:

```json
{
  "category": "tool_poisoning",
  "title": "one-sentence description of the finding",
  "plane": "context"
}
```

`file` is strongly preferred. `plane` must be `context` or `action`
(use `context` for all curated findings).

Category vocabularies by track:

**packages:** `install_hook_exec` · `postinstall_script` · `typosquat` · `dependency_confusion` ·
`credential_exfiltration` · `obfuscated_payload` · `remote_code_fetch` · `persistence` · `vulnerable_dependency`

**mcp_servers:** `tool_poisoning` · `tool_shadow` · `schema_mismatch` · `manifest_tamper` ·
`prompt_injection` · `credential_exfiltration` · `excessive_scope`

**skills:** `prompt_injection` · `hidden_instruction` · `context_injection` ·
`credential_exfiltration` · `tool_poisoning` · `unicode_anomaly` · `deceptive_documentation`

### `ground_truth.json` (repositories only)

```json
{
  "vulnerabilities": [
    { "file": "app.py", "line": 18, "cwe": "CWE-89", "title": "...", "description": "..." }
  ],
  "supply_chain": [
    { "type": "vulnerable_dependency", "name": "node-fetch" }
  ],
  "secrets": [
    { "file": "server.js", "line": 8, "type": "aws_access_key" }
  ]
}
```

**Hard gates:** `file` must exist inside the zip (after lowercasing). `cwe` must match
`CWE-\d+` exactly. `supply_chain.type` must be one of:
`typosquat` · `dependency_confusion` · `install_script` · `vulnerable_dependency`.
Safe entries use `{}`.

---

## CSV columns

Every track CSV has these columns (blank `licence` = ERROR, blank `verified_by` = warning):

| Column | Notes |
|--------|-------|
| `ref` | Immutable ref string |
| `label` | `malicious` or `safe` — no other value |
| `artifact_file` | Filename of the zip inside `artifacts/` |
| `source` | URL or description of the original source |
| `source_ref` | CVE, GHSA, licence, arXiv ID, etc. |
| `licence` | SPDX identifier — must not be blank |
| `findings_count` | Integer matching the JSON array length |
| `curator` | GitHub username of the person who built the entry |
| `curated_at` | ISO date `YYYY-MM-DD` |
| `verified_by` | GitHub username of second reviewer (blank = warning) |
| `notes` | Free text — explain the attack pattern or why it is safe |

---

## Two mistakes that destroy data silently

**Label strings.** Only `malicious` or `safe`. Anything else causes the task to be
skipped by the validator with no error message. Not `benign`, not `ok`, not `bad`.
CI rejects the PR.

**Class balance.** Every track needs both labels present. A track with only one label
scores every agent zero regardless of quality. Target 50/50; hard fail at 70/30.
CI fails the PR if a track drifts past that threshold.

---

## Validation

```bash
python3 validate.py
```

Output shows per-track totals, errors (block merge), and warnings (informational).
**0 errors required before opening a PR.** Common errors:

| Error | Cause |
|-------|-------|
| `zip missing` | Artifact file not committed or wrong filename |
| `json missing` | Ground truth file missing or misspelled |
| `file not in archive` | `ground_truth.json` references a path not in the zip |
| `invalid label` | Label is not exactly `malicious` or `safe` |
| `malicious + 0 findings` | Malicious entry must have at least one finding |
| `safe + findings > 0` | Safe entry must have an empty findings array / `{}` |
| `licence blank` | CSV row is missing the licence field |
| `balance > 70/30` | Track has too many entries of one label |

---

## How to contribute

1. Fork / branch from `main`.
2. Build your artifact: zip the source, write the JSON, add the CSV row.
3. Run `python3 validate.py` — fix all errors.
4. Open a PR. Title format: `feat(<track>): short description — N malicious + N safe`.
5. Include sourcing notes in the PR body (URL, licence, CVE/GHSA if applicable).

Each track's `README.md` carries additional sourcing guidance and the full category
vocabulary for that track.

---

## Key research references

- **GhostSplice** — ASSET Research Group, Aug 2026. Splits instructions across tool descriptions; 97% LLM compliance rate.
- **MCPTox Benchmark** — arxiv/2508.14925. 99 template tool-poisoning attack patterns.
- **CVE-2026-23744** — `@mcpjam/inspector` unauthenticated HTTP admin. CVSS 9.8, CWE-306.
- **CVE-2026-25536** — MCP TypeScript SDK. GHSA-345p-7cg4-v4c7, Red Hat RHSA-2026:3960.
- **Invariant Labs** — Tool Poisoning Attacks: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- **CyberArk** — Full-Schema Poisoning: https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe
- **ETDI** — Rug-Pull via `AddSessionTool`: arxiv/2506.01333
