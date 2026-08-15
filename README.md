# Phylax corpus data

A labelled corpus for building and testing Phylax detection agents on your own
machine, before you ever submit to subnet 76.

Every artifact here ships with its ground truth. You can see exactly what your
agent was supposed to find, fix it, and run again in seconds instead of waiting
two days for the next round.

**This is not the live scoring corpus.** Rounds on subnet 76 draw from a separate
corpus whose ground truth is never published. Nothing here is used to score a
round, so nothing here can be memorised for points. Treat it as a practice set:
if your agent cannot pass locally, it will not place on chain.

---

## Quick start

```bash
git clone https://github.com/praxi-labs/phylax-corpus-data.git
cd phylax-corpus-data
git lfs pull

python3 build_local_corpus.py
export PHYLAX_CORPUS_DIR=$PWD/local-corpus
```

That converts the repo into the layout the subnet harness reads. Then score your
agent from your `phylax-subnet` checkout:

```bash
python3 scripts/evaluate_local.py --agent my_agent.py --track packages
```

It runs `agent_main` over every artifact, scores with the same metric the
validator applies, and prints each task you got wrong alongside the confusion
matrix and your score against the qualifying threshold.

Build one track only while you are working on it:

```bash
python3 build_local_corpus.py --track packages
```

To drive the loop yourself instead, `phylax.harness.corpus.load_corpus(track)`
hands back each task with `ref`, `label`, the artifact as a base64 zip in
`artifact_b64`, and its ground truth.

See [local_testing.md](https://github.com/praxi-labs/phylax-subnet/blob/main/docs/local_testing.md)
in the subnet repo for the full loop including scoring.

---

## What is in here

| Track | Artifacts | Malicious | Safe | What it covers |
|-------|----------:|----------:|-----:|----------------|
| `skills` | 15 | 5 | 10 | Claude skill files. Hidden instructions, credential exfiltration, context injection |
| `repositories` | 12 | 6 | 6 | Full source repos. Vulnerability scanning, secret detection, supply chain |
| `packages` | 10 | 5 | 5 | npm and PyPI packages. Install hooks, typosquats, obfuscated payloads |
| `mcp_servers` | 10 | 5 | 5 | MCP server definitions. Tool poisoning, schema abuse, prompt injection |

The safe artifacts matter as much as the malicious ones. Several are deliberate
false positive traps: a legitimate AWS SDK helper that reads credential env vars,
a security audit skill dense with secret related keywords because it teaches how
to find them. An agent that flags those is scored down, on the behavioural tracks
as hard as a miss.

**The zips contain real malware**, including a compromised node-ipc build and a
Discord token stealer sourced from `ossf/malicious-packages`. Your antivirus will
flag the checkout. Unpack them inside a container or VM, never on a host you care
about.

---

## How your agent is scored

Local scoring should mirror the network, so build against the same metric.

**Behavioural tracks** (`skills`, `mcp_servers`, `packages`) score on verdict
correctness, not on findings. Tally your verdicts against labels and compute
clamped MCC. `BLOCK` or `WARN` on a malicious artifact is a true positive,
`ALLOW` on a safe one is a true negative:

```
score = max(0, MCC)
```

An agent that answers `ALLOW` to everything scores exactly 0, as does one that
answers `BLOCK` to everything. The qualifying threshold is **0.20**.

**Repositories** scores on findings recovered, using F-beta with beta 2. Your
findings are matched against planted ground truth, giving recall `R` and
precision `P`:

```
F2 = 5PR / (4P + R)
```

Beta 2 favours recall: a missed vulnerability costs more than a false alarm. The
qualifying threshold is **0.50**.

Full definitions, budgets and failure semantics are in
[mechanism.md](https://github.com/praxi-labs/phylax-subnet/blob/main/docs/mechanism.md).

---

## Ground truth format

```
skills, mcp_servers, packages   →  artifacts/<ref>.expected_findings.json
repositories                    →  artifacts/<ref>.ground_truth.json
```

### `expected_findings.json`

An array. Each finding carries a category, a title, and the plane it sits on.
`file` points at the offending file inside the zip.

```json
[
  {
    "category": "credential_exfiltration",
    "file": "SKILL.md",
    "title": "skill requires collecting SSH keys and env vars before every review",
    "plane": "context"
  }
]
```

Category vocabulary per track:

**skills** `prompt_injection` · `hidden_instruction` · `context_injection` ·
`credential_exfiltration` · `tool_poisoning` · `unicode_anomaly` · `deceptive_documentation`

**mcp_servers** `tool_poisoning` · `tool_shadow` · `schema_mismatch` ·
`manifest_tamper` · `prompt_injection` · `credential_exfiltration` · `excessive_scope`

**packages** `install_hook_exec` · `postinstall_script` · `typosquat` ·
`dependency_confusion` · `credential_exfiltration` · `obfuscated_payload` ·
`remote_code_fetch` · `persistence` · `vulnerable_dependency`

### `ground_truth.json`, repositories only

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

Safe repositories carry `{}`. Weighting is `vulnerabilities` 0.5,
`supply_chain` 0.3, `secrets` 0.2, renormalised over whichever dimensions are
present.

---

## Layout

```
<track>/
  artifacts/
    <ref>.zip                     the artifact
    <ref>.expected_findings.json  ground truth (skills, mcp_servers, packages)
    <ref>.ground_truth.json       ground truth (repositories)
  <track>.csv                     one row per artifact, all metadata
  README.md                       sourcing notes and category vocabulary
```

Refs are immutable join keys tying the zip, the JSON and the CSV row together:
`packages-npm-0001`, `mcp_servers-0001`, `repositories-py-0001`, `skills-0001`.
They are never reused and never renumbered.

The CSV carries `ref`, `label`, `artifact_file`, `source`, `source_ref`,
`licence`, `findings_count`, `curator`, `curated_at`, `verified_by`, `notes`.
The `notes` column explains the attack pattern, or why a safe artifact is a
useful false positive trap. Read it while you are debugging a miss.

---

## Contributing

We take corpus contributions, and accepted ones earn a share of the contribution
emission pool. See
[mechanism.md](https://github.com/praxi-labs/phylax-subnet/blob/main/docs/mechanism.md)
for how that pool is split.

1. Branch from `main`.
2. Build the artifact: zip the source, write the ground truth JSON, add the CSV row.
3. Run `python3 validate.py` and fix every error.
4. Open a PR titled `feat(<track>): short description — N malicious + N safe`.
   Include the source URL, licence, and CVE or GHSA in the body.

[`DATA_SPEC.md`](DATA_SPEC.md) defines every field the scoring code consumes.
`validate.py` enforces it and CI blocks the merge on any error.

Two mistakes that fail silently if CI ever misses them. Labels are exactly
`malicious` or `safe`, never `benign` or `bad`. And every track needs both labels
present, because a single label track scores every agent zero no matter how good
it is. Target an even split; CI hard fails past 70/30.

---

## Sourcing

Artifacts come from published research and public malware archives, never from
anything we invented to be unsolvable.

- **PyPI malregistry** and **ossf/malicious-packages** for confirmed malicious releases
- **MCPTox Benchmark** arxiv/2508.14925, 99 tool poisoning attack templates
- **Invariant Labs** tool description poisoning and cross-server shadowing
- **CyberArk** full-schema poisoning, attacks hidden in parameter names and enum values
- **ETDI** arxiv/2506.01333, rug-pull via `AddSessionTool`
- **appsecco/bad-mcp** and **vulnerable-mcp-servers-lab**, malicious and vulnerable servers
- **MaliciousAgentSkillsBench** (USENIX 2026) for real safe skills
- **CVE-2026-23744**, `@mcpjam/inspector` unauthenticated admin endpoint, CWE-306
- Canonical CWE patterns: CWE-89 injection, CWE-798 hardcoded credentials, CWE-22 traversal, CWE-94 eval RCE

Per track sourcing notes are in each track's `README.md`.
