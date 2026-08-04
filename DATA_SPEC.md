# Corpus data specification

What a curated task must contain for validators to score it. Fields named here
are consumed by code; anything else is ignored.

Internal. Do not publish, and do not restate thresholds or matcher tolerances to
miners.

## The four tracks

| Track | Artifact is | Detonated | Ground truth file | Target |
| --- | --- | --- | --- | --- |
| `repositories` | a source repository | no | `ground_truth` | 80 |
| `packages` | an npm or PyPI archive | yes | `expected_findings` | 200 |
| `mcp_servers` | an MCP server package | yes | `expected_findings` | 250 |
| `skills` | an agent skill bundle | yes | `expected_findings` | 300 |

Targets are the round task count times ten, because a round freezes a pool of
that size and draws a unique subset per validator. Below target, validators
start receiving overlapping task sets.

`repositories` is the smallest and the most urgent: it has no ground truth at
all today, so the evaluator falls back to a path that cannot clear the earning
threshold and the track pays nobody.

## How a task is filed

Two files per task, side by side:

    <track>/artifacts/<ref>.zip
    <track>/artifacts/<ref>.expected_findings.json     detonation tracks
    <track>/artifacts/<ref>.ground_truth.json          repositories

Plus one row in `<track>/<track>_tracking.xlsx`.

Ref naming:

    skills-0001
    mcp_servers-0001
    packages-npm-0001        packages-pypi-0001
    repositories-py-0001     repositories-js-0001

The ref is the join key between the zip, the JSON and the sheet row. Never reuse
one, never renumber.

Malicious artifacts are password-protected zips. Dropbox quarantines loose
malware and can flag the account.

## What the server builds from this

| Field | Source |
| --- | --- |
| `ref` | the filename stem |
| `label` | the sheet |
| `artifact_b64` | base64 of the zip |
| `expected_findings` | the JSON, detonation tracks |
| `ground_truth` | the JSON, repositories |

## Label

Use `malicious` or `safe`. Nothing else. The sheet enforces this with a
dropdown.

The scoring code accepts a wider vocabulary (`known_bad`, `unsafe`, `block`,
`vulnerable`, `known_good`, `allow`, `clean`), but a value outside that list
makes the task **silently skipped** rather than failed, so a typo removes it
from scoring with no error anywhere. Two words is a smaller surface for that
mistake than nine.

`benign`, `ok`, `good`, `bad` and `suspicious` are all invalid.

## Class balance is not optional

Track scoring is the Matthews correlation coefficient. Its denominator is

```text
sqrt((tp+fp) * (tp+fn) * (tn+fp) * (tn+fn))
```

If a track has no safe artifacts then `tn` and `fp` are both zero, the
denominator is zero, and **every agent in that track scores exactly 0.0** no
matter how good it is. The same happens with no malicious artifacts.

Target a 50/50 split per track. Do not go past 70/30 in either direction. This
is the single most expensive mistake available in this dataset, and it looks
like nothing until every score in the track flatlines.

The counters at the top of each tracking sheet show this live.

## `expected_findings` — skills, mcp_servers, packages

A list of objects. Each entry is one thing a competent agent should report.

```json
[
  {
    "category": "install_hook_exec",
    "file": "package.json",
    "title": "postinstall downloads and executes a remote script",
    "plane": "context"
  }
]
```

| Key | Required | Matching |
| --- | --- | --- |
| `category` | yes | exact, or any shared word with the agent's category |
| `file` | strongly preferred | path match, either side may be a suffix of the other |
| `title` | yes | word overlap, used only when `file` is absent on either side |
| `plane` | yes | `context` or `action`, see below |

`plane` changes whether the entry counts at all. Entries marked `context` always
count. Entries marked `action` are dropped whenever the sandbox already observed
capabilities for that artifact, on the grounds that the harness saw it directly
and the agent gets no credit for restating it.

**Consequence for curation:** label context-plane findings — prompt injection,
hidden instructions, deceptive documentation, misleading manifests. Action-plane
findings are usually redundant with the trace and will not score.

Aim for 3 to 6 findings on a malicious artifact. A safe artifact still needs its
JSON file, carrying `[]` rather than being absent.

### Category vocabulary

Reuse these. Matching is by word overlap, so inventing synonyms works by luck
and makes the data unqueryable later.

`skills` — `prompt_injection`, `hidden_instruction`, `context_injection`,
`credential_exfiltration`, `tool_poisoning`, `unicode_anomaly`,
`deceptive_documentation`

`mcp_servers` — `tool_poisoning`, `tool_shadow`, `schema_mismatch`,
`manifest_tamper`, `prompt_injection`, `credential_exfiltration`,
`excessive_scope`

`packages` — `install_hook_exec`, `postinstall_script`, `typosquat`,
`dependency_confusion`, `credential_exfiltration`, `obfuscated_payload`,
`remote_code_fetch`, `persistence`, `vulnerable_dependency`

## `ground_truth` — repositories

An object with up to three labelled dimensions. A dimension is scored only when
present, so omit rather than supply an empty one you have not curated.

```json
{
  "vulnerabilities": [
    {
      "file": "src/db/query.py",
      "line": 142,
      "cwe": "CWE-89",
      "title": "user input concatenated into SQL statement",
      "description": "the id parameter reaches execute() without parameterisation"
    }
  ],
  "supply_chain": [
    { "type": "typosquat", "name": "reqeusts" }
  ],
  "secrets": [
    { "file": ".env.example", "line": 3, "type": "aws_access_key" }
  ]
}
```

Weighting: `vulnerabilities` 0.5, `supply_chain` 0.3, `secrets` 0.2, renormalised
over whichever dimensions are present.

CVE-linked commits are the best source. The fixing commit gives you the file,
the line and the CWE; take the **parent** commit as the vulnerable artifact and
put the CVE in `source_ref`.

### vulnerabilities

| Key | Required | Matching |
| --- | --- | --- |
| `file` | yes | must match exactly after lowercasing and slash normalisation |
| `cwe` | yes | exact string match, `CWE-89` form |
| `title` | yes | word overlap, accepted as an alternative to `cwe` |
| `line` | yes | must be within 10 lines of the agent's report |
| `description` | yes | folded into the title comparison |

`file` is a hard gate. A correct finding with the wrong path scores nothing, so
paths must be repo-relative and exactly as they appear in the archive.

`line` tolerance is 10 either way. A missing line does not disqualify a match,
but a wrong line does. Take it from the diff, not from memory.

### supply_chain

`type` must match exactly. Use these values only:

`typosquat`, `dependency_confusion`, `install_script`, `vulnerable_dependency`

`name` is the package name, lowercase. Leave it empty for `install_script`.

### secrets

`file` must match. `type` is compared when both sides supply one; if the types
disagree the entry falls back to the line window.

## Tracking sheet

One workbook per track, in that track's folder. Columns in this order:

| Column | Purpose |
| --- | --- |
| `ref` | join key to the zip and the JSON |
| `label` | dropdown, `malicious` or `safe` |
| `artifact_file` | zip filename in `artifacts/` |
| `source` | where the artifact came from, URL or dataset |
| `source_ref` | CVE, advisory id, commit sha, or package version |
| `licence` | blank means unresolved and blocks use |
| `findings_count` | entries in the ground truth file |
| `curator` | who labelled it |
| `curated_at` | `YYYY-MM-DD` |
| `verified_by` | second pair of eyes, blank means unreviewed |
| `notes` | anything the matcher cannot express |

Row 2 of each sheet counts rows, malicious, safe and unverified.

`verified_by` matters more than it looks. A wrong label is worse than a missing
task: it teaches every agent the opposite of the right answer and it penalises
the agents that got it right.

## Order of work

1. `ground_truth` for repositories. Absent entirely today, which is why that
   track cannot pay anyone.
2. Safe artifacts for every track, so no track is single-class. Nothing in a
   single-class track scores at all.
3. Malicious artifacts with real provenance, one advisory or CVE each.
4. `expected_findings` for the detonation tracks, context-plane first.

For `packages` specifically, the valuable safe artifacts are the
alarming-looking ones: native modules with `node-gyp` postinstall hooks, CLIs
that legitimately spawn processes, SDKs that read environment variables. Those
are what the current field false-positives on, so they are worth more than
another obvious malware sample.

## Rejecting an artifact

Drop it rather than guess when any of these hold:

- the licence does not permit redistribution
- the malicious behaviour cannot be pointed at a specific file and line
- the label depends on judgement two curators would disagree about
- the artifact is already in the corpus under another `ref`

Rejecting is a real outcome. Record the reason in `notes` and leave the row in
the sheet so the same artifact is not collected again.
