# Phylax corpus data

Collection area. One folder per track, one tracking sheet per track.

Read `_SPEC/DATA_SPEC.md` before labelling anything. It defines every field the
scoring code actually consumes.

## What to do

For each artifact you collect:

1. Put the zip in `<track>/artifacts/`, named with its ref.
2. Put the ground truth JSON next to it, same ref.
3. Add a row to `<track>/<track>_tracking.xlsx`.

That is the whole job. Nothing to move or rename afterwards.

## Ref naming

    skills-0001
    mcp_servers-0001
    packages-npm-0001        packages-pypi-0001
    repositories-py-0001     repositories-js-0001

Never reuse a ref, never renumber. It is the join key between the zip, the JSON
and the sheet row.

## Ground truth file

    skills, mcp_servers, packages   ->  <ref>.expected_findings.json
    repositories                    ->  <ref>.ground_truth.json

`_TEMPLATES/task_folder/` shows the shape of each.

## Two mistakes that destroy the data silently

**Label strings.** Only `malicious` or `safe`. Use the dropdown in the sheet.
Anything else makes the task skipped by the validator with no error message
anywhere. Not `benign`, not `ok`, not `bad`, not `suspicious`.

**Class balance.** Every track needs both labels present. A track with only one
label scores every agent zero no matter how good they are. Aim 50/50, never past
70/30. The counters at the top of each sheet track this live.

## Malicious artifacts

Password-protected zips only. Dropbox scans uploads and will quarantine or
delete live malware, and loose samples can flag the account. Keep the password
outside Dropbox.

## Targets

| Track | Tasks | Priority |
| --- | --- | --- |
| `repositories` | 80 | highest, this track currently pays nobody |
| `packages` | 200 | |
| `mcp_servers` | 250 | |
| `skills` | 300 | |

Each track's README and the `brief` tab in its sheet carry the sourcing notes
and category vocabulary for that track.
