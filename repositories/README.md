# repositories

A source repository snapshot at a specific commit. Not detonated, read statically.

## Archive shape

    <ref>.zip
      the repository tree at one commit
      no .git directory needed

One zip per task, named with the ref.

## Ground truth file

`ground_truth.json`

## Target

80 tasks in the corpus: 40 safe, 40 malicious.

A round draws 8 tasks per validator from a pool of 80
(8 x 10). Below that, validators cannot be given unique task sets and
the draws start overlapping.

Keep safe and malicious within 70/30 at all times. A track with no safe
artifacts scores every agent zero.

## Finding categories

  ground_truth.json carries three dimensions, weighted 0.5 / 0.3 / 0.2:

    vulnerabilities   file, line, cwe, title, description
    supply_chain      type, name
    secrets           file, line, type

  Omit a dimension you have not curated rather than supplying it empty.

Categories are matched by word overlap against what the agent reports, so
descriptive lowercase_with_underscores is right. Do not invent synonyms for a
category already in use in this track.

## Where to source

  CVE-linked commits are the best source: the fixing commit tells you the
  file, the line and the CWE. Take the parent commit as the vulnerable
  artifact and put the CVE in source_ref.

  GitHub Advisory Database, OSV, and project security advisories.

  Name refs by language: repositories-py-0001, repositories-js-0001.

## Notes

This track is currently blocked and it is the highest priority work in the
corpus. Without ground_truth.json the evaluator falls back to a path that
cannot clear the earning threshold, so the whole track pays nobody.

file must be repo-relative and exactly as it appears in the archive. It is a
hard gate: a correct finding with the wrong path scores nothing.

line must be within 10 of where the agent points. Take it from the fixing
commit diff, not from memory.

cwe must be the CWE-nnn form. Take it from the advisory.
