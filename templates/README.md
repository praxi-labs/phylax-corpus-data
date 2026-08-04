Shape reference only. You do not copy this folder anywhere.

For each artifact, two files go into <track>/artifacts/:

    <ref>.zip                       the artifact
    <ref>.expected_findings.json    skills, mcp_servers, packages
    <ref>.ground_truth.json         repositories

Then one row in that track's tracking sheet. Everything else lives in the sheet,
so there is no task.json.

expected_findings.json is a list. Each entry is one thing a competent agent
should report. plane must be "context" or "action" — context findings always
count, action findings are dropped when the sandbox already observed the
behaviour itself. Label context findings.

ground_truth.json is an object with up to three dimensions: vulnerabilities,
supply_chain, secrets. Omit a dimension you have not curated rather than
supplying it empty.

A safe artifact still needs its JSON file, carrying an empty list or object
rather than being absent.

Field definitions and matching rules are in _SPEC/DATA_SPEC.md.
