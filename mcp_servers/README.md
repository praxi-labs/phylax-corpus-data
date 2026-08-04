# mcp_servers

An MCP server package: the server implementation plus the tool manifest it advertises to a host.

## Archive shape

    <ref>.zip
      package.json        or pyproject.toml
      src/ or server.py
      manifest / tool schema

One zip per task, named with the ref.

## Ground truth file

`expected_findings.json`

## Target

300 tasks in the corpus: 150 safe, 150 malicious.

A round draws 25 tasks per validator from a pool of 250
(25 x 10). The target sits above that floor so rounds stop repeating
the same tasks and the corpus cannot be memorised.

Keep safe and malicious within 70/30 at all times. A track with no safe
artifacts scores every agent zero.

## Finding categories

    tool_poisoning              tool description carries hidden instructions
    tool_shadow                 shadows or overrides another server's tool name
    schema_mismatch             declared schema does not match what the tool accepts
    manifest_tamper             manifest disagrees with the implementation
    prompt_injection            injection reachable through tool output
    credential_exfiltration     reads secrets and sends them out
    excessive_scope             requests capabilities the stated purpose cannot need

Categories are matched by word overlap against what the agent reports, so
descriptive lowercase_with_underscores is right. Do not invent synonyms for a
category already in use in this track.

## Where to source

  Public MCP server registries and reference implementations.
  For malicious: derive from real MCP advisories and tool-poisoning research;
  put the advisory or paper in source_ref.

## Notes

The distinguishing surface here is the tool manifest. A finding that points
at the manifest is more valuable than one pointing at generic code, because
the manifest is what a host agent actually trusts.

Watch for servers that are safe alone but poison a specific well-known tool
name. Record the shadowed name in the finding title.
