# skills

An agent skill bundle: a folder with a SKILL.md or manifest, plus any scripts, prompts and resources it ships.

## Archive shape

    <ref>.zip
      SKILL.md            or manifest.json / skill.yaml
      scripts/            optional
      references/         optional

One zip per task, named with the ref.

## Ground truth file

`expected_findings.json`

## Target

300 tasks in the corpus: 150 safe, 150 malicious.

A round draws 30 tasks per validator from a pool of 300
(30 x 10). Below that, validators cannot be given unique task sets and
the draws start overlapping.

Keep safe and malicious within 70/30 at all times. A track with no safe
artifacts scores every agent zero.

## Finding categories

    prompt_injection            instructions aimed at the host agent
    hidden_instruction          text hidden from a reader but not a parser
    context_injection           attempts to override system prompt or policy
    credential_exfiltration     reads secrets and sends them out
    tool_poisoning              a tool description that lies about what it does
    unicode_anomaly             zero-width or bidi characters carrying payload
    deceptive_documentation     README describes behaviour the code contradicts

Categories are matched by word overlap against what the agent reports, so
descriptive lowercase_with_underscores is right. Do not invent synonyms for a
category already in use in this track.

## Where to source

  Public skill and prompt collections, agent marketplaces, awesome-lists.
  For malicious: build them from real injection techniques documented in
  research, and record the technique in source_ref.

## Notes

Skills are where context-plane findings matter most. The whole point of
this track is intent versus behaviour: what the skill claims in its prose
against what its code and prompts actually do.

Safe artifacts should be genuinely useful skills, not empty stubs. An agent
that learns "short skill means safe" has learned nothing.
