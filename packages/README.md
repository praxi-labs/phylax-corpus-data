# packages

A published npm or PyPI package archive, exactly as a developer would install it.

## Archive shape

    <ref>.zip
      package.json / setup.py / pyproject.toml
      lib/ or src/
      install scripts if any

One zip per task, named with the ref.

## Ground truth file

`expected_findings.json`

## Target

200 tasks in the corpus: 100 safe, 100 malicious.

A round draws 20 tasks per validator from a pool of 200
(20 x 10). Below that, validators cannot be given unique task sets and
the draws start overlapping.

Keep safe and malicious within 70/30 at all times. A track with no safe
artifacts scores every agent zero.

## Finding categories

    install_hook_exec           preinstall/postinstall runs code
    postinstall_script          install-phase script present
    typosquat                   name imitates a popular package
    dependency_confusion        scoped or internal name resolvable publicly
    credential_exfiltration     reads env, keys or wallets and sends them out
    obfuscated_payload          encoded blob decoded and executed
    remote_code_fetch           downloads and pipes a script to a shell
    persistence                 writes shell profile, cron, hosts file
    vulnerable_dependency       pulls a dependency with a known CVE

Categories are matched by word overlap against what the agent reports, so
descriptive lowercase_with_underscores is right. Do not invent synonyms for a
category already in use in this track.

## Where to source

  ossf/malicious-packages is the primary source and carries advisories.
  npm and PyPI directly for safe artifacts.
  GitHub Advisory Database for the CVE-linked ones.

  Name refs by ecosystem: packages-npm-0001, packages-pypi-0001.

## Notes

Balance is easy to get wrong here because malicious samples are easier to
find than curated safe ones. Safe artifacts must include packages that look
alarming and are not: native modules with node-gyp postinstall hooks, CLIs
that legitimately spawn processes, SDKs that read environment variables.

Those are exactly the cases the current field gets wrong, so they are the
most valuable safe artifacts you can collect.
