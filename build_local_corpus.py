from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TRACKS = ("skills", "mcp_servers", "packages", "repositories")
LABEL_DIRS = {"malicious": "known-bad", "safe": "known-good"}
REPO_KEYS = ("vulnerabilities", "supply_chain", "secrets")


def rows(track: str) -> list[dict]:
    sheet = ROOT / track / f"{track}.csv"
    if not sheet.is_file():
        return []
    with sheet.open(encoding="utf-8-sig", newline="") as fh:
        return [r for r in csv.DictReader(fh) if (r.get("ref") or "").strip()]


def sidecar(track: str, ref: str) -> tuple[str, dict | list] | None:
    art = ROOT / track / "artifacts"
    if track == "repositories":
        path = art / f"{ref}.ground_truth.json"
        if not path.is_file():
            return None
        doc = json.loads(path.read_text(encoding="utf-8"))
        return "ground_truth.json", {k: doc.get(k, []) for k in REPO_KEYS if k in doc}
    path = art / f"{ref}.expected_findings.json"
    if not path.is_file():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    return "label.json", {"expected_findings": doc if isinstance(doc, list) else []}


def build(out: Path, tracks: list[str]) -> int:
    made = 0
    for track in tracks:
        for row in rows(track):
            ref = row["ref"].strip()
            label = (row.get("label") or "").strip()
            bucket = LABEL_DIRS.get(label)
            if bucket is None:
                print(f"  skip {ref}: label '{label}' is not malicious or safe")
                continue
            archive = ROOT / track / "artifacts" / (row.get("artifact_file") or "").strip()
            if not archive.is_file():
                print(f"  skip {ref}: {archive.name} missing")
                continue
            dest = out / track / bucket / ref
            if dest.exists():
                shutil.rmtree(dest)
            dest.mkdir(parents=True)
            with zipfile.ZipFile(archive) as zf:
                for member in zf.infolist():
                    name = member.filename.replace("\\", "/")
                    if member.is_dir() or name.startswith("/") or ".." in name.split("/"):
                        continue
                    target = dest / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
            found = sidecar(track, ref)
            if found is None:
                print(f"  skip {ref}: ground truth json missing")
                shutil.rmtree(dest)
                continue
            name, payload = found
            (dest / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            made += 1
        built = sum(1 for _ in (out / track).rglob("*")) if (out / track).is_dir() else 0
        if built:
            print(f"{track}: ready")
    return made


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert this repo into a corpus directory the Phylax harness can load."
    )
    ap.add_argument(
        "--out",
        default="local-corpus",
        help="output directory to point PHYLAX_CORPUS_DIR at (default: local-corpus)",
    )
    ap.add_argument(
        "--track",
        action="append",
        choices=TRACKS,
        help="build one track only; repeatable (default: all four)",
    )
    args = ap.parse_args()

    out = Path(args.out).expanduser().resolve()
    tracks = args.track or list(TRACKS)
    out.mkdir(parents=True, exist_ok=True)

    made = build(out, tracks)
    if not made:
        print("nothing built; check that git lfs pulled the zips")
        return 1
    print(f"\n{made} artifacts written to {out}")
    print(f"\nexport PHYLAX_CORPUS_DIR={out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
