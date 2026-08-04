from __future__ import annotations

import csv
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TRACKS = {
    "skills": {"truth": "expected_findings", "target": 400},
    "mcp_servers": {"truth": "expected_findings", "target": 300},
    "packages": {"truth": "expected_findings", "target": 250},
    "repositories": {"truth": "ground_truth", "target": 150},
}

LABELS = {"malicious", "safe"}
PLANES = {"context", "action"}
SC_TYPES = {"typosquat", "dependency_confusion", "install_script", "vulnerable_dependency"}
CWE = re.compile(r"^CWE-\d+$")
REF = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*-\d{4,}$")
BALANCE_MAX = 0.70

errors: list[str] = []
warnings: list[str] = []


def err(track: str, ref: str, message: str) -> None:
    errors.append(f"{track}/{ref or '-'}: {message}")


def warn(track: str, ref: str, message: str) -> None:
    warnings.append(f"{track}/{ref or '-'}: {message}")


def load_rows(track: str) -> list[dict]:
    path = ROOT / track / f"{track}.csv"
    if not path.exists():
        err(track, "", f"missing {path.name}")
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return [r for r in csv.DictReader(handle) if (r.get("ref") or "").strip()]


def zip_names(archive: Path) -> list[str] | None:
    try:
        with zipfile.ZipFile(archive) as zf:
            if any(i.flag_bits & 0x1 for i in zf.infolist()):
                return None
            return [n.replace("\\", "/").lower() for n in zf.namelist()]
    except (zipfile.BadZipFile, OSError):
        return []


def check_expected_findings(track: str, ref: str, payload: object) -> int:
    if not isinstance(payload, list):
        err(track, ref, "expected_findings must be a list")
        return 0
    for i, entry in enumerate(payload):
        if not isinstance(entry, dict):
            err(track, ref, f"finding {i} is not an object")
            continue
        for key in ("category", "title", "plane"):
            if not str(entry.get(key, "")).strip():
                err(track, ref, f"finding {i} missing {key}")
        plane = str(entry.get("plane", "")).strip().lower()
        if plane and plane not in PLANES:
            err(track, ref, f"finding {i} plane '{plane}' not in {sorted(PLANES)}")
    return len(payload)


def check_ground_truth(track: str, ref: str, payload: object, names: list[str] | None) -> int:
    if not isinstance(payload, dict):
        err(track, ref, "ground_truth must be an object")
        return 0
    known = {"vulnerabilities", "supply_chain", "secrets"}
    unknown = set(payload) - known
    if unknown:
        err(track, ref, f"unknown ground_truth keys {sorted(unknown)}")
    count = 0

    for i, v in enumerate(payload.get("vulnerabilities") or []):
        count += 1
        if not isinstance(v, dict):
            err(track, ref, f"vulnerability {i} is not an object")
            continue
        for key in ("file", "cwe", "title", "line"):
            if key not in v or str(v.get(key, "")).strip() == "":
                err(track, ref, f"vulnerability {i} missing {key}")
        cwe = str(v.get("cwe", "")).strip()
        if cwe and not CWE.match(cwe):
            err(track, ref, f"vulnerability {i} cwe '{cwe}' is not CWE-nnn")
        try:
            int(v.get("line"))
        except (TypeError, ValueError):
            err(track, ref, f"vulnerability {i} line is not an integer")
        path = str(v.get("file", "")).strip().replace("\\", "/").lower().lstrip("./")
        if path and names:
            if not any(n == path or n.endswith("/" + path) for n in names):
                err(track, ref, f"vulnerability {i} file '{path}' not present in the archive")

    for i, s in enumerate(payload.get("supply_chain") or []):
        count += 1
        if not isinstance(s, dict):
            err(track, ref, f"supply_chain {i} is not an object")
            continue
        kind = str(s.get("type", "")).strip()
        if kind not in SC_TYPES:
            err(track, ref, f"supply_chain {i} type '{kind}' not in {sorted(SC_TYPES)}")
        if kind != "install_script" and not str(s.get("name", "")).strip():
            err(track, ref, f"supply_chain {i} missing name")

    for i, s in enumerate(payload.get("secrets") or []):
        count += 1
        if not isinstance(s, dict):
            err(track, ref, f"secret {i} is not an object")
            continue
        if not str(s.get("file", "")).strip():
            err(track, ref, f"secret {i} missing file")
    return count


def check_track(track: str, spec: dict) -> tuple[int, int]:
    rows = load_rows(track)
    artifacts = ROOT / track / "artifacts"
    seen: set[str] = set()
    malicious = safe = 0

    for row in rows:
        ref = (row.get("ref") or "").strip()
        if ref in seen:
            err(track, ref, "duplicate ref")
            continue
        seen.add(ref)

        if not REF.match(ref):
            warn(track, ref, "ref does not look like <track>-<nnnn>")

        label = (row.get("label") or "").strip().lower()
        if label not in LABELS:
            err(track, ref, f"label '{label}' must be one of {sorted(LABELS)}")
        elif label == "malicious":
            malicious += 1
        else:
            safe += 1

        if not (row.get("licence") or "").strip():
            err(track, ref, "licence is blank")
        if not (row.get("verified_by") or "").strip():
            warn(track, ref, "not verified")

        archive = artifacts / f"{ref}.zip"
        if not archive.exists():
            err(track, ref, f"no artifact at artifacts/{ref}.zip")
            continue

        names = zip_names(archive)
        if names is None:
            names = []
        elif names == []:
            err(track, ref, "artifact is not a readable zip")

        truth_path = artifacts / f"{ref}.{spec['truth']}.json"
        if not truth_path.exists():
            err(track, ref, f"no ground truth at artifacts/{truth_path.name}")
            continue
        try:
            payload = json.loads(truth_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            err(track, ref, f"{truth_path.name} does not parse: {exc}")
            continue

        if spec["truth"] == "expected_findings":
            count = check_expected_findings(track, ref, payload)
        else:
            count = check_ground_truth(track, ref, payload, names)

        declared = (row.get("findings_count") or "").strip()
        if declared:
            try:
                if int(declared) != count:
                    err(track, ref, f"findings_count says {declared}, file has {count}")
            except ValueError:
                err(track, ref, f"findings_count '{declared}' is not a number")

        if label == "malicious" and count == 0:
            err(track, ref, "labelled malicious with no findings")
        if label == "safe" and count > 0:
            err(track, ref, "labelled safe but carries findings")

    for stray in sorted(artifacts.glob("*.zip")):
        if stray.stem not in seen:
            err(track, stray.stem, "artifact present with no row in the sheet")

    total = malicious + safe
    if total:
        share = max(malicious, safe) / total
        if share > BALANCE_MAX:
            heavier = "malicious" if malicious > safe else "safe"
            err(track, "", f"class balance {share:.0%} {heavier} exceeds {BALANCE_MAX:.0%}")
        if malicious == 0 or safe == 0:
            err(track, "", "single class, every agent in this track scores zero")
    return total, malicious


def main() -> int:
    print(f"{'track':<14} {'rows':>6} {'malicious':>10} {'safe':>6} {'target':>7} {'progress':>9}")
    for track, spec in TRACKS.items():
        total, malicious = check_track(track, spec)
        target = spec["target"]
        print(
            f"{track:<14} {total:>6} {malicious:>10} {total - malicious:>6} "
            f"{target:>7} {total / target:>8.0%}"
        )

    if warnings:
        print(f"\n{len(warnings)} warning(s)")
        for line in warnings[:40]:
            print(f"  ! {line}")
        if len(warnings) > 40:
            print(f"  ... {len(warnings) - 40} more")

    if errors:
        print(f"\n{len(errors)} error(s)")
        for line in errors[:80]:
            print(f"  x {line}")
        if len(errors) > 80:
            print(f"  ... {len(errors) - 80} more")
        return 1

    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
