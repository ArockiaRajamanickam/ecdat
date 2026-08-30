"""ECDAT scan pipeline: walk a tree, run every detector, normalise, score, recommend."""
from __future__ import annotations
import os, datetime
from typing import Any

from .models import ScanResult, Artefact
from .policy import Policy
from .normalize import merge_artefacts
from .normalize2 import merge_compatible, infer_missing_params
from .risk.engine import apply_risk
from . import recommend as _recommend

# tree-walking detectors: detect(root, policy) -> (artefacts, files, errors)
def _tree_detectors():
    mods = []
    for name in ("source_python", "source_js", "source_java", "source_go"):
        try:
            mods.append(__import__(f"engine.detectors.{name}", fromlist=[name]))
        except Exception:
            pass
    return mods

# per-file detectors: detect(path) -> [Artefact]
def _file_detectors():
    mods = []
    for name in ("certs", "deps"):
        try:
            mods.append(__import__(f"engine.detectors.{name}", fromlist=[name]))
        except Exception:
            pass
    return mods

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
             ".ruff_cache", ".pytest_cache", "site-packages", ".claude"}


def scan(root: str, policy: Policy | None = None, target: str | None = None,
         now_year: int | None = None) -> ScanResult:
    root = os.path.abspath(os.path.expanduser(root))
    policy = policy or Policy.load(None)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    artefacts: list[Artefact] = []
    errors: list[str] = []
    files_scanned = 0

    # 1. tree-walking source detectors
    for mod in _tree_detectors():
        try:
            arts, n, errs = mod.detect(root, policy)
            artefacts.extend(arts); files_scanned += n; errors.extend(errs or [])
        except Exception as e:
            errors.append(f"{getattr(mod,'__name__','detector')}: {type(e).__name__}: {e}")

    # 2. per-file detectors (certs, dependency manifests)
    fdets = _file_detectors()
    if fdets:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if policy.is_ignored(p):
                    continue
                for mod in fdets:
                    try:
                        got = mod.detect(p)
                        if got:
                            artefacts.extend(got); files_scanned += 1
                    except Exception as e:
                        errors.append(f"{fn}: {type(e).__name__}: {e}")

    # Drop occurrences inside vendored / mirrored / build directories. Tree
    # detectors do their own walking, so a worktree copy of the repo would
    # otherwise be counted as separate provenance for the same asset.
    _skip_norm = {d.lstrip(".").lower() for d in SKIP_DIRS}

    def _excluded(path: str) -> bool:
        # Compare with leading dots stripped: some detectors report ".claude/x"
        # as "claude/x", and a vendored copy must be excluded either way.
        parts = {seg.lstrip(".").lower() for seg in os.path.normpath(path).split(os.sep)}
        return bool(parts & _skip_norm)

    for a in artefacts:
        a.occurrences = [o for o in a.occurrences if not _excluded(o.file or "")]
    artefacts = [a for a in artefacts if a.occurrences]

    # Report every path relative to the scan root. Detectors disagree (source
    # detectors return relative paths, the cert detector absolute ones) and a
    # mixed table is unreadable.
    for a in artefacts:
        for o in a.occurrences:
            f = o.file or ""
            if f.startswith(root):
                try:
                    o.file = os.path.relpath(f, root)
                except Exception:
                    pass

    # 3. normalise -> 4. risk -> 5. recommend
    artefacts = infer_missing_params(merge_compatible(merge_artefacts(artefacts)))
    try:
        apply_risk(artefacts, policy, now_year)
    except Exception as e:
        errors.append(f"risk: {type(e).__name__}: {e}")
    rec_all = getattr(_recommend, "recommend_all", None)
    if callable(rec_all):
        try: rec_all(artefacts)
        except Exception as e: errors.append(f"recommend: {type(e).__name__}: {e}")
    else:
        one = getattr(_recommend, "recommend", None)
        for a in artefacts:
            try: one(a)
            except Exception: pass

    # 6. autofix — generate a real unified diff where a safe mechanical fix exists
    gen = getattr(_recommend, "generate_fix", None)
    if callable(gen):
        for a in artefacts:
            try:
                patch = gen(a, repo_root=root, errors=errors)
                if patch: a.fix_patch = patch
            except Exception as e:
                errors.append(f"autofix {a.name}: {type(e).__name__}: {e}")

    # distinguish certificate/library assets from code usage in the display name
    for a in artefacts:
        if a.kind in ("certificate", "key", "library") and not a.name.endswith(")"):
            a.name = f"{a.name} ({a.kind})"

    return ScanResult(target=target or os.path.basename(root) or root,
                      artefacts=artefacts, files_scanned=files_scanned,
                      started=started,
                      finished=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      policy_name=getattr(policy, "name", "default"), errors=errors)
