"""Compatibility-aware artefact merging.

The naive key (family|key_size|curve|mode) splits the SAME asset when one
detector knows a parameter and another does not: Ed25519 found in Python
(key_size=256) would not merge with Ed25519 found in Go (key_size=None).

Here an unknown parameter (None) is treated as a WILDCARD that is compatible
with any concrete value, so the two collapse into one asset carrying the
richest known parameters and the union of provenance. Concrete values that
genuinely differ (RSA-1024 vs RSA-2048, AES-GCM vs AES-ECB) never merge.
"""
from __future__ import annotations
from .models import Artefact, Params

_FIELDS = ("key_size", "curve", "mode", "padding")


def _compatible(a: Artefact, b: Artefact) -> bool:
    if a.family != b.family or a.kind != b.kind:
        return False
    for f in _FIELDS:
        x, y = getattr(a.params, f, None), getattr(b.params, f, None)
        if x is not None and y is not None and x != y:
            return False
    return True


def _absorb(dst: Artefact, src: Artefact) -> None:
    for f in _FIELDS:
        if getattr(dst.params, f, None) is None:
            v = getattr(src.params, f, None)
            if v is not None:
                setattr(dst.params, f, v)
    try:
        extra = dict(getattr(src.params, "extra", {}) or {})
        base = dict(getattr(dst.params, "extra", {}) or {})
        base.update(extra); dst.params.extra = base
    except Exception:
        pass
    seen = {(o.file, o.line, o.evidence) for o in dst.occurrences}
    for o in src.occurrences:
        if (o.file, o.line, o.evidence) not in seen:
            dst.occurrences.append(o); seen.add((o.file, o.line, o.evidence))
    # dst is always at least as parameter-specific as src (callers sort by
    # specificity), so its name is the authoritative one. Never let a vaguer
    # artefact rename a precise finding (RSA-1024 must not become RSA-SHA-256).


def merge_compatible(artefacts: list[Artefact]) -> list[Artefact]:
    """Merge artefacts whose parameters do not conflict. Order-independent:
    the most-specified artefacts are considered first so wildcards attach to
    them rather than to each other."""
    def specificity(a: Artefact) -> int:
        return sum(1 for f in _FIELDS if getattr(a.params, f, None) is not None)

    out: list[Artefact] = []
    for art in sorted(artefacts, key=specificity, reverse=True):
        for existing in out:
            if _compatible(existing, art):
                _absorb(existing, art)
                break
        else:
            out.append(art)
    for a in out:
        a.occurrences.sort(key=lambda o: (o.file, o.line or 0))
    return out


_HASH_FAMILIES = {"SHA-2", "SHA-3", "SHA-1", "MD5", "BLAKE2", "SHAKE"}
_HASH_BITS = (("512", 512), ("384", 384), ("256", 256), ("224", 224), ("160", 160), ("128", 128))


def infer_missing_params(artefacts: list[Artefact]) -> list[Artefact]:
    """Fill obvious parameters the detectors could not see.

    A hash artefact named "SHA-256" plainly has a 256-bit digest; without it the
    knowledge base cannot classify and the asset falls through as UNKNOWN. This
    only ever fills a value that is unambiguous from the canonical name.
    """
    for a in artefacts:
        if a.params.key_size is None and a.family in _HASH_FAMILIES:
            for token, bits in _HASH_BITS:
                if token in a.name:
                    a.params.key_size = bits
                    break
    return artefacts
