"""ECDAT output serializers: CycloneDX CBOM, Markdown report, SARIF.

Each submodule is importable on its own and depends only on the stdlib, so a
missing optional dependency elsewhere in the engine can never take the reporting
path down with it.
"""

from __future__ import annotations

__all__ = ["to_cbom", "to_cbom_json", "to_markdown", "to_sarif", "to_sarif_json"]


def __getattr__(name: str):  # lazy re-export, keeps import cost near zero
    if name in ("to_cbom", "to_cbom_json"):
        from . import cbom

        return getattr(cbom, name)
    if name == "to_markdown":
        from . import report

        return report.to_markdown
    if name in ("to_sarif", "to_sarif_json"):
        from . import sarif

        return getattr(sarif, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
