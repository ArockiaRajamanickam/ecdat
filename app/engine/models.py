"""ECDAT core data model. Every detector and serializer speaks this language."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Threat(str, Enum):
    SHOR_BROKEN = "shor_broken"          # public-key broken by Shor (RSA/ECC/DH/Ed…)
    LEGACY_BROKEN = "legacy_broken"      # already broken classically (MD5/SHA-1/DES/RC4)
    GROVER_WEAKENED = "grover_weakened"  # symmetric/hash weakened but not broken
    QUANTUM_SAFE = "quantum_safe"        # AES-256, SHA-384+, ChaCha20
    PQC = "pqc"                          # ML-KEM / ML-DSA / SLH-DSA / Falcon
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.NONE: 4}


@dataclass
class Occurrence:
    """Where an artefact was seen. Provenance is non-negotiable: file + line."""
    file: str
    line: int | None = None
    evidence: str = ""            # the matched source text / description
    detector: str = ""            # which detector produced it
    confidence: str = "high"      # high | low


@dataclass
class Params:
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None       # GCM / CBC / ECB …
    padding: str | None = None
    not_after: str | None = None  # cert expiry (ISO)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Artefact:
    """A deduplicated cryptographic asset, with every place it was seen."""
    name: str                              # canonical display, e.g. "RSA-1024"
    family: str                            # RSA | ECDSA | X25519 | AES | SHA-2 | ML-KEM …
    kind: str = "algorithm"                # algorithm | certificate | key | library | protocol
    params: Params = field(default_factory=Params)
    occurrences: list[Occurrence] = field(default_factory=list)

    # filled by the risk engine
    threat: Threat = Threat.UNKNOWN
    threat_reason: str = ""
    severity: Severity = Severity.NONE
    score: float = 0.0
    data_class: str = ""
    x_years: int = 0
    y_years: int = 0
    mosca_act_now: bool = False
    mosca_shortfall: int = 0
    criticality: float = 0.0

    # filled by the recommender
    recommendation: str = ""
    rec_rationale: str = ""
    trade_offs: dict[str, str] = field(default_factory=dict)
    fix_patch: str = ""                    # unified diff, when we can generate one

    def key(self) -> str:
        return f"{self.family}|{self.params.key_size}|{self.params.curve}|{self.params.mode}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat"] = self.threat.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    target: str
    artefacts: list[Artefact] = field(default_factory=list)
    files_scanned: int = 0
    started: str = ""
    finished: str = ""
    policy_name: str = "default"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"target": self.target, "files_scanned": self.files_scanned,
                "started": self.started, "finished": self.finished,
                "policy_name": self.policy_name, "errors": self.errors,
                "artefacts": [a.to_dict() for a in self.artefacts]}
