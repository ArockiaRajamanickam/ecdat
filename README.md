# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

Finds every use of cryptography in a codebase, classifies what a quantum computer
will break, ranks it by urgency, and prescribes the exact NIST post-quantum
replacement. Emits a CycloneDX CBOM and SARIF. Runs entirely offline.

**Smart India Hackathon 2026 · Problem Statement SIH26164 (NTRO) · Team WEB Shooters**

```
sources ──┐
certs ────┤
deps  ────┼─► detectors ─► normalize ─► risk (Mosca X+Y>Z) ─► recommend ─► CBOM / SARIF / report / CI gate
TLS   ────┘
```

## What it finds

| Input | Detector | Extracts |
|---|---|---|
| Python | tree-sitter + alias resolution | key sizes, curves, cipher modes, padding |
| JavaScript / TypeScript | tree-sitter | WebCrypto, node:crypto, JWT, forge, crypto-js |
| Java | tree-sitter | `Cipher.getInstance` transformations, key sizes |
| Go | tree-sitter | `crypto/*` packages, curve + key size |
| X.509 certs & keys | `cryptography` | family, key size, curve, signature hash, expiry |
| Dependency manifests | requirements / package.json / pom / go.mod / Cargo | crypto libraries + versions |
| Live TLS endpoint | stdlib `ssl` | negotiated version, cipher, peer key |

Four risk tiers, kept distinct on purpose: **quantum-broken** (Shor), **classically
broken** (MD5, SHA-1, DES, RC4 — these need no quantum computer), **Grover-weakened**,
and **quantum-safe / PQC**.

## Quick start

```bash
pip install -r requirements.txt

python app/engine/cli.py scan   ./my-project          # scan, print summary
python app/engine/cli.py report ./my-project          # markdown report
python app/engine/cli.py ci     ./my-project --fail-on critical   # CI gate
ECDAT_LOCAL=1 uvicorn app.server:app --port 8000      # dashboard
```

## Prescriptive, never guessed

Replacements are a deterministic lookup keyed to FIPS 203/204/205 — a model cannot
hallucinate them. Where a fix is mechanically safe (`hashlib.md5(` → `hashlib.sha256(`)
ECDAT emits a real unified diff you can `git apply`. Where it is not — replacing RSA
key transport with ML-KEM is a design change, not a text substitution — it says
**manual review** rather than guessing.

## Prior art

Scanning is not new: IBM's [CBOMkit](https://github.com/IBM/CBOM) is open source and
good. ECDAT's contribution is the layer on top — Mosca-based prioritisation driven by
an editable `policy.yaml`, prescriptive fixes, SARIF + CI gating, and a build that runs
air-gapped with nothing leaving the machine.

## Credits

Built by **Team WEB Shooters**. The engine architecture — the asset model with
provenance, policy-driven risk, and the CI gate — was shaped by a parallel
implementation by **richa**, merged into this codebase.

## Licence

MIT.
