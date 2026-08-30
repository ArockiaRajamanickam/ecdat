# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

Scans a codebase for cryptography, flags what a quantum computer will break
(RSA, ECC/ECDH, Diffie-Hellman via Shor's algorithm), ranks urgency with
Mosca's theorem, and prescribes the exact NIST post-quantum replacement
(ML-KEM, ML-DSA). Emits a CycloneDX CBOM. Runs offline.

SIH 2026 · Problem Statement SIH26164 (NTRO) · Team WEB Shooters.

## Run it on your own machine (scan your own code, offline)
    pip install -r requirements.txt
    ECDAT_LOCAL=1 uvicorn app.server:app --port 8000
Open http://localhost:8000, then type the path to any folder on your computer
and click **Scan folder**. Your code never leaves your machine.

(On Windows PowerShell: `$env:ECDAT_LOCAL=1; uvicorn app.server:app --port 8000`)

## Scan from the command line
    python app/ecdat.py <path-to-repo>
