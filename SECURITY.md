# Security Policy

## Reporting a Vulnerability

We take the security of NextSSL seriously. If you discover a security vulnerability, please follow these guidelines:

1.  **Do NOT create a public GitHub issue.** Publicly disclosing a vulnerability can put users at risk before a patch is available.
2.  **Email the maintainers** directly at **Qudslab@proton.me** or use a private disclosure channel if available.
3.  Include as much detail as possible:
    -   A description of the vulnerability.
    -   Steps to reproduce the issue (proof-of-concept code is highly appreciated).
    -   The version of NextSSL you are using.
    -   Your operating system and compiler details.

We will acknowledge your report within 1 week and provide an estimated timeline for a fix.

## Post-Quantum Security

NextSSL includes implementations of NIST-standardized Post-Quantum Cryptography (PQC) algorithms (Kyber, Dilithium, Falcon, SPHINCS+). While these are based on reference implementations (e.g., PQClean), the field of PQC is evolving. We recommend keeping the library updated to the latest version to ensure you have the latest parameter sets and security fixes.

## Legacy Algorithms

The `legacy/` directory contains algorithms that are considered weak (`alive`) or broken (`unsafe`).
-   **legacy/alive**: (e.g., MD5, SHA-1) Should only be used for compatibility with existing systems, not for new security designs.
-   **legacy/unsafe**: (e.g., MD4, MD2) Included strictly for historical reference or decoding legacy data. **DO NOT USE** these for any security-critical purpose.
