<div align="center">

<img src="extra/assets/logo.svg" style="width: 300px;" alt="NextSSL Banner" />

<div align="center" style="background: #e46e0013;color: #ff7b00ff;border:1px solid #eb5e00ff;padding:12px 16px;border-radius:6px;margin-bottom:16px;font-weight:600;">
  This repository is under active development — APIs and features may change without notice.
</div>


</div>


# NextSSL
**Next Super Secure Layer**

NextSSL is a comprehensive, modular cryptographic library designed for the post-quantum era. It provides a unified API for classic primitives, modern high-speed algorithms, and NIST-standardized Post-Quantum Cryptography (PQC).

## 📚 Documentation

- **[Algorithm Catalog](ALGORITHM.md)**: A complete reference of every supported algorithm, variant, and API signature.
- **[Source Map](SOURCE.md)**: A detailed navigation guide to the source code directory structure.

## 🚀 Key Features

- **Post-Quantum Ready**: Full support for ML-KEM (Kyber), ML-DSA (Dilithium), Falcon, SPHINCS+, HQC, and Classic McEliece.
- **High-Performance Hashing**: Optimized implementations of BLAKE3, SHA-256, and SHA-512.
- **Modern Encryption**: Authenticated encryption via AES-GCM, AES-GCM-SIV, and ChaCha20-Poly1305.
- **Elliptic Curves**: Comprehensive ECC suite including Ed25519, X25519, Curve448, and Ristretto255.
- **Modular Architecture**: Granular build system allowing for partial, base, or full library compilation.
- **Python Integration**: Built-in Python test runner and build system.

## 🛠️ Build & Test

NextSSL uses a Python-based runner for building and testing. No external Python dependencies are required.

### Prerequisites
- Python 3.8+
- GCC or compatible C compiler

### Quick Start

**Build and run all tests:**
```bash
python runner.py
```

**Build specific components:**
```bash
python runner.py --build hash      # Build hash primitives
python runner.py --build pqc       # Build PQC modules
python runner.py --build core      # Build core encryption modules
```

**Run specific tests:**
```bash
python runner.py --test hash:fast  # Test fast hash algorithms
python runner.py --test core:aead  # Test AEAD modes
```

For more details on the build system, refer to the `script/` directory.

## 🔒 Security

Security is our top priority. Please see **[SECURITY.md](SECURITY.md)** for our reporting policy and supported versions.

## 🤝 Contributing

We welcome contributions! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for details on our code of conduct and the process for submitting pull requests.

---
*NextSSL — A private Leyline for proper security, whether it's for a server, AI, human, or your pet frog.*
