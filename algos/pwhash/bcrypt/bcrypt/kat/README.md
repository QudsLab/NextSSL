# KAT provenance: bcrypt

- Openwall crypt_blowfish-1.3.tar.gz https://www.openwall.com/crypt/crypt_blowfish-1.3.tar.gz sha256 `83fa01fca6996fe8d882b7f8e9ba0305a5664936100b01481ea3c6a8ce8d72fd`, file wrapper.c, table `tests[][3]`.
- Not included: `$2x$` vectors (emulate a historical sign-extension bug), and 12 vectors whose password is longer than 71 bytes (the reference truncates; this adapter refuses).

- `crypt_blowfish.json` sha256 `4d5bd16966f85fe364279d7ada1ea7bdc2ad85828c8a008776e7fce4a07062c9`
