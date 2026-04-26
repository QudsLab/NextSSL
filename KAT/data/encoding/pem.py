# PEM — RFC 7468 textual encoding of DER-encoded data
meta = {
    "group": "encoding",
    "algorithm": "pem",
    "source": "rfc",
    "source_ref": "RFC 7468 / KAT/repo/encoding/pem",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # Minimal RSA public key PEM  (synthetic, valid DER header + 64-byte payload)
    {
        "id": "pem-rsa-pubkey-0001",
        "label": "PUBLIC KEY",
        "der_hex": (
            "30819f300d06092a864886f70d010101050003818d00308189"
            "028181009e22"  # truncated for illustration — real key below
        ),
        "pem": (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeIg==\n"
            "-----END PUBLIC KEY-----\n"
        ),
        "note": "Illustrative — decoder must accept CRLF or LF line endings",
    },
    # Certificate PEM parse check (label extraction)
    {
        "id": "pem-cert-label-0001",
        "label": "CERTIFICATE",
        "pem": (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIC\n"
            "-----END CERTIFICATE-----\n"
        ),
        "note": "Minimal — parser must return label=CERTIFICATE and base64 body",
    },
    # Encrypted private key label
    {
        "id": "pem-enc-key-0001",
        "label": "ENCRYPTED PRIVATE KEY",
        "pem": (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            "MIIB\n"
            "-----END ENCRYPTED PRIVATE KEY-----\n"
        ),
        "note": "Parser must handle multi-word labels with spaces",
    },
    # Multiple PEM objects in one stream
    {
        "id": "pem-multi-0001",
        "count": 2,
        "pem": (
            "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        ),
        "note": "Parser must return two objects",
    },
    {"id": 5, "label": 'CERTIFICATE REQUEST', "der_hex": '308200', "pem": '-----BEGIN CERTIFICATE REQUEST-----\nMIIA\n-----END CERTIFICATE REQUEST-----\n'},
    {"id": 6, "label": 'PRIVATE KEY', "der_hex": '308204a7020100', "pem": '-----BEGIN PRIVATE KEY-----\nMIIEpwIBAA==\n-----END PRIVATE KEY-----\n'},
    {"id": 7, "label": 'RSA PRIVATE KEY', "der_hex": '3082025c0201000281', "pem": '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKB\n-----END RSA PRIVATE KEY-----\n'},
    {"id": 8, "label": 'EC PRIVATE KEY', "der_hex": '303e0201010420', "pem": '-----BEGIN EC PRIVATE KEY-----\nMD4CAQEEIA==\n-----END EC PRIVATE KEY-----\n'},
    {"id": 9, "label": 'EC PARAMETERS', "der_hex": '06082a8648ce3d030107', "pem": '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n'},
    {"id": 10, "label": 'TRUSTED CERTIFICATE', "der_hex": '30820324308201', "pem": '-----BEGIN TRUSTED CERTIFICATE-----\nMIIDJDCCAQ==\n-----END TRUSTED CERTIFICATE-----\n'},
    {"id": 11, "label": 'X509 CRL', "der_hex": '30820145308200', "pem": '-----BEGIN X509 CRL-----\nMIIBRTCCAA==\n-----END X509 CRL-----\n'},
    {"id": 12, "label": 'CERTIFICATE', "der_hex": '3082aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "pem": '-----BEGIN CERTIFICATE-----\nMIKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\nqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\nqqqqqqqq\n-----END CERTIFICATE-----\n'},
    {"id": 13, "label": 'PUBLIC KEY', "der_hex": '30819f300d06092a864886f70d01010105000381', "pem": '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4E=\n-----END PUBLIC KEY-----\n'},
    {"id": 14, "label": 'NEW CERTIFICATE REQUEST', "der_hex": '308201080201', "pem": '-----BEGIN NEW CERTIFICATE REQUEST-----\nMIIBCAIB\n-----END NEW CERTIFICATE REQUEST-----\n'},
    {"id": 15, "label": 'DH PARAMETERS', "der_hex": '30820108020201', "pem": '-----BEGIN DH PARAMETERS-----\nMIIBCAICAQ==\n-----END DH PARAMETERS-----\n'},
    {"id": 16, "label": 'DSA PRIVATE KEY', "der_hex": '3081fa020100028181', "pem": '-----BEGIN DSA PRIVATE KEY-----\nMIH6AgEAAoGB\n-----END DSA PRIVATE KEY-----\n'},
    {"id": 17, "label": 'OPENSSH PRIVATE KEY', "der_hex": '6f70656e7373682d6b65792d76310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', "pem": '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END OPENSSH PRIVATE KEY-----\n'},
    {"id": 18, "label": 'PKCS7', "der_hex": '30800609600000000000000000000000000000000000000000', "pem": '-----BEGIN PKCS7-----\nMIAGCWAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PKCS7-----\n'},
    {"id": 19, "label": 'CMS', "der_hex": '30820100060960864801650304020105', "pem": '-----BEGIN CMS-----\nMIIBAAYJYIZIAWUDBAIBBQ==\n-----END CMS-----\n'},
    {"id": 20, "label": 'ATTRIBUTE CERTIFICATE', "der_hex": '308201', "pem": '-----BEGIN ATTRIBUTE CERTIFICATE-----\nMIIB\n-----END ATTRIBUTE CERTIFICATE-----\n'},

]
