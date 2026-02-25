# Author: Futhark1393
# Description: Ed25519 digital signature support for forensic audit trails.
# Provides key generation, signing, and verification.

import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


def generate_signing_keypair(output_dir: str) -> tuple[str, str]:
    """
    Generate an Ed25519 keypair and write PEM files to *output_dir*.

    Returns (private_key_path, public_key_path).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = os.path.join(output_dir, "rfi_signing.key")
    pub_path = os.path.join(output_dir, "rfi_signing.pub")

    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
    os.chmod(priv_path, 0o600)

    with open(pub_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return priv_path, pub_path


def _load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def _load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        key = load_pem_public_key(f.read())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key


def sign_audit_trail(audit_file: str, private_key_path: str) -> str:
    """
    Sign *audit_file* with the Ed25519 private key at *private_key_path*.

    Writes a detached signature to ``<audit_file>.sig`` and returns its path.
    """
    private_key = _load_private_key(private_key_path)

    with open(audit_file, "rb") as f:
        data = f.read()

    signature = private_key.sign(data)

    sig_path = audit_file + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    return sig_path


def verify_audit_signature(
    audit_file: str, sig_path: str, public_key_path: str
) -> tuple[bool, str]:
    """
    Verify the detached Ed25519 signature for *audit_file*.

    Returns (ok, message).
    """
    if not os.path.exists(audit_file):
        return False, f"Audit file not found: {audit_file}"
    if not os.path.exists(sig_path):
        return False, f"Signature file not found: {sig_path}"
    if not os.path.exists(public_key_path):
        return False, f"Public key not found: {public_key_path}"

    try:
        public_key = _load_public_key(public_key_path)

        with open(audit_file, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()

        public_key.verify(signature, data)
        return True, "Digital signature is valid."

    except Exception as e:
        return False, f"Signature verification failed: {e}"
