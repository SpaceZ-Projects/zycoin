"""BIP-39 English 24-word generation, validation, and seed derivation."""

import hashlib
import hmac
import os
import unicodedata
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent / "wordlist" / "english.txt"
_WORDLIST = None


def _wordlist():
    global _WORDLIST
    if _WORDLIST is None:
        words = WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
        if len(words) != 2048 or len(set(words)) != 2048:
            raise RuntimeError("BIP-39 English wordlist must contain 2048 unique words")
        _WORDLIST = words
    return _WORDLIST


def _normalize(value):
    if not isinstance(value, str):
        raise ValueError("BIP-39 input must be text")
    return unicodedata.normalize("NFKD", value)


def _entropy_to_mnemonic(entropy):
    if not isinstance(entropy, bytes) or len(entropy) != 32:
        raise ValueError("BIP-39 24-word phrases require exactly 32 entropy bytes")
    checksum = hashlib.sha256(entropy).digest()[0]
    bit_string = f"{int.from_bytes(entropy, 'big'):0256b}{checksum:08b}"
    words = _wordlist()
    return " ".join(
        words[int(bit_string[offset:offset + 11], 2)]
        for offset in range(0, 264, 11)
    )


def generate_mnemonic():
    """Generate a 24-word phrase from 256 bits of operating-system entropy."""
    return _entropy_to_mnemonic(os.urandom(32))


def validate_mnemonic(mnemonic):
    """Return whether text is a valid 24-word English BIP-39 phrase."""
    if not isinstance(mnemonic, str):
        return False
    words = _normalize(mnemonic).strip().split()
    if len(words) != 24:
        return False
    word_indices = {word: index for index, word in enumerate(_wordlist())}
    try:
        bit_string = "".join(f"{word_indices[word]:011b}" for word in words)
    except KeyError:
        return False
    entropy = int(bit_string[:256], 2).to_bytes(32, "big")
    actual_checksum = bit_string[256:]
    expected_checksum = f"{hashlib.sha256(entropy).digest()[0]:08b}"
    return hmac.compare_digest(actual_checksum, expected_checksum)


def is_valid_mnemonic(mnemonic):
    """Alias for callers that prefer an is_* validation name."""
    return validate_mnemonic(mnemonic)


def mnemonic_to_seed(mnemonic, passphrase=""):
    """Derive the standard 64-byte BIP-39 seed from a valid 24-word phrase."""
    if not validate_mnemonic(mnemonic):
        raise ValueError("invalid 24-word English BIP-39 mnemonic")
    if passphrase is None:
        passphrase = ""
    if not isinstance(passphrase, str):
        raise ValueError("BIP-39 passphrase must be text")
    normalized_mnemonic = _normalize(" ".join(_normalize(mnemonic).split()))
    normalized_passphrase = _normalize(passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512",
        normalized_mnemonic.encode("utf-8"),
        ("mnemonic" + normalized_passphrase).encode("utf-8"),
        2048,
        dklen=64,
    )
