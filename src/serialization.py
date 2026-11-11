"""Canonical Sapling Bech32 key and payment-address serialization."""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def convert_bits(data, from_bits, to_bits, pad):
    accumulator = 0
    bit_count = 0
    result = []
    maximum = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("value exceeds source bit width")
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & maximum)
    if pad:
        if bit_count:
            result.append((accumulator << (to_bits - bit_count)) & maximum)
    elif bit_count >= from_bits or (
        (accumulator << (to_bits - bit_count)) & maximum
    ):
        raise ValueError("non-canonical bit conversion")
    return result


def _polymod(values):
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(_GENERATORS):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _hrp_expand(hrp):
    return [ord(char) >> 5 for char in hrp] + [0] + [
        ord(char) & 31 for char in hrp
    ]


def bech32_encode(hrp, payload):
    if not hrp or any(ord(char) < 33 or ord(char) > 126 for char in hrp):
        raise ValueError("invalid Bech32 human-readable prefix")
    if hrp.lower() != hrp and hrp.upper() != hrp:
        raise ValueError("mixed-case Bech32 prefix")
    data = convert_bits(payload, 8, 5, True)
    polymod = _polymod(_hrp_expand(hrp.lower()) + data + [0] * 6) ^ 1
    checksum = [
        (polymod >> (5 * (5 - index))) & 31 for index in range(6)
    ]
    return hrp.lower() + "1" + "".join(
        CHARSET[value] for value in data + checksum
    )


def bech32_decode(encoded):
    if not isinstance(encoded, str) or not 8 <= len(encoded) <= 1023:
        raise ValueError("invalid Bech32 string length")
    if encoded.lower() != encoded and encoded.upper() != encoded:
        raise ValueError("mixed-case Bech32 string")
    encoded = encoded.lower()
    separator = encoded.rfind("1")
    if separator < 1 or separator + 7 > len(encoded):
        raise ValueError("invalid Bech32 separator")
    hrp = encoded[:separator]
    try:
        data = [CHARSET.index(char) for char in encoded[separator + 1:]]
    except ValueError as exc:
        raise ValueError("invalid Bech32 character") from exc
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("invalid Bech32 checksum")
    return hrp, bytes(convert_bits(data[:-6], 5, 8, False))
