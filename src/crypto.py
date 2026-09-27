
import base64
import os
import ecdsa
import pyaes
import hmac
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
import hashlib
from .util import *
from . import constants

TYPE_ADDRESS = 0
TYPE_PUBKEY  = 1
TYPE_SCRIPT  = 2

SCRIPT_TYPES = {
    'p2pkh':0,
    'p2sh':5,
}

AES = None

BIP32_PRIME = 0x80000000

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43

def base_decode(v, length, base):
    v = to_bytes(v, 'ascii')
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        digit = chars.find(bytes([c]))
        if digit == -1:
            raise ValueError('Forbidden character {} for base {}'.format(c, base))
        long_value += digit * (base**i)
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)

def b58_address_to_hash160(addr):
    addr = to_bytes(addr, 'ascii')
    _bytes = base_decode(addr, 26, base=58)
    return _bytes[0:2], _bytes[2:22]

def address_to_script(addr):
    addrtype, hash_160 = b58_address_to_hash160(addr)
    if addrtype == constants.net.ADDRTYPE_P2PKH:
        script = '76a9'
        script += push_script(bh2u(hash_160))
        script += '88ac'
    elif addrtype == constants.net.ADDRTYPE_P2SH:
        script = 'a9'
        script += push_script(bh2u(hash_160))
        script += '87'
    else:
        print('unknown address type: {}'.format(addrtype))
    return script

def address_to_scripthash(addr):
    script = address_to_script(addr)
    return script_to_scripthash(script)

def script_to_scripthash(script: str) -> str:
    h = hashlib.sha256(bytes.fromhex(script)).digest()
    return bh2u(h[::-1])

def sha256(x):
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())

def Hash(x):
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out

def base_encode(v, base):
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * c
    result = bytearray()
    while long_value >= base:
        div, mod = divmod(long_value, base)
        result.append(chars[mod])
        long_value = div
    result.append(chars[long_value])
    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0x00:
            nPad += 1
        else:
            break
    result.extend([chars[0]] * nPad)
    result.reverse()
    return result.decode('ascii')

def hash160_to_b58_address(h160, addrtype):
    s = addrtype
    s += h160
    return base_encode(s+Hash(s)[0:4], base=58)

def hash160_to_p2pkh(h160):
    return hash160_to_b58_address(h160, constants.net.ADDRTYPE_P2PKH)

def hash160_to_p2sh(h160):
    return hash160_to_b58_address(h160, constants.net.ADDRTYPE_P2SH)


def script_to_address(script, *, net=None):
    from .transaction import get_address_from_output_script
    t, addr = get_address_from_output_script(bytes.fromhex(script), net=net)
    assert t == TYPE_ADDRESS
    return addr

def rev_hex(s):
    return bh2u(bfh(s)[::-1])


def int_to_hex(i, length=1):
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    if i < 0:
        i = pow(256, length) + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def var_int(i):
    if i<0xfd:
        return int_to_hex(i)
    elif i<=0xffff:
        return "fd"+int_to_hex(i,2)
    elif i<=0xffffffff:
        return "fe"+int_to_hex(i,4)
    else:
        return "ff"+int_to_hex(i,8)

def op_push(i):
    if i<0x4c:
        return int_to_hex(i)
    elif i<=0xff:
        return '4c' + int_to_hex(i)
    elif i<=0xffff:
        return '4d' + int_to_hex(i,2)
    else:
        return '4e' + int_to_hex(i,4)

def push_script(x):
    return op_push(len(x)//2) + x

def public_key_to_p2pk_script(pubkey):
    script = push_script(pubkey)
    script += 'ac'
    return script

def point_to_ser(P, comp=True ):
    if comp:
        return bfh( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) )
    return bfh( '04'+('%064x'%P.x())+('%064x'%P.y()) )

def i2o_ECPublicKey(pubkey, compressed=False):
    if compressed:
        if pubkey.point.y() & 1:
            key = '03' + '%064x' % pubkey.point.x()
        else:
            key = '02' + '%064x' % pubkey.point.x()
    else:
        key = '04' + \
              '%064x' % pubkey.point.x() + \
              '%064x' % pubkey.point.y()

    return bfh(key)

def regenerate_key(pk):
    assert len(pk) == 32
    return EC_KEY(pk)

def GetPubKey(pubkey, compressed=False):
    return i2o_ECPublicKey(pubkey, compressed)


def public_key_from_private_key(pk, compressed):
    pkey = regenerate_key(pk)
    public_key = GetPubKey(pkey.pubkey, compressed)
    return bh2u(public_key)

def hash_160(public_key):
    try:
        md = hashlib.new('ripemd160')
        md.update(sha256(public_key))
        return md.digest()
    except BaseException:
        from . import ripemd
        md = ripemd.new(sha256(public_key))
        return md.digest()

def public_key_to_p2pkh(public_key):
    return hash160_to_p2pkh(hash_160(public_key))


def EncodeBase58Check(vchIn):
    hash = Hash(vchIn)
    return base_encode(vchIn + hash[0:4], base=58)


def serialize_privkey(secret, compressed, txin_type, internal_use=False):
    if internal_use:
        prefix = bytes([(SCRIPT_TYPES[txin_type] + constants.net.WIF_PREFIX) & 255])
    else:
        prefix = bytes([constants.net.WIF_PREFIX])
    suffix = b'\01' if compressed else b''
    vchIn = prefix + secret + suffix
    base58_wif = EncodeBase58Check(vchIn)
    if internal_use:
        return base58_wif
    else:
        return '{}:{}'.format(txin_type, base58_wif)
    

def DecodeBase58Check(psz):
    vchRet = base_decode(psz, None, base=58)
    key = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = Hash(key)
    cs32 = hash[0:4]
    if cs32 != csum:
        raise Exception('expected {}, actual {}'.format(bh2u(cs32), bh2u(csum)))
    else:
        return key
    

def is_minikey(text):
    return (len(text) >= 20 and text[0] == 'S'
            and all(ord(c) in __b58chars for c in text)
            and sha256(text + '?')[0] == 0x00)

def minikey_to_private_key(text):
    return sha256(text)
    

def deserialize_privkey(key):
    if is_minikey(key):
        return 'p2pkh', minikey_to_private_key(key), True

    txin_type = None
    if ':' in key:
        txin_type, key = key.split(sep=':', maxsplit=1)
        if txin_type not in SCRIPT_TYPES:
            raise Exception('unknown script type: {}'.format(txin_type))
    try:
        vch = DecodeBase58Check(key)
    except BaseException:
        neutered_privkey = str(key)[:3] + '..' + str(key)[-2:]
        raise Exception("cannot deserialize privkey {}"
                               .format(neutered_privkey))

    if txin_type is None:
        txin_type = inv_dict(SCRIPT_TYPES)[vch[0] - constants.net.WIF_PREFIX]
    else:
        if vch[0] != constants.net.WIF_PREFIX:
            raise Exception('invalid prefix ({}) for WIF key'.format(vch[0]))

    if len(vch) not in [33, 34]:
        raise Exception('invalid vch len for WIF key: {}'.format(len(vch)))
    compressed = len(vch) == 34
    return txin_type, vch[1:33], compressed


def append_PKCS7_padding(data):
    assert_bytes(data)
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen

def strip_PKCS7_padding(data):
    assert_bytes(data)
    if len(data) % 16 != 0 or len(data) == 0:
        print("invalid length")
    padlen = data[-1]
    if padlen > 16:
        return None
    for i in data[-padlen:]:
        if i != padlen:
            return None
    return data[0:-padlen]

def aes_encrypt_with_iv(key, iv, data):
    assert_bytes(key, iv, data)
    data = append_PKCS7_padding(data)
    if AES:
        e = AES.new(key, AES.MODE_CBC, iv).encrypt(data)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Encrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        e = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return e


def aes_decrypt_with_iv(key, iv, data):
    assert_bytes(key, iv, data)
    if AES:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    else:
        aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
        aes = pyaes.Decrypter(aes_cbc, padding=pyaes.PADDING_NONE)
        data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    try:
        return strip_PKCS7_padding(data)
    except Exception as e:
        print(e)


def EncodeAES(secret, s):
    assert_bytes(s)
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, s)
    e = iv + ct
    return base64.b64encode(e)

def DecodeAES(secret, e):
    e = bytes(base64.b64decode(e))
    iv, e = e[:16], e[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s

def pw_encode(s, password):
    if password:
        secret = Hash(password)
        return EncodeAES(secret, to_bytes(s, "utf8")).decode('utf8')
    else:
        return s
    

def pw_decode(s, password):
    if password is not None:
        secret = Hash(password)
        try:
            d = to_string(DecodeAES(secret, s), "utf8")
        except Exception:
            raise Exception()
        return d
    else:
        return s
    
def deserialize_xkey(xkey, prv, *, net=None):
    xkey = DecodeBase58Check(xkey)
    if len(xkey) != 78:
        raise Exception('Invalid length for extended key: {}'
                               .format(len(xkey)))
    depth = xkey[4]
    fingerprint = xkey[5:9]
    child_number = xkey[9:13]
    c = xkey[13:13+32]
    header = int('0x' + bh2u(xkey[0:4]), 16)
    headers = constants.net.XPRV_HEADERS if prv else constants.net.XPUB_HEADERS
    if header not in headers.values():
        raise Exception('Invalid extended key format: {}'
                               .format(hex(header)))
    xtype = list(headers.keys())[list(headers.values()).index(header)]
    n = 33 if prv else 32
    K_or_k = xkey[13+n:]
    return xtype, depth, fingerprint, child_number, c, K_or_k

def ECC_YfromX(x,curved=curve_secp256k1, odd=True):
    _p = curved.p()
    _a = curved.a()
    _b = curved.b()
    for offset in range(128):
        Mx = x + offset
        My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
        My = pow(My2, (_p+1)//4, _p )

        if curved.contains_point(Mx,My):
            if odd == bool(My&1):
                return [My,offset]
            return [_p-My,offset]
    raise Exception('ECC_YfromX: No Y found')

def ser_to_point(Aser):
    curve = curve_secp256k1
    generator = generator_secp256k1
    _r  = generator.order()
    assert Aser[0] in [0x02, 0x03, 0x04]
    if Aser[0] == 0x04:
        return Point( curve, ecdsa.util.string_to_number(Aser[1:33]), ecdsa.util.string_to_number(Aser[33:]), _r )
    Mx = ecdsa.util.string_to_number(Aser[1:])
    return Point( curve, Mx, ECC_YfromX(Mx, curve, Aser[0] == 0x03)[0], _r )

def CKD_pub(cK, c, n):
    if n & BIP32_PRIME: raise
    return _CKD_pub(cK, c, bfh(rev_hex(int_to_hex(n,4))))


def _CKD_pub(cK, c, s):
    order = generator_secp256k1.order()
    I = hmac.new(c, cK + s, hashlib.sha512).digest()
    curve = SECP256k1
    pubkey_point = ecdsa.util.string_to_number(I[0:32])*curve.generator + ser_to_point(cK)
    public_key = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
    c_n = I[32:]
    cK_n = GetPubKey(public_key.pubkey,True)
    return cK_n, c_n

def CKD_priv(k, c, n):
    is_prime = n & BIP32_PRIME
    return _CKD_priv(k, c, bfh(rev_hex(int_to_hex(n,4))), is_prime)


def _CKD_priv(k, c, s, is_prime):
    order = generator_secp256k1.order()
    keypair = EC_KEY(k)
    cK = GetPubKey(keypair.pubkey,True)
    data = bytes([0]) + k + s if is_prime else cK + s
    I = hmac.new(c, data, hashlib.sha512).digest()
    k_n = ecdsa.util.number_to_string( (ecdsa.util.string_to_number(I[0:32]) + ecdsa.util.string_to_number(k)) % order , order )
    c_n = I[32:]
    return k_n, c_n

def xpub_header(xtype, *, net=None):
    return bfh("%08x" % constants.net.XPUB_HEADERS[xtype])

def xprv_header(xtype, *, net=None):
    return bfh("%08x" % constants.net.XPRV_HEADERS[xtype])

def serialize_xpub(xtype, c, cK, depth=0, fingerprint=b'\x00'*4,
                   child_number=b'\x00'*4, *, net=None):
    xpub = xpub_header(xtype, net=net) \
           + bytes([depth]) + fingerprint + child_number + c + cK
    return EncodeBase58Check(xpub)

def serialize_xprv(xtype, c, k, depth=0, fingerprint=b'\x00'*4,
                   child_number=b'\x00'*4, *, net=None):
    xprv = xprv_header(xtype, net=net) \
           + bytes([depth]) + fingerprint + child_number + c + bytes([0]) + k
    return EncodeBase58Check(xprv)

def deserialize_xpub(xkey, *, net=None):
    return deserialize_xkey(xkey, False, net=net)

def deserialize_xprv(xkey, *, net=None):
    return deserialize_xkey(xkey, True, net=net)
    

def bip32_public_derivation(xpub, branch, sequence):
    xtype, depth, fingerprint, child_number, c, cK = deserialize_xpub(xpub)
    if not sequence.startswith(branch):
        raise ValueError('incompatible branch ({}) and sequence ({})'
                         .format(branch, sequence))
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n)
        parent_cK = cK
        cK, c = CKD_pub(cK, c, i)
        depth += 1
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X"%i)
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)


def get_pubkeys_from_secret(secret):
    # public key
    private_key = ecdsa.SigningKey.from_string( secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    K = public_key.to_string()
    K_compressed = GetPubKey(public_key.pubkey,True)
    return K, K_compressed

def xpub_from_xprv(xprv):
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    K, cK = get_pubkeys_from_secret(k)
    return serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)



def bip32_root(seed, xtype):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_k = I[0:32]
    master_c = I[32:]
    K, cK = get_pubkeys_from_secret(master_k)
    xprv = serialize_xprv(xtype, master_c, master_k)
    xpub = serialize_xpub(xtype, master_c, cK)
    return xprv, xpub


def bip32_private_derivation(xprv, branch, sequence):
    if not sequence.startswith(branch):
        raise ValueError('incompatible branch ({}) and sequence ({})'
                         .format(branch, sequence))
    if branch == sequence:
        return xprv, xpub_from_xprv(xprv)
    xtype, depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        parent_k = k
        k, c = CKD_priv(k, c, i)
        depth += 1
    _, parent_cK = get_pubkeys_from_secret(parent_k)
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X"%i)
    K, cK = get_pubkeys_from_secret(k)
    xpub = serialize_xpub(xtype, c, cK, depth, fingerprint, child_number)
    xprv = serialize_xprv(xtype, c, k, depth, fingerprint, child_number)
    return xprv, xpub


def bip32_private_key(sequence, k, chain):
    for i in sequence:
        k, chain = CKD_priv(k, chain, i)
    return k

def is_b58_address(addr):
    try:
        addrtype, h = b58_address_to_hash160(addr)
    except Exception as e:
        return False
    if addrtype not in [constants.net.ADDRTYPE_P2PKH, constants.net.ADDRTYPE_P2SH]:
        return False
    return addr == hash160_to_b58_address(h, addrtype)

def is_address(addr):
    return is_b58_address(addr)


def is_xpub(text):
    try:
        deserialize_xpub(text)
        return True
    except:
        return False
    
def is_xprv(text):
    try:
        deserialize_xprv(text)
        return True
    except:
        return False
    

def pubkey_to_address(txin_type, pubkey):
    if txin_type == 'p2pkh':
        return public_key_to_p2pkh(bfh(pubkey))
    else:
        raise NotImplementedError(txin_type)
    

def pubkey_from_signature(sig, h):
    if len(sig) != 65:
        raise Exception("Wrong encoding")
    nV = sig[0]
    if nV < 27 or nV >= 35:
        raise Exception("Bad encoding")
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False
    recid = nV - 27
    return MyVerifyingKey.from_signature(sig[1:], recid, h, curve = SECP256k1), compressed
    

def msg_magic(message):
    length = bfh(var_int(len(message)))
    return b"\x18BTCZ Signed Message:\n" + length + message


def verify_message(address, sig, message):
    assert_bytes(sig, message)
    try:
        h = Hash(msg_magic(message))
        public_key, compressed = pubkey_from_signature(sig, h)
        pubkey = point_to_ser(public_key.pubkey.point, compressed)
        for txin_type in ['p2pkh']:
            addr = pubkey_to_address(txin_type, bh2u(pubkey))
            if address == addr:
                break
        else:
            raise Exception("Bad signature")
        public_key.verify_digest(sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
        return True
    except Exception as e:
        return False


class MyVerifyingKey(ecdsa.VerifyingKey):
    @classmethod
    def from_signature(klass, sig, recid, h, curve):
        from ecdsa import util, numbertheory
        from . import msqr
        curveFp = curve.curve
        G = curve.generator
        order = G.order()
        r, s = util.sigdecode_string(sig, order)
        x = r + (recid//2) * order
        alpha = ( x * x * x  + curveFp.a() * x + curveFp.b() ) % curveFp.p()
        beta = msqr.modular_sqrt(alpha, curveFp.p())
        y = beta if (beta - recid) % 2 == 0 else curveFp.p() - beta
        R = Point(curveFp, x, y, order)
        e = ecdsa.util.string_to_number(h)
        minus_e = -e % order
        inv_r = numbertheory.inverse_mod(r,order)
        Q = inv_r * ( s * R + minus_e * G )
        return klass.from_public_point( Q, curve )
    

class MySigningKey(ecdsa.SigningKey):
    def sign_number(self, number, entropy=None, k=None):
        curve = SECP256k1
        G = curve.generator
        order = G.order()
        r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
        if s > order//2:
            s = order - s
        return r, s
    

class EC_KEY(object):

    def __init__( self, k ):
        secret = ecdsa.util.string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( generator_secp256k1, generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret

    def get_public_key(self, compressed=True):
        return bh2u(point_to_ser(self.pubkey.point, compressed))

    def sign(self, msg_hash):
        private_key = MySigningKey.from_secret_exponent(self.secret, curve = SECP256k1)
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_string)
        assert public_key.verify_digest(signature, msg_hash, sigdecode = ecdsa.util.sigdecode_string)
        return signature

    def sign_message(self, message, is_compressed):
        message = to_bytes(message, 'utf8')
        signature = self.sign(Hash(msg_magic(message)))
        for i in range(4):
            sig = bytes([27 + i + (4 if is_compressed else 0)]) + signature
            try:
                self.verify_message(sig, message)
                return sig
            except Exception as e:
                continue
        else:
            raise Exception("error: cannot sign message")

    def verify_message(self, sig, message):
        assert_bytes(message)
        h = Hash(msg_magic(message))
        public_key, compressed = pubkey_from_signature(sig, h)
        if point_to_ser(public_key.pubkey.point, compressed) != point_to_ser(self.pubkey.point, compressed):
            raise Exception("Bad signature")
        public_key.verify_digest(sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)