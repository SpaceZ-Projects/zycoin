
import struct
import hashlib
from . import crypto
from . import constants
from .keystore import xpubkey_to_pubkey
import ecdsa

NO_SIGNATURE = 'ff'
SAPLING_VERSION_GROUP_ID = 0x892F2085
OVERWINTERED_VERSION_GROUP_ID = 0x03C48270
SAPLING_BRANCH_ID = 0x76B809BB


class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, _bytes):
        if self.input is None:
            self.input = bytearray(_bytes)
        else:
            self.input += bytearray(_bytes)

    def read_string(self, encoding='ascii'):
        if self.input is None:
            raise ("call write(bytes) before trying to deserialize")

        length = self.read_compact_size()

        return self.read_bytes(length).decode(encoding)

    def write_string(self, string, encoding='ascii'):
        string = crypto.to_bytes(string, encoding)
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor+length]
            self.read_cursor += length
            return result
        except IndexError:
            raise ("attempt to read past end of buffer")
        

    def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
    def read_int16(self): return self._read_num('<h')
    def read_uint16(self): return self._read_num('<H')
    def read_int32(self): return self._read_num('<i')
    def read_uint32(self): return self._read_num('<I')
    def read_int64(self): return self._read_num('<q')
    def read_uint64(self): return self._read_num('<Q')

    def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
    def write_int16(self, val): return self._write_num('<h', val)
    def write_uint16(self, val): return self._write_num('<H', val)
    def write_int32(self, val): return self._write_num('<i', val)
    def write_uint32(self, val): return self._write_num('<I', val)
    def write_int64(self, val): return self._write_num('<q', val)
    def write_uint64(self, val): return self._write_num('<Q', val)

    def read_compact_size(self):
        try:
            size = self.input[self.read_cursor]
            self.read_cursor += 1
            if size == 253:
                size = self._read_num('<H')
            elif size == 254:
                size = self._read_num('<I')
            elif size == 255:
                size = self._read_num('<Q')
            return size
        except IndexError:
            raise ("attempt to read past end of buffer")

    def write_compact_size(self, size):
        if size < 0:
            raise ("attempt to write size < 0")
        elif size < 253:
            self.write(bytes([size]))
        elif size < 2**16:
            self.write(b'\xfd')
            self._write_num('<H', size)
        elif size < 2**32:
            self.write(b'\xfe')
            self._write_num('<I', size)
        elif size < 2**64:
            self.write(b'\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        try:
            (i,) = struct.unpack_from(format, self.input, self.read_cursor)
            self.read_cursor += struct.calcsize(format)
        except Exception as e:
            raise (e)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


class EnumException(Exception):
    pass

class Enumeration:
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = { }
        reverseLookup = { }
        i = 0
        uniqueNames = [ ]
        uniqueValues = [ ]
        for x in enumList:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumException("enum name is not a string: " + x)
            if not isinstance(i, int):
                raise EnumException("enum value is not an integer: " + i)
            if x in uniqueNames:
                raise EnumException("enum name is not unique: " + x)
            if i in uniqueValues:
                raise EnumException("enum value is not unique for " + x)
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup

    def __getattr__(self, attr):
        if attr not in self.lookup:
            raise AttributeError
        return self.lookup[attr]
    def whatis(self, value):
        return self.reverseLookup[value]


opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1",76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT", "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    ("OP_NOP1", 0xB0),
    ("OP_CHECKLOCKTIMEVERIFY", 0xB1), ("OP_CHECKSEQUENCEVERIFY", 0xB2),
    "OP_NOP4", "OP_NOP5", "OP_NOP6", "OP_NOP7", "OP_NOP8", "OP_NOP9", "OP_NOP10",
    ("OP_INVALIDOPCODE", 0xFF),
])


def script_GetOp(_bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = _bytes[i]
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                nSize = _bytes[i]
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                (nSize,) = struct.unpack_from('<H', _bytes, i)
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', _bytes, i)
                i += 4
            vch = _bytes[i:i + nSize]
            i += nSize

        yield opcode, vch, i


def script_GetOpName(opcode):
    return (opcodes.whatis(opcode)).replace("OP_", "")


def parse_scriptSig(d, _bytes):
    try:
        decoded = [ x for x in script_GetOp(_bytes) ]
    except Exception as e:
        print("parse_scriptSig: cannot find address in input script (coinbase?)",
                    crypto.bh2u(_bytes))
        return
    
def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and decoded[i][0] <= opcodes.OP_PUSHDATA4 and decoded[i][0]>0:
            continue
        if to_match[i] != decoded[i][0]:
            return False
    return True

hash_encode = lambda x: crypto.bh2u(x[::-1])

def parse_input(vds):
    d = {}
    prevout_hash = hash_encode(vds.read_bytes(32))
    prevout_n = vds.read_uint32()
    scriptSig = vds.read_bytes(vds.read_compact_size())
    sequence = vds.read_uint32()
    d['prevout_hash'] = prevout_hash
    d['prevout_n'] = prevout_n
    d['sequence'] = sequence
    d['x_pubkeys'] = []
    d['pubkeys'] = []
    d['signatures'] = {}
    d['address'] = None
    d['num_sig'] = 0
    if prevout_hash == '00'*32:
        d['type'] = 'coinbase'
        d['scriptSig'] = crypto.bh2u(scriptSig)
    else:
        d['type'] = 'unknown'
        if scriptSig:
            d['scriptSig'] = crypto.bh2u(scriptSig)
            try:
                parse_scriptSig(d, scriptSig)
            except BaseException:
                print('failed to parse scriptSig', crypto.bh2u(scriptSig))
        else:
            d['scriptSig'] = ''

    return d

def get_address_from_output_script(_bytes, *, net=None):
    decoded = [x for x in script_GetOp(_bytes)]
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG ]
    if match_decoded(decoded, match):
        return crypto.TYPE_PUBKEY, crypto.bh2u(decoded[0][1])

    match = [ opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG ]
    if match_decoded(decoded, match):
        return crypto.TYPE_ADDRESS, crypto.hash160_to_p2pkh(decoded[2][1], net=net)

    match = [ opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUAL ]
    if match_decoded(decoded, match):
        return crypto.TYPE_ADDRESS, crypto.hash160_to_p2sh(decoded[1][1], net=net)

    return crypto.TYPE_SCRIPT, crypto.bh2u(_bytes)


def parse_output(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    scriptPubKey = vds.read_bytes(vds.read_compact_size())
    d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
    d['scriptPubKey'] = crypto.bh2u(scriptPubKey)
    d['prevout_n'] = i
    return d


def parse_join_split(vds):
    d = {}
    d['vpub_old'] = vds.read_uint64()
    d['vpub_new'] = vds.read_uint64()
    d['anchor'] = vds.read_bytes(32)
    d['nullifiers'] = vds.read_bytes(64)
    d['commitments'] = vds.read_bytes(64)
    d['ephemeralKey'] = vds.read_bytes(32)
    d['randomSeed'] = vds.read_bytes(32)
    d['vmacs'] = vds.read_bytes(64)
    d['zkproof'] = vds.read_bytes(296)
    d['encCiphertexts'] = vds.read_bytes(1202)
    return d


def deserialize(raw):
    vds = BCDataStream()
    vds.write(bytes.fromhex(raw))
    d = {}

    header = vds.read_uint32()
    overwintered = True if header & 0x80000000 else False
    version = header & 0x7FFFFFFF

    if overwintered:
        if version not in [3, 4]:
            raise ('Overwintered transaction'
                                          ' with invalid version=%d' % version)
        ver_group_id = vds.read_uint32()
        if (version == 3 and ver_group_id != OVERWINTERED_VERSION_GROUP_ID or
            version == 4 and ver_group_id != SAPLING_VERSION_GROUP_ID):
            raise ('Overwintered transaction with wrong'
                                          ' versionGroupId=%X' % ver_group_id)
        d['versionGroupId'] = ver_group_id

    d['overwintered'] = overwintered
    d['version'] = version

    n_vin = vds.read_compact_size()
    d['inputs'] = [parse_input(vds) for i in range(n_vin)]
    n_vout = vds.read_compact_size()
    d['outputs'] = [parse_output(vds, i) for i in range(n_vout)]
    d['lockTime'] = vds.read_uint32()

    if overwintered:
        d['expiryHeight'] = vds.read_uint32()

        if version == 4:
            d['valueBalance'] = vds.read_int64()
            n_sh_sp = vds.read_compact_size()
            if n_sh_sp > 0:
                d['shieldedSpends'] = vds.read_bytes(n_sh_sp*384)
            n_sh_out = vds.read_compact_size()
            if n_sh_out > 0:
                d['shieldedOutputs'] = vds.read_bytes(n_sh_out*948)

        n_js = vds.read_compact_size()
        if n_js > 0:
            if version == 3:
                d['joinSplits'] = [parse_join_split(vds) for i in range(n_js)]
            else:
                d['joinSplits'] = vds.read_bytes(n_js*1698)
            d['joinSplitPubKey'] = vds.read_bytes(32)
            d['joinSplitSig'] = vds.read_bytes(64)
            if version == 4:
                d['bindingSig'] = vds.read_bytes(64)

    return d


def multisig_script(public_keys, m):
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = format(opcodes.OP_1 + m - 1, 'x')
    op_n = format(opcodes.OP_1 + n - 1, 'x')
    keylist = [crypto.op_push(len(k)//2) + k for k in public_keys]
    return op_m + ''.join(keylist) + op_n + 'ae'


class Transaction:

    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, raw):
        if raw is None:
            self.raw = None
        elif isinstance(raw, str):
            self.raw = raw.strip() if raw else None
        elif isinstance(raw, dict):
            self.raw = raw['hex']
        else:
            raise Exception("cannot initialize transaction", raw)
        self._inputs = None
        self._outputs = None
        self.locktime = 0
        self.version = 4
        self.overwintered = True
        self.versionGroupId = SAPLING_VERSION_GROUP_ID
        self.expiryHeight = 0
        self.valueBalance = 0
        self.shieldedSpends = None
        self.shieldedOutputs = None
        self.joinSplits = None
        self.joinSplitPubKey = None
        self.joinSplitSig = None
        self.bindingSig = None

    def update(self, raw):
        self.raw = raw
        self._inputs = None
        self.deserialize()

    def inputs(self):
        if self._inputs is None:
            self.deserialize()
        return self._inputs

    def outputs(self):
        if self._outputs is None:
            self.deserialize()
        return self._outputs

    @classmethod
    def get_sorted_pubkeys(self, txin):
        if txin['type'] == 'coinbase':
            return [], []
        x_pubkeys = txin['x_pubkeys']
        pubkeys = txin.get('pubkeys')
        if pubkeys is None:
            pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
            pubkeys, x_pubkeys = zip(*sorted(zip(pubkeys, x_pubkeys)))
            txin['pubkeys'] = pubkeys = list(pubkeys)
            txin['x_pubkeys'] = x_pubkeys = list(x_pubkeys)
        return pubkeys, x_pubkeys

    def update_signatures(self, raw):
        """Add new signatures to a transaction"""
        d = deserialize(raw)
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            sigs1 = txin.get('signatures')
            sigs2 = d['inputs'][i].get('signatures')
            for sig in sigs2:
                if sig in sigs1:
                    continue
                pre_hash = crypto.Hash(crypto.bfh(self.serialize_preimage(i)))
                order = ecdsa.ecdsa.generator_secp256k1.order()
                r, s = ecdsa.util.sigdecode_der(crypto.bfh(sig[:-2]), order)
                sig_string = ecdsa.util.sigencode_string(r, s, order)
                compressed = True
                for recid in range(4):
                    public_key = crypto.MyVerifyingKey.from_signature(sig_string, recid, pre_hash, curve = crypto.SECP256k1)
                    pubkey = crypto.bh2u(crypto.point_to_ser(public_key.pubkey.point, compressed))
                    if pubkey in pubkeys:
                        public_key.verify_digest(sig_string, pre_hash, sigdecode = ecdsa.util.sigdecode_string)
                        j = pubkeys.index(pubkey)
                        print("adding sig", i, j, pubkey, sig)
                        self._inputs[i]['signatures'][j] = sig
                        break
        self.raw = self.serialize()

    def deserialize(self):
        if self.raw is None:
            return
        if self._inputs is not None:
            return
        d = deserialize(self.raw)
        self._inputs = d['inputs']
        self._outputs = [(x['type'], x['address'], x['value']) for x in d['outputs']]
        self.locktime = d['lockTime']
        self.version = d['version']
        self.overwintered = d['overwintered']
        self.versionGroupId = d.get('versionGroupId')
        self.expiryHeight = d.get('expiryHeight', 0)
        self.valueBalance = d.get('valueBalance', 0)
        self.shieldedSpends = d.get('shieldedSpends')
        self.shieldedOutputs = d.get('shieldedOutputs')
        self.joinSplits = d.get('joinSplits')
        self.joinSplitPubKey = d.get('joinSplitPubKey')
        self.joinSplitSig = d.get('joinSplitSig')
        self.bindingSig = d.get('bindingSig')
        return d

    @classmethod
    def from_io(klass, inputs, outputs, locktime=0):
        self = klass(None)
        self._inputs = inputs
        self._outputs = outputs
        self.locktime = locktime
        return self

    @classmethod
    def pay_script(self, output_type, addr):
        if output_type == crypto.TYPE_SCRIPT:
            return addr
        elif output_type == crypto.TYPE_ADDRESS:
            return crypto.address_to_script(addr)
        elif output_type == crypto.TYPE_PUBKEY:
            return crypto.public_key_to_p2pk_script(addr)
        else:
            raise TypeError('Unknown output type')

    @classmethod
    def estimate_pubkey_size_from_x_pubkey(cls, x_pubkey):
        try:
            if x_pubkey[0:2] in ['02', '03']:
                return 0x21
            elif x_pubkey[0:2] == '04':
                return 0x41
            elif x_pubkey[0:2] == 'ff':
                return 0x21
            elif x_pubkey[0:2] == 'fe':
                return 0x41
        except Exception as e:
            pass
        return 0x21

    @classmethod
    def estimate_pubkey_size_for_txin(cls, txin):
        pubkeys = txin.get('pubkeys', [])
        x_pubkeys = txin.get('x_pubkeys', [])
        if pubkeys and len(pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(pubkeys[0])
        elif x_pubkeys and len(x_pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(x_pubkeys[0])
        else:
            return 0x21
    @classmethod
    def get_siglist(self, txin, estimate_size=False):
        if txin['type'] == 'coinbase':
            return [], []
        num_sig = txin.get('num_sig', 1)
        if estimate_size:
            pubkey_size = self.estimate_pubkey_size_for_txin(txin)
            pk_list = ["00" * pubkey_size] * len(txin.get('x_pubkeys', [None]))
            sig_list = [ "00" * 0x48 ] * num_sig
        else:
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            x_signatures = txin['signatures']
            signatures = list(filter(None, x_signatures))
            is_complete = len(signatures) == num_sig
            if is_complete:
                pk_list = pubkeys
                sig_list = signatures
            else:
                pk_list = x_pubkeys
                sig_list = [sig if sig else NO_SIGNATURE for sig in x_signatures]
        return pk_list, sig_list

    @classmethod
    def input_script(self, txin, estimate_size=False):
        _type = txin['type']
        if _type == 'coinbase':
            return txin['scriptSig']
        pubkeys, sig_list = self.get_siglist(txin, estimate_size)
        script = ''.join(crypto.push_script(x) for x in sig_list)
        if _type == 'p2pk':
            pass
        elif _type == 'p2sh':
            script = '00' + script
            redeem_script = multisig_script(pubkeys, txin['num_sig'])
            script += crypto.push_script(redeem_script)
        elif _type == 'p2pkh':
            script += crypto.push_script(pubkeys[0])
        elif _type == 'address':
            script += crypto.push_script(pubkeys[0])
        elif _type == 'unknown':
            return txin['scriptSig']
        return script

    @classmethod
    def is_txin_complete(cls, txin):
        if txin['type'] == 'coinbase':
            return True
        num_sig = txin.get('num_sig', 1)
        x_signatures = txin['signatures']
        signatures = list(filter(None, x_signatures))
        return len(signatures) == num_sig

    @classmethod
    def get_preimage_script(self, txin):
        pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
        if txin['type'] == 'p2pkh':
            return crypto.address_to_script(txin['address'])
        elif txin['type'] in ['p2sh']:
            return multisig_script(pubkeys, txin['num_sig'])
        elif txin['type'] == 'p2pk':
            pubkey = pubkeys[0]
            return crypto.public_key_to_p2pk_script(pubkey)
        else:
            raise TypeError('Unknown txin type', txin['type'])

    @classmethod
    def serialize_outpoint(self, txin):
        return crypto.bh2u(crypto.bfh(txin['prevout_hash'])[::-1]) + crypto.int_to_hex(txin['prevout_n'], 4)

    @classmethod
    def get_outpoint_from_txin(cls, txin):
        if txin['type'] == 'coinbase':
            return None
        prevout_hash = txin['prevout_hash']
        prevout_n = txin['prevout_n']
        return prevout_hash + ':%d' % prevout_n

    @classmethod
    def serialize_input(self, txin, script):
        s = self.serialize_outpoint(txin)
        s += crypto.var_int(len(script)//2)
        s += script
        s += crypto.int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
        return s

    def BIP_LI01_sort(self):
        self._inputs.sort(key = lambda i: (i['prevout_hash'], i['prevout_n']))
        self._outputs.sort(key = lambda o: (o[2], self.pay_script(o[0], o[1])))

    def serialize_output(self, output):
        output_type, addr, amount = output
        s = crypto.int_to_hex(amount, 8)
        script = self.pay_script(output_type, addr)
        s += crypto.var_int(len(script)//2)
        s += script
        return s

    def serialize_join_split(self, js):
        s = crypto.int_to_hex(js['vpub_old'], 8)
        s += crypto.int_to_hex(js['vpub_new'], 8)
        s += js['anchor']
        s += js['nullifiers']
        s += js['commitments']
        s += js['ephemeralKey']
        s += js['randomSeed']
        s += js['vmacs']
        s += js['zkproof']
        s += js['encCiphertexts']
        return s

    def serialize_preimage(self, i):
        overwintered = self.overwintered
        version = self.version
        nHashType = crypto.int_to_hex(1, 4)
        nLocktime = crypto.int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txin = inputs[i]
        if overwintered:
            nHeader = crypto.int_to_hex(0x80000000 | version, 4)
            nVersionGroupId = crypto.int_to_hex(self.versionGroupId, 4)
            s_prevouts = crypto.bfh(''.join(self.serialize_outpoint(txin) for txin in inputs))
            hashPrevouts = hashlib.blake2b(s_prevouts, digest_size=32, person=b'ZcashPrevoutHash').hexdigest()
            s_sequences = crypto.bfh(''.join(crypto.int_to_hex(txin.get('sequence', 0xffffffff - 1), 4) for txin in inputs))
            hashSequence = hashlib.blake2b(s_sequences, digest_size=32, person=b'ZcashSequencHash').hexdigest()
            s_outputs = crypto.bfh(''.join(self.serialize_output(o) for o in outputs))
            hashOutputs = hashlib.blake2b(s_outputs, digest_size=32, person=b'ZcashOutputsHash').hexdigest()
            hashJoinSplits = '00'*32
            hashShieldedSpends = '00'*32
            hashShieldedOutputs = '00'*32
            nExpiryHeight = crypto.int_to_hex(self.expiryHeight, 4)
            nValueBalance = crypto.int_to_hex(self.valueBalance, 8)

            txin = inputs[i]

            preimage_script = self.get_preimage_script(txin)
            scriptCode = crypto.var_int(len(preimage_script) // 2) + preimage_script
            preimage = (
                nHeader + nVersionGroupId + hashPrevouts + hashSequence + hashOutputs
                + hashJoinSplits + hashShieldedSpends + hashShieldedOutputs + nLocktime
                + nExpiryHeight + nValueBalance + nHashType
                + self.serialize_outpoint(txin)
                + scriptCode
                + crypto.int_to_hex(txin['value'], 8)
                + crypto.int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
            )
        else:
            nVersion = crypto.int_to_hex(version, 4)
            txins = crypto.var_int(len(inputs)) + ''.join(self.serialize_input(txin, self.get_preimage_script(txin) if i==k else '') for k, txin in enumerate(inputs))
            txouts = crypto.var_int(len(outputs)) + ''.join(self.serialize_output(o) for o in outputs)
            preimage = nVersion + txins + txouts + nLocktime + nHashType
        return preimage

    def serialize(self, estimate_size=False):
        nVersion = crypto.int_to_hex(self.version, 4)
        nLocktime = crypto.int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txins = crypto.var_int(len(inputs)) + ''.join(self.serialize_input(txin, self.input_script(txin, estimate_size)) for txin in inputs)
        txouts = crypto.var_int(len(outputs)) + ''.join(self.serialize_output(o) for o in outputs)
        if self.overwintered:
            nVersion = crypto.int_to_hex(0x80000000 | self.version, 4)
            nVersionGroupId = crypto.int_to_hex(self.versionGroupId, 4)
            nExpiryHeight = crypto.int_to_hex(self.expiryHeight, 4)
            nValueBalance = crypto.int_to_hex(self.valueBalance, 8)
            return (nVersion + nVersionGroupId + txins + txouts + nLocktime
                    + nExpiryHeight + nValueBalance + '00' + '00' + '00')
        else:
            return nVersion + txins + txouts + nLocktime

    def hash(self):
        print("warning: deprecated tx.hash()")
        return self.txid()

    def txid(self):
        if not self.is_complete():
            return None
        ser = self.serialize()
        return crypto.bh2u(crypto.Hash(crypto.bfh(ser))[::-1])

    def add_inputs(self, inputs):
        self._inputs.extend(inputs)
        self.raw = None

    def add_outputs(self, outputs):
        self._outputs.extend(outputs)
        self.raw = None

    def input_value(self):
        return sum(x['value'] for x in self.inputs())

    def output_value(self):
        return sum(val for tp, addr, val in self.outputs())

    def get_fee(self):
        return self.input_value() - self.output_value()

    def is_final(self):
        return not any([x.get('sequence', 0xffffffff - 1) < 0xffffffff - 1 for x in self.inputs()])

    @crypto.profiler
    def estimated_size(self):
        weight = self.estimated_weight()
        return self.virtual_size_from_weight(weight)

    @classmethod
    def estimated_input_weight(cls, txin):
        '''Return an estimate of serialized input weight in weight units.'''
        script = cls.input_script(txin, True)
        input_size = len(cls.serialize_input(txin, script)) // 2
        return 4 * input_size

    @classmethod
    def estimated_output_size(cls, address):
        """Return an estimate of serialized output size in bytes."""
        script = crypto.address_to_script(address)
        return 9 + len(script) // 2

    @classmethod
    def virtual_size_from_weight(cls, weight):
        return weight // 4 + (weight % 4 > 0)

    def estimated_total_size(self):
        """Return an estimated total transaction size in bytes."""
        return len(self.serialize(True)) // 2 if not self.is_complete() or self.raw is None else len(self.raw) // 2  # ASCII hex string

    def estimated_base_size(self):
        """Return an estimated base transaction size in bytes."""
        return self.estimated_total_size()

    def estimated_weight(self):
        """Return an estimate of transaction weight."""
        total_tx_size = self.estimated_total_size()
        base_tx_size = self.estimated_base_size()
        return 3 * base_tx_size + total_tx_size

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs():
            if txin['type'] == 'coinbase':
                continue
            signatures = list(filter(None, txin.get('signatures',[])))
            s += len(signatures)
            r += txin.get('num_sig',-1)
        return s, r

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    def sign(self, keypairs):
        for i, txin in enumerate(self.inputs()):
            num = txin['num_sig']
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            for j, x_pubkey in enumerate(x_pubkeys):
                signatures = list(filter(None, txin['signatures']))
                if len(signatures) == num:
                    break
                if x_pubkey in keypairs.keys():
                    sec, compressed = keypairs.get(x_pubkey)
                    pubkey = crypto.public_key_from_private_key(sec, compressed)
                    if self.overwintered:
                        data = crypto.bfh(self.serialize_preimage(i))
                        person = b'ZcashSigHash' + constants.net.BRANCH_ID.to_bytes(4, 'little')
                        pre_hash = hashlib.blake2b(data, digest_size=32, person=person).digest()
                    else:
                        pre_hash = crypto.Hash(crypto.bfh(self.serialize_preimage(i)))
                    pkey = crypto.regenerate_key(sec)
                    secexp = pkey.secret
                    private_key = crypto.MySigningKey.from_secret_exponent(secexp, curve = crypto.SECP256k1)
                    public_key = private_key.get_verifying_key()
                    sig = private_key.sign_digest_deterministic(pre_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der_canonize)
                    if not public_key.verify_digest(sig, pre_hash, sigdecode = ecdsa.util.sigdecode_der):
                        raise Exception('Sanity check verifying our own signature failed.')
                    txin['signatures'][j] = crypto.bh2u(sig) + '01'
                    txin['pubkeys'][j] = pubkey
                    self._inputs[i] = txin
        self.raw = self.serialize()

    def get_outputs(self):
        """convert pubkeys to addresses"""
        o = []
        for type, x, v in self.outputs():
            if type == crypto.TYPE_ADDRESS:
                addr = x
            elif type == crypto.TYPE_PUBKEY:
                addr = crypto.public_key_to_p2pkh(crypto.bfh(x))
            else:
                addr = 'SCRIPT ' + x
            o.append((addr,v))
        return o

    def get_output_addresses(self):
        return [addr for addr, val in self.get_outputs()]


    def has_address(self, addr):
        return (addr in self.get_output_addresses()) or (addr in (tx.get("address") for tx in self.inputs()))

    def as_dict(self):
        if self.raw is None:
            self.raw = self.serialize()
        self.deserialize()
        out = {
            'hex': self.raw,
            'complete': self.is_complete(),
            'final': self.is_final(),
        }
        return out