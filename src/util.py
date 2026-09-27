
import time
import hashlib
import binascii

bfh = bytes.fromhex
hfu = binascii.hexlify

def bh2u(x):
    return binascii.hexlify(x).decode('ascii')

def rev_hex(s):
    return bh2u(bytes.fromhex(s)[::-1])

def int_to_hex(i, length=1):
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    if i < 0:
        i = pow(256, length) + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def profiler(func):
    def do_profile(func, args, kw_args):
        n = func.__name__
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        print("[profiler]", n, "%.4f"%t)
        return o
    return lambda *args, **kw_args: do_profile(func, args, kw_args)

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

def to_bytes(something, encoding='utf8'):
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")
    
def inv_dict(d):
    return {v: k for k, v in d.items()}
    
def sha256(x):
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())

def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except:
        print('assert bytes failed', list(map(type, args)))
        raise

def to_string(x, enc):
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise TypeError("Not a string or bytes like object")