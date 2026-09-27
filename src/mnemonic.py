
import os
import math
import hmac
import ecdsa
import pbkdf2
import hashlib
import unicodedata
import string

from .util import bh2u, bfh

SEED_PREFIX      = '01'
hmac_sha_512 = lambda x, y: hmac.new(x, y, hashlib.sha512).digest()

def seed_prefix(seed_type):
    if seed_type == 'standard':
        return SEED_PREFIX
    

CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F , 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]

def is_CJK(c):
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False
    

def normalize_text(seed):
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed


def load_wordlist(filename):
    path = os.path.join(os.path.dirname(__file__), 'wordlist', filename)
    with open(path, 'r', encoding='utf-8') as f:
        s = f.read().strip()
    s = unicodedata.normalize('NFKD', s)
    lines = s.split('\n')
    wordlist = []
    for line in lines:
        line = line.split('#')[0]
        line = line.strip(' \r')
        assert ' ' not in line
        if line:
            wordlist.append(line)
    return wordlist


filenames = {
    'en':'english.txt',
    'es':'spanish.txt',
    'fr':'french.txt',
    'tr':'turkich.txt',
    'ru':'russian.txt',
    'cz':'czech.txt',
    'ja':'japanese.txt',
    'pt':'portuguese.txt',
    'zh':'chinese_simplified.txt'
}


def is_new_seed(x, prefix=SEED_PREFIX):
    x = normalize_text(x)
    s = bh2u(hmac_sha_512(b"Seed version", x.encode('utf8')))
    return s.startswith(prefix)


def is_old_seed(seed):
    from . import old_mnemonic
    seed = normalize_text(seed)
    words = seed.split()
    try:
        old_mnemonic.mn_decode(words)
        uses_electrum_words = True
    except Exception:
        uses_electrum_words = False
    try:
        seed = bfh(seed)
        is_hex = (len(seed) == 16 or len(seed) == 32)
    except Exception:
        is_hex = False
    return is_hex or (uses_electrum_words and (len(words) == 12 or len(words) == 24))

def seed_type(x):
    if is_old_seed(x):
        return 'old'
    elif is_new_seed(x):
        return 'standard'
    return ''

class Mnemonic(object):

    def __init__(self, lang=None):
        lang = lang or 'en'
        filename = filenames.get(lang[0:2], 'english.txt')
        self.wordlist = load_wordlist(filename)

    @classmethod
    def mnemonic_to_seed(self, mnemonic, passphrase):
        PBKDF2_ROUNDS = 2048
        mnemonic = normalize_text(mnemonic)
        passphrase = normalize_text(passphrase)
        return pbkdf2.PBKDF2(mnemonic, 'electrum' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

    def mnemonic_encode(self, i):
        n = len(self.wordlist)
        words = []
        while i:
            x = i%n
            i = i//n
            words.append(self.wordlist[x])
        return ' '.join(words)

    def get_suggestions(self, prefix):
        for w in self.wordlist:
            if w.startswith(prefix):
                yield w

    def mnemonic_decode(self, seed):
        n = len(self.wordlist)
        words = seed.split()
        i = 0
        while words:
            w = words.pop()
            k = self.wordlist.index(w)
            i = i*n + k
        return i

    def make_seed(self, seed_type='standard', num_bits=132):
        prefix = seed_prefix(seed_type)
        # increase num_bits in order to obtain a uniform distribution for the last word
        bpw = math.log(len(self.wordlist), 2)
        # rounding
        n = int(math.ceil(num_bits/bpw) * bpw)
        entropy = 1
        while entropy < pow(2, n - bpw):
            # try again if seed would not contain enough words
            entropy = ecdsa.util.randrange(pow(2, n))
        nonce = 0
        while True:
            nonce += 1
            i = entropy + nonce
            seed = self.mnemonic_encode(i)
            if i != self.mnemonic_decode(seed):
                raise Exception('Cannot extract same entropy from mnemonic!')
            if is_old_seed(seed):
                continue
            if is_new_seed(seed, prefix):
                break
        return seed