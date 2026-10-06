
class Coin:
    NAME = None
    SYMBOL = None

    WIF_PREFIX = None
    ADDRTYPE_P2PKH = None
    ADDRTYPE_P2SH = None

    DEFAULT_PORTS = {}
    SERVERS = []
    BITCORE_API = None

    XPUB_HEADERS = {}
    XPRV_HEADERS = {}

    BRANCH_ID = None

    @classmethod
    def set_as_network(cls) -> None:
        global net
        net = cls


class BitcoinZ(Coin):

    NAME = "BitcoinZ"
    SYMBOL = "BTCZ"

    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = bytes.fromhex('1CB8')
    ADDRTYPE_P2SH = bytes.fromhex('1CBD')
    DEFAULT_PORTS = {'t': '50001', 's': '50002', 'w': '50004'}

    SERVERS = [
        "electrum1.btcz.rocks",
        "electrum2.btcz.rocks",
        "electrum4.btcz.rocks"
    ]

    BITCORE_API = "https://explorer.btcz.rocks/"

    XPRV_HEADERS = {
        'standard':    0x0488ade4,
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,
    }

    BRANCH_ID = 0xe9ff75a6


class ZeroCurrency(Coin):

    NAME = "Zero"
    SYMBOL = "ZER"

    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = bytes.fromhex('1CB8')
    ADDRTYPE_P2SH = bytes.fromhex('1CBD')
    DEFAULT_PORTS = {'t': '50001', 's': '50002', 'w': '50004'}

    SERVERS = []

    BITCORE_API = "https://explorer.zer.zelcore.io/"
    
    XPRV_HEADERS = {
        'standard':    0x0488ade4,
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,
    }

    BRANCH_ID = 0x7361707a



class Zclassic(Coin):

    NAME = "Zclassic"
    SYMBOL = "ZCL"

    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = bytes.fromhex('1CB8')
    ADDRTYPE_P2SH = bytes.fromhex('1CBD')
    DEFAULT_PORTS = {'t': '50001', 's': '50002', 'w': '50004'}
    
    SERVERS = []

    BITCORE_API = "https://explorer.zcl.zelcore.io/"

    XPRV_HEADERS = {
        'standard':    0x0488ade4,
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,
    }

    BRANCH_ID = 0x930b540d


class Flux(Coin):

    NAME = "Flux"
    SYMBOL = "FLUX"

    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = bytes.fromhex('1CB8')
    ADDRTYPE_P2SH = bytes.fromhex('1CBD')
    DEFAULT_PORTS = {'t': '50001', 's': '50002', 'w': '50004'}
    
    SERVERS = [
        "electrumx.runonflux.io",
        "electrumx2.runonflux.io"
    ]

    BITCORE_API = "https://explorer.runonflux.io/"

    XPRV_HEADERS = {
        'standard':    0x0488ade4,
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,
    }

    BRANCH_ID = 0x76b809bb



class ZeroClassic(Coin):

    NAME = "ZeroClassic"
    SYMBOL = "ZERC"

    WIF_PREFIX = 0x80
    ADDRTYPE_P2PKH = bytes.fromhex('1CB8')
    ADDRTYPE_P2SH = bytes.fromhex('1CBD')
    DEFAULT_PORTS = {'t': '50001', 's': '50002', 'w': '50004'}
    
    SERVERS = []

    BITCORE_API = "https://insight.zeroclassic.org/"

    XPRV_HEADERS = {
        'standard':    0x0488ade4,
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,
    }

    BRANCH_ID = 0x7a737763



COINS = {
    BitcoinZ.SYMBOL.lower(): BitcoinZ,
    Flux.SYMBOL.lower(): Flux,
    Zclassic.SYMBOL.lower(): Zclassic,
    ZeroClassic.SYMBOL.lower(): ZeroClassic,
    ZeroCurrency.SYMBOL.lower(): ZeroCurrency,
}

net = BitcoinZ

def set_coin(coin):
    global net

    key = coin.strip().lower()
    if key not in COINS:
        raise ValueError(f"Unknown coin: {coin}")
    net = COINS[key]
    return net