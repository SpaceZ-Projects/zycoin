from pathlib import Path
from setuptools import setup
README = Path(__file__).resolve().parent / "README.md"

setup(
    name="zycoin",
    version="1.0.0",
    description="Python client library for BitcoinZ and related Zcoin-family blockchain networks using Electrum and Bitcore APIs.",
    long_description=README.read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="BitcoinZ Community",
    license="MIT",
    packages=["zycoin"],
    package_dir={"zycoin": "src"},
    package_data={
        'zycoin': [
            'wordlist/*.txt'
        ]
    },
    python_requires=">=3.10",
    install_requires=[
        "ecdsa>=0.19.2",
        "pbkdf2>=1.3",
        "pyaes>=1.6.1",
        "aiohttp>=3.14.3; platform_system != 'Emscripten'",
        "websockets>=16.1.1; platform_system != 'Emscripten'"
    ],
    keywords=[
        "bitcoinz",
        "btcz",
        "electrum",
        "blockchain",
        "zcash",
        "zycoin"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)