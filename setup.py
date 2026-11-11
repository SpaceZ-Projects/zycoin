from pathlib import Path
from setuptools import setup
README = Path(__file__).resolve().parent / "README.md"

setup(
    name="zycoin",
    version="2.0.0",
    description="Async Python clients and wallet primitives for Electrum, Bitcore, and Lightwalletd networks.",
    long_description=(
        README.read_text(encoding="utf-8") if README.is_file() else ""
    ),
    long_description_content_type="text/markdown",
    author="BitcoinZ Community",
    license="MIT",
    packages=[
        "zycoin",
        "zycoin.clients",
        "zycoin.clients.protocol",
    ],
    package_dir={"zycoin": "src"},
    include_package_data=True,
    package_data={
        "zycoin": [
            "clients/*.py",
            "coins/*.json",
            "wordlist/*.txt",
        ],
        "zycoin.clients.protocol": [
            "*.proto",
            "LICENSE",
        ],
    },
    python_requires=">=3.10",
    install_requires=[
        "ecdsa>=0.19.2",
        "pyaes>=1.6.1",
        "aiohttp>=3.14.3; platform_system != 'Emscripten'",
        "websockets>=16.1.1; platform_system != 'Emscripten'",
        "grpcio>=1.62.3; platform_system != 'Emscripten'",
        "protobuf>=4.25.3; platform_system != 'Emscripten'",
    ],
    keywords=[
        "bitcoinz",
        "btcz",
        "electrum",
        "blockchain",
        "zcash",
        "zycoin",
        "bitcore",
        "zclassic"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)