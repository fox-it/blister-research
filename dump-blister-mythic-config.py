#!/usr/bin/env python3
#
# file: dump-blister-mythic-config.py
# author: Fox-IT, part of NCC Group
#
#  Decrypts the configuration section of BlisterMythic.
#
import argparse
import collections
import itertools
import json
import pathlib
import sys
import logging
from ast import literal_eval

try:
    import pefile
except ImportError:
    raise ImportError(f"Could not find pefile. Please run `pip install pefile`.")

try:
    from dissect import cstruct
except ImportError:
    raise ImportError(
        f"Could not find dissec.cstruct. Please run `pip install dissect.cstruct`."
    )

log = logging.getLogger(__name__)

# Quick and dirty BlisterMythic structures.
config_struct = """
struct config_item {
    uint32 len_item;
    uint32 len_buf;
    uint32 possible_checksum;
    char buf[len_buf];
};

struct mythic_config {
    uint32 magic;
    uint32 len;
    uint32 unk1;
    uint32 possible_checksum;
    char buf[len];
};
"""

cparser = cstruct.cstruct()
cparser.load(config_struct)


def uint32(x: int) -> int:
    return x & 0xFFFFFFFF


def rol32(x: int, y: int) -> int:
    return uint32((x << y) | (x >> (32 - y)))


def get_section(data: bytes, section_name: str) -> bytes:
    pe = pefile.PE(data=data)

    # Get data section.
    for section in pe.sections:
        if section.Name.strip(b"\x00") == section_name.encode():
            return section.get_data()

    msg = f"Unable to find the {section_name!r} section!"
    raise ValueError(msg)


def find_key(data: bytes) -> int:
    """
    Find the correct key by using basic statistics (most NULL bytes).
    """
    found_key = bytearray(4)
    for i in range(4):
        bcounter = collections.Counter()
        for c in range(0x100):
            percent = float(c) / 0x100 * 100
            sys.stderr.write(f"\rCalculating key {i}: {percent:.2f}%")
            found_key[i] = c
            # Keep track of how many NULL bytes we have for each byte
            counter = collections.Counter(
                decrypt_config(data, int.from_bytes(found_key, "little"))
            )
            bcounter[c] = counter[0]
        # The byte that resulted in the most NULL bytes wins
        key, count = bcounter.most_common(1).pop()
        sys.stderr.write(f"\rCalculating key {i}: Found 0x{key:02x}!\n")
        found_key[i] = key
    found_key = int.from_bytes(found_key, "little")
    sys.stderr.write(f"XOR key = 0x{key:04x}\n")
    return found_key


def find_key_reverse(data, plaintext=b"\x41\x00\x6c\x00"):
    """Calculate the correct key from first 4 known plaintext bytes."""
    v = int.from_bytes(data[:4], "little")
    x = int.from_bytes(plaintext[:4], "little")
    return abs(~(v | x) | (v & x)) - 1


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)


def decrypt_config(data: bytes, key: int) -> bytes:
    """Decrypt the config in data using key as decryption key."""
    dec_bytes = b""
    z = 0
    for i, block in enumerate(grouper(data, n=4, fillvalue=0)):
        v = int.from_bytes(block, "little")
        x = (~(v & key) & (v | key)) - z
        dec_bytes += uint32(x).to_bytes(4, "little")
        z = rol32(v, i & 7)

    return dec_bytes


def get_agent_dict(config_items: list) -> dict:
    """
    Parse the list of configuration items and retrieve the configuration item
    with the agent dictionary in it. The string seems to be a literal Python
    dictionary imported into the BlisterMythic agent.
    """
    for item in config_items:
        if "'AgentMessage'" in item:
            dict_item = item
            break

    try:
        return literal_eval(dict_item)
    except Exception as e:
        log.error(f"Something went wrong parsing agent dictionary: %r", e)

    return None


def get_config_items(data: bytes) -> list:
    # Find the start of the configuration struct and parse it.
    config_start = data.find(b"JNod")
    mythic_buf = data[config_start:]
    mythic_config = cparser.mythic_config(mythic_buf)

    # print(f"BlisterMythic config length = 0x{mythic_config.len:x}", file=sys.stderr)
    log.info(f"BlisterMythic config length = 0x{mythic_config.len:x}")

    # Loop over the configuration to parse each item until we've reached the
    # the null config.
    config_items = []
    config_buf = mythic_config.buf
    i = 0
    while True:
        # Parse config item and save the buffer.
        config_item = cparser.config_item(config_buf[i:])
        config_items.append(config_item.buf.decode())

        # Stop when we encounter an item of length 0.
        if config_item.len_item == 0:
            break

        # Move to next config element.
        i += config_item.len_item

    return config_items


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decrypt the config section of BlisterMythic.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("file", nargs="?", help="File to decrypt", default=None)
    parser.add_argument(
        "-k", "--key", default=None, help="Force Decryption key (int or hex)"
    )
    parser.add_argument(
        "-b", "--bruteforce", action="store_true", help="Bruteforce Decryption key"
    )
    parser.add_argument("-o", "--output", default=None, help="Output file")
    parser.add_argument(
        "-d",
        "--dump",
        action="store_true",
        default=None,
        help="Dump decrypted configuration blob as raw bytes, enabled if no option is given",
    )
    parser.add_argument(
        "-ac",
        "--agent-config",
        action="store_true",
        default=None,
        help="Dump agent configuration in JSON format",
    )
    args = parser.parse_args()

    # Either read from a provided file or from stdin.
    if args.file:
        file_data = pathlib.Path(args.file).read_bytes()
    else:
        file_data = sys.stdin.buffer.read()

    # Parse PE file and retrieve the .bss section.
    bss_data = get_section(file_data, ".bss")

    # By default, we dump the decrypted configuration blob.
    if not any([args.dump, args.agent_config]):
        args.dump = True

    # Key retrieval methods.
    if args.key:
        key = int(args.key, 0)
    elif args.bruteforce:
        key = find_key(bss_data)
    else:
        key = find_key_reverse(bss_data)

    log.info(f"Using decryption key: 0x{key:08x}")

    # Decrypt the encrypted configuration.
    dec_bytes = decrypt_config(bss_data, key)

    # Retrieve the Agent configuration if applicable.
    if args.agent_config:
        # Parse the BlisterMythic configuration structure.
        config_items = get_config_items(dec_bytes)
        # Get the agent configuration, which is one of the configuration items.
        agent_dict = get_agent_dict(config_items)
        # Get Agent config as JSON string encoded to bytes.
        output = json.dumps(agent_dict, indent=4).encode()
    elif args.dump:
        output = dec_bytes

    if args.output:
        pathlib.Path(args.output).write_bytes(output)
        log.info(f"Dumped BlisterMythic config to {args.output}")
    else:
        sys.stdout.buffer.write(output + b"\n")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    sys.exit(main())
