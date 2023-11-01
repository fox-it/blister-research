#!/usr/bin/env python3
#
# file: unpack-mythic-packer.py
# author: Fox-IT, part of NCC Group
#
#  Reconstruct a PE file packed with MythicPacker shellcode.
#
#  The shellcode is decrypted and the mapped PE is reconstructed to a static PE.
#  The static PE is written to a file or stdout.
#

import argparse
import pathlib
import struct
import sys

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

# Copied from https://github.com/fox-it/dissect.cobaltstrike/blob/24444e08fc5fb91d1ca912880f956dc18b9cfd6e/dissect/cobaltstrike/pe.py#L12
pe_defs = """
#define IMAGE_FILE_MACHINE_AMD64    0x8664
#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_IA64     0x0200

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME          8

#define IMAGE_DIRECTORY_ENTRY_EXPORT	0
#define IMAGE_DIRECTORY_ENTRY_IMPORT	1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE	2

typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_SECTION_HEADER {
    char    Name[IMAGE_SIZEOF_SHORT_NAME];
    ULONG   VirtualSize;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG   Characteristics;
        ULONG   OriginalFirstThunk;
    } u;
    ULONG   TimeDateStamp;
    ULONG   ForwarderChain;
    ULONG   Name;
    ULONG   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;     // RVA from base of image
    ULONG   AddressOfNames;         // RVA from base of image
    ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY;
"""

pestruct = cstruct.cstruct()
pestruct.load(pe_defs)


def add32(x: int, y: int) -> int:
    return (x + y) & 0xFFFFFFFF


def and32(x: int, y: int) -> int:
    return (x & y) & 0xFFFFFFFF


def and64(x: int, y: int) -> int:
    return (x & y) & 0xFFFFFFFFFFFFFFFF


def xor32(x: int, y: int) -> int:
    return (x ^ y) & 0xFFFFFFFF


def sub32(x: int, y: int) -> int:
    return (x - y) & 0xFFFFFFFF


def sub64(x: int, y: int) -> int:
    return (x - y) & 0xFFFFFFFFFFFFFFFF


def rol32(x: int, y: int) -> int:
    return ((x << y) | (x >> (32 - y))) & 0xFFFFFFFF


def shr32(x: int, y: int) -> int:
    return (x >> y) & 0xFFFFFFFF


def decrypt_pe(file_data: bytes) -> bytes:
    """
    Receives a blob of shellcode from MythicPacker and tries to decrypt it.
    Algorithm copied from assembly.

    Returns the decrypted file_data starting from the PE buffer that it
    contains.
    """
    file_data = bytearray(file_data)

    # Until now, this has always been the same offsets, i.e. at the start of
    # the shellcode buffer, after the call instruction.
    enc_len = struct.unpack("<I", file_data[0x10:0x14])[0]
    xor_key = struct.unpack("<I", file_data[0x14:0x18])[0]

    # rdx is an address pointing to the start of the encrypted buffer, thus far
    # it always was at relative offset 0x18.
    rdx = 0x18

    # Get the length of the total encrypted buffer, 0x1000-byte aligned.
    len_buf = xor32(enc_len, xor_key)
    len_buf = add32(len_buf, 0xFFF)
    len_buf = and32(len_buf, 0xFFFFF000)

    # Get the 0x1000-byte aligned next address after rdx.
    rdi = add32(rdx, 0xFFF)
    rdi = and64(rdi, 0xFFFFFFFFFFFFF000)

    # nr_dwords = len_buf / 4
    nr_dwords = shr32(len_buf, 2)

    # Initialization.
    rdx += len_buf - 4
    r11 = rdi + len_buf - 4
    ecx = (nr_dwords - 2) % 8
    r11 = sub64(r11, rdx)

    # Start decrypting dwords.
    while nr_dwords:
        # Read encrypted dword.
        v = struct.unpack("<I", file_data[rdx : rdx + 4])[0]

        if nr_dwords <= 1:
            eax = 0
        else:
            # Read the preceding dword.
            eax = struct.unpack("<I", file_data[rdx - 4 : rdx])[0]
            eax = rol32(eax, ecx)
            ecx = (ecx - 1) % 8

        v = xor32(v, xor_key)
        v = sub32(v, eax)

        # Write decrypted dword.
        file_data[rdx + r11 : rdx + r11 + 4] = struct.pack("<I", v)

        rdx -= 4
        nr_dwords -= 1

    # We decrypt from the bottom up, the last 4 bytes we just decrypted are the
    # start of the PE header.
    start_pe = rdx + r11 + 4

    # The decrypted buffer is a PE already mapped in memory, we have to parse
    # the PE header and reconstruct it to a static PE.
    pe_buf = file_data[start_pe:]
    pe_buf[:4] = b"PE\x00\x00"

    return bytes(pe_buf)


def reconstruct_pe(mapped_pe: bytes) -> bytes:
    """
    Reconstructs the PE file from a buffer containing a mapped PE including the
    PE header.

    Returns a buffer containing the reconstructed static PE file.
    """
    # Dummy IMAGE_DOS_HEADER to recreate PE.
    dummy_dos_buf = bytes.fromhex(
        """
    4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
    B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    """
    )

    dummy_dos = pestruct.IMAGE_DOS_HEADER(dummy_dos_buf)

    # PE header directly follows MZ header.
    dummy_dos.e_lfanew = len(dummy_dos)

    # Create a dummy PE, which we use to get the data to reconstruct the correct PE.
    dummy_pe = dummy_dos.dumps() + mapped_pe

    pe = pefile.PE(data=dummy_pe)

    # Reconstruct executable.
    size_reconstructed_pe = pe.OPTIONAL_HEADER.SizeOfImage

    # Sanity check.
    if size_reconstructed_pe > 0xF00000:
        print("Size of reconstructed PE larger than 15MB, probably too large:")
        print(f"  0x{size_reconstructed_pe:x} bytes")
        raise ValueError("Reconstructed PE too large")

    new_pe = bytearray(size_reconstructed_pe)

    # Parse each of the sections and copy them back to their static locations,
    # also save the lowest raw address.
    lowest_addr = 0xFFFFFFFF

    for section in pe.sections:
        # Get mapped section in memory.
        i = section.VirtualAddress
        j = section.PointerToRawData
        section_buf = mapped_pe[i : i + section.SizeOfRawData]
        # Copy mapped section to raw address.
        new_pe[j : j + section.SizeOfRawData] = section_buf
        # Save lowest raw address for when we copy the PE headers.
        if lowest_addr > section.PointerToRawData:
            lowest_addr = section.PointerToRawData

    # Copy the PE buffer up to the start of the first section, i.e. up to the
    # lowest address.
    new_pe[:lowest_addr] = dummy_pe[:lowest_addr]

    return new_pe


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unpacks MythicPacker shellcode in the form of a reconstructed PE file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("file", nargs="?", help="File to unpack", default=None)
    parser.add_argument("-o", "--output", default=None, help="Output file")
    args = parser.parse_args()

    # Either read from a provided file or from stdin.
    if args.file:
        file_data = pathlib.Path(args.file).read_bytes()
    else:
        file_data = sys.stdin.buffer.read()

    # Decrypt the encrypted buffer of MythicPacker and retrieve the mapped PE.
    mapped_pe = decrypt_pe(file_data)
    # Reconstruct static PE from mapped PE buffer.
    try:
        reconstructed_pe = reconstruct_pe(mapped_pe)
    except ValueError:
        print("Reconstructed PE too large, probably not a MythicPacker shellcode.")
        return 1

    # Write new PE to a file or stdout.
    if args.output:
        with open(args.output, "wb") as f:
            f.write(reconstructed_pe)
    else:
        sys.stdout.buffer.write(reconstructed_pe)


if __name__ == "__main__":
    sys.exit(main())
