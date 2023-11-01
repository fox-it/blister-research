rule shellcode_obfuscator
{
    meta:
        author = "Fox-IT, part of NCC Group"
        os = "Windows"
        arch = "x86-64"
        description = "Detects shellcode packed with unknown obfuscator observed in Blister samples."
        reference_sample = "178ffbdd0876b99ad1c2d2097d9cf776eca56b540a36c8826b400cd9d5514566"
    strings:
        $rol_ror = { 48 C1 ?? ?? ?? 48 C1 ?? ?? ?? 48 C1 ?? ?? ?? }
        $mov_rol_mov = { 4d ?? ?? ?? 49 c1 ?? ?? ?? 4d ?? ?? ?? }
        $jmp = { 49 81 ?? ?? ?? ?? ?? 41 ?? }
    condition:
        #rol_ror > 60 and $jmp and filesize < 2MB and #mov_rol_mov > 60
}

import "pe"
import "math"

rule blister_x64_windows_loader {
    meta:
        author = "Fox-IT, part of NCC Group"
        os = "Windows"
        arch = "x86-64"
        family = "Blister"
        description = "Detects Blister loader component injected into legitimate executables."
        reference_sample = "343728792ed1e40173f1e9c5f3af894feacd470a9cdc72e4f62c0dc9cbf63fc1, 8d53dc0857fa634414f84ad06d18092dedeb110689a08426f08cb1894c2212d4, a5fc8d9f9f4098e2cecb3afc66d8158b032ce81e0be614d216c9deaf20e888ac"
    strings:
        // 65 48 8B 04 25 60 00 00 00                          mov     rax, gs:60h
        $inst_1 = {65 48 8B 04 25 60 00 00 00}
        // 48 8D 87 44 6D 00 00                                lea     rax, [rdi+6D44h]
        $inst_2 = {48 8D 87 44 6D 00 00}
        // 44 69 C8 95 E9 D1 5B                                imul    r9d, eax, 5BD1E995h
        $inst_3 = {44 ?? ?? 95 E9 D1 5B}
        // 41 81 F9 94 85 09 64                                cmp     r9d, 64098594h
        $inst_4 = {41 ?? ?? 94 85 09 64}
        // B8 FF FF FF 7F                                      mov     eax, 7FFFFFFFh
        $inst_5 = {B8 FF FF FF 7F}
        // 48 8D 4D 48                                         lea     rcx, [rbp+48h]
        $inst_6 = {48 8D 4D 48}
    condition:
        uint16(0) == 0x5A4D and
        all of ($inst_*) and
        pe.number_of_resources > 0 and
        for any i in (0..pe.number_of_resources - 1):
            ( (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 6) and
                pe.resources[i].length > 200000 
            )
}

rule blister_mythic_payload {
    meta:
        author = "Fox-IT, part of NCC Group"
        os = "Windows"
        arch = "x86-64"
        family = "BlisterMythic"
        description = "Detects specific Mythic agent dropped by Blister."
        reference_samples = "2fd38f6329b9b2c5e0379a445e81ece43fe0372dec260c1a17eefba6df9ffd55, 3d2499e5c9b46f1f144cfbbd4a2c8ca50a3c109496a936550cbb463edf08cd79, ab7cab5192f0bef148670338136b0d3affe8ae0845e0590228929aef70cb9b8b, f89cfbc1d984d01c57dd1c3e8c92c7debc2beb5a2a43c1df028269a843525a38"
    strings:
        $start_inst = { 48 83 EC 28 B? [4-8] E8 ?? ?? 00 00 }
        $for_inst = { 48 2B C8 0F 1F 00 C6 04 01 00 48 2D 00 10 00 00 }
    condition:
        all of them
}

rule mythic_packer
{
    meta:
        author = "Fox-IT, part of NCC Group"
        os = "Windows"
        arch = "x86-64"
        family = "MythicPacker"
        description = "Detects specific PE packer dropped by Blister."
        reference_samples = "9a08d2db7d0bd7d4251533551d4def0f5ee52e67dff13a2924191c8258573024, 759ac6e54801e7171de39e637b9bb525198057c51c1634b09450b64e8ef47255"
    strings:
        // 41 81 38 72 47 65 74        cmp     dword ptr [r8], 74654772h
        $a = { 41 ?? ?? 72 47 65 74 }
        // 41 81 38 72 4C 6F 61        cmp     dword ptr [r8], 616F4C72h
        $b = { 41 ?? ?? 72 4C 6F 61 }
        // B8 01 00 00 00              mov     eax, 1
        // C3                          retn
        $c = { B8 01 00 00 00 C3 }
    condition:
        all of them and uint8(0) == 0x48
}
