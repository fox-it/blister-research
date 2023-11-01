# Popping Blisters for research

This repository contains information related to our blog post _Popping Blisters for research: An overview of past payloads and exploring recent developments_, you can read it here:
   * https://blog.fox-it.com/2023/11/01/popping-blisters-for-research-an-overview-of-past-payloads-and-exploring-recent-developments/
   * https://research.nccgroup.com/2023/11/01/popping-blisters-for-research-an-overview-of-past-payloads-and-exploring-recent-developments/

We uploaded an archive containing all the payloads we retrieved from the Blister samples discussed in the blog to VirusTotal. This archive can be found here: 

   * https://www.virustotal.com/gui/file/44b36f5ece88f34259c9d689f4183de90658c6fb39d0c11f14e0b045ee06d06b

# Dumping BlisterMythic configurations

The Mythic agent Blister drops, which we refer to as BlisterMythic, contains a configuration that can be decrypted. The script [dump-blister-mythic-config.py](dump-blister-mythic-config.py) tries to retrieve and decrypt this configuration, assuming it is a PE file. Blister in some cases also drops MythicPacker, which is a shellcode that decrypts and executes a PE file. You can use our other script to reconstruct the packed PE file and then use [dump-blister-mythic-config.py](dump-blister-mythic-config.py) to retrieve the configuration, see the next section.

There are different ways to decrypt the configuration, either by providing the key or using a brute force or known plaintext attack. By default, known plaintext attack is used, but you can specify the key with ``-k`` or ``--key`` or use the brute force attack method by specifying ``-b`` or ``--bruteforce``.

By default, the script dumps the raw bytes of the decrypted configuration. However, you can  provide the ``-ac`` or ``--agent-config`` option to dump the interpreted BlisterMythic agent configuration. To our knowledge, this configuration is not linked to Mythic in general, but specifically to BlisterMythic. Strangely enough, the agent configuration also contains the command-and-control server configuration.

# Unpacking MythicPacker

The script [unpack-mythic-packer.py](unpack-mythic-packer.py) can be used to reconstruct a PE file packed with MythicPacker shellcode. The script is solely based on encountered Blister payloads and assumes that the start of the shellcode is at offset 0. If this is not the case, it will fail. To retrieve the BlisterMythic configuration you could do the following:

```bash
$ python unpack-mythic-packer.py /tmp/mythicpackedfile | python dump-blister-mythic-config.py
```

# Blister samples

[blister-samples.json](blister-samples.json) is a JSON file containing information on the Blister samples we analyzed in the blog. For example, it contains the SHA256 hash of the Blister sample and its payload, the payload label, the configuration flags and some other information as well.

# Cobalt Strike beacons

In [blister-payloads-cobaltstrike-iocs.csv](iocs/blister-payloads-cobaltstrike-iocs.csv), we list the beacon information of the Cobalt Strike beacons we encountered and to what payload they belong. You can use the SHA256 hash to find the corresponding Blister sample, using [blister-samples.json](blister-samples.json).

> [!NOTE]  
> Some beacons are configured to use Domain Fronting, in that case the Host header is shown.

# BlisterMythic

In [blister-payloads-mythic-iocs.csv](iocs/blister-payloads-mythic-iocs.csv), we list the command-and-control domain and the payload SHA256 hash that is linked to it. Similar to the Cobalt Strike beacons, you can use this hash to find the corresponding Blister sample that dropped it, using [blister-samples.json](blister-samples.json).

Furthermore, we included BlisterMythic C2 servers in [blister-mythic-c2s.csv](iocs/blister-mythic-c2s.csv). And our YARA rules in [blister.yara](yara/blister.yara)
