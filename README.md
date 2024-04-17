# wireshark-dlms

Device Language Message Specification (DLMS) dissector plugin for Wireshark.

The plugin can be used to dissect DLMS protocol, either captured live or imported from a pcap file or hex dump, in TCP packets with destination ports:
- 4059 (the IANA assigned DLMS port)
- 4060-4063 (ports used by GuruxDLMS C++ implementation)
- 4064-4069 (some more ports for user-implementations if desired)

![Screenshot](screenshot.png)

The figure is showing deciphered packets from Gurux DLMS Client-Server communication.
- The ciphering parameters can be modified in file `./include/dlms-keys.h`. Currently, only `Security Suite 0` is supported (`AES-128-GCM` symmetric key encryption and authentication tag).
- The reassembly of Data With-Block is not working perfectly yet.

## Install

### GNU/Linux

1. Install the Wireshark development libraries: sudo apt-get install wireshark-dev
2. Compile the dlms.so plugin: `./build.sh`

## License

These files are distributed under the same license as Wireshark (the GNU General Public License version 2).

## References
1. IEC 62056-5-3:2023 (DLMS Green Book)
2. IEC 62056-6-2:2023 (DLMS Blue Book)
3. [Gurux DLMS C++ implementation](https://github.com/Gurux/Gurux.DLMS.cpp)
4. [GitHub:bearxiong99 Wireshark DLMS plugin template](https://github.com/bearxiong99/wireshark-dlms)