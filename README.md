# Iridium
A genshin packet sniffer + visualizer in 1


# Usage

0. Bring your `packetIds.json` to the `backend/` folder.

1. Capture your Genshin session from the point of login with Wireshark, tcpdump or any other suitable packet capturer.

> Strongly recommended to filter it with `udp portrange 22101-22102` before saving to `.pcap`.

2. Save it to .pcap format (not pcap-ng).

3. Feed to the tool via `node . path/to/pcap.pcap`.

4. The output will be serialized into `bins/`.