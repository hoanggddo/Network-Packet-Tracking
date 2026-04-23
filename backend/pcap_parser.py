import dpkt
import socket

def extract_ip_pairs(file_path, max_packets=500):
    pairs = set()
    results = []

    with open(file_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for _, buf in pcap:
            if len(results) >= max_packets:
                break

            try:
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data

                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                if (src, dst) in pairs:
                    continue

                pairs.add((src, dst))
                results.append((src, dst))

            except:
                continue

    return results