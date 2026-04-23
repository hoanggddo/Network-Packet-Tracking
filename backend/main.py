from backend.pcap_parser import extract_ip_pairs
from backend.geo import GeoLocator

def is_private(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.")
    )


def process_pcap(file_path, geo_db):
    geo = GeoLocator(geo_db)

    pairs = extract_ip_pairs(file_path)

    enriched = []

    for src, dst in pairs:

        # 1. skip private-private traffic early
        if is_private(src) and is_private(dst):
            continue

        src_geo = geo.lookup(src)
        dst_geo = geo.lookup(dst)

        # skip private traffic early
        if is_private(src) and is_private(dst):
            continue

        # only plot if BOTH endpoints are valid
        if not src_geo or not dst_geo:
            continue

        enriched.append({
            "src_ip": src,
            "dst_ip": dst,

        })

    print("Total enriched pairs:", len(enriched))
    return enriched