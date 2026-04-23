import dpkt
import socket
import pygeoip

gi = pygeoip.GeoIP('GeoLiteCity.dat')


def retKML(dstip, srcip):
    try:
        dst = gi.record_by_name(dstip)
        src = gi.record_by_name(srcip)

        # if GeoIP fails, return fallback point
        if not dst or not src:
            return f"""
<Placemark>
    <name>{srcip} -> {dstip}</name>
    <Point>
        <coordinates>-77.0369,38.9072,0</coordinates>
    </Point>
</Placemark>
"""

        # validate coordinates exist
        if not all(k in dst for k in ['longitude', 'latitude']):
            return ""
        if not all(k in src for k in ['longitude', 'latitude']):
            return ""

        # skip identical points (noise reduction)
        if (src['longitude'] == dst['longitude'] and
            src['latitude'] == dst['latitude']):
            return ""

        return f"""
<Placemark>
    <name>{dstip}</name>
    <LineString>
        <coordinates>
            {src['longitude']},{src['latitude']},0
            {dst['longitude']},{dst['latitude']},0
        </coordinates>
    </LineString>
</Placemark>
"""

    except:
        return ""


def plotIPs(pcap):
    kml = ''
    count = 0
    MAX_PLACEMARKS = 500

    seen = set()  # prevents duplicates

    for ts, buf in pcap:
        if count >= MAX_PLACEMARKS:
            break

        try:
            eth = dpkt.ethernet.Ethernet(buf)

            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data

            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            # skip duplicates
            pair = (src, dst)
            if pair in seen:
                continue
            seen.add(pair)

            piece = retKML(dst, src)
            if piece:
                kml += piece
                count += 1

        except:
            continue

    return kml


def main():
    with open('wiresharkdump.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        kmlheader = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
<Style id="transBluePoly">
<LineStyle>
    <width>1.5</width>
    <color>7dff0000</color>
</LineStyle>
</Style>
"""

        kmlfooter = """
</Document>
</kml>
"""

        kmldoc = kmlheader + "\n<Folder><name>Connections</name>\n" + plotIPs(pcap) + "\n</Folder>\n" + kmlfooter
        print("KML size:", len(kmldoc))
        with open("output.kml", "w", encoding="utf-8") as out:
            out.write(kmldoc)

        print("KML file created: output.kml")


if __name__ == "__main__":
    main()