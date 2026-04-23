import pygeoip

class GeoLocator:
    def __init__(self, db_path):
        self.gi = pygeoip.GeoIP(db_path)

    def lookup(self, ip):
        try:
            data = self.gi.record_by_name(ip)

            if not data:
                return None

            lat = data.get("latitude")
            lon = data.get("longitude")

            if lat is None or lon is None:
                return None

            return {
                "lat": lat,
                "lon": lon
            }

        except:
            return None