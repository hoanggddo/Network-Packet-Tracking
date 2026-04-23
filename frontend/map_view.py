import folium

def build_map(data):
    if not data:
        return "<h3>No valid mapped traffic found</h3>"

    avg_lat = sum(d["src"]["lat"] for d in data) / len(data)
    avg_lon = sum(d["src"]["lon"] for d in data) / len(data)

    m = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles="CartoDB positron"
    )

    for d in data:
        src = (d["src"]["lat"], d["src"]["lon"])
        dst = (d["dst"]["lat"], d["dst"]["lon"])

        folium.PolyLine(
            [src, dst],
            color="red",
            weight=2,
            opacity=0.7
        ).add_to(m)

        folium.CircleMarker(
            src, radius=3, color="blue"
        ).add_to(m)

        folium.CircleMarker(
            dst, radius=3, color="green"
        ).add_to(m)

    return m._repr_html_()