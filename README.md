# PCAP Network Mapper

## Overview

The PCAP Network Mapper is a desktop application that analyzes packet capture (PCAP) files and visualizes network traffic as an interactive graph in a web browser. It extracts IP addresses from captured packets, optionally resolves them using GeoIP data, and displays communication paths between network nodes.

The goal of this tool is to help users understand network behavior by visualizing connections between devices in a clear and interactive way.

---

## Features

- Load and parse `.pcap` and `.cap` files
- Extract source and destination IP addresses from packets
- Optional GeoIP resolution using MaxMind GeoLite2 database
- Interactive network visualization using Leaflet.js in a browser
- Graph-based representation of network traffic flows
- Automatic clustering for private IP addresses (LAN visualization)
- Desktop GUI for selecting and processing PCAP files
- Automatic generation and opening of an HTML visualization

---

## Requirements

### Python Version
- Python 3.8 or newer

### Python Dependencies

Install required packages:

```bash
pip install dpkt PyQt5 geoip2
```

## Usage

Run the application:

```bash
python pcap.py
```

---
## Steps

1. Launch the application  
2. Click **Open PCAP**  
3. Select a `.pcap` or `.cap` file  
4. The tool processes the file  
5. A browser window opens showing the network visualization  


