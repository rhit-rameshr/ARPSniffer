# ARP Sniffer and Database Logger

This project captures ARP (Address Resolution Protocol) packets on the network and logs the MAC and IP addresses into an SQLite database. The application uses the Scapy library for packet sniffing and SQLite for database management.

## Features

- Captures ARP packets from the network.
- Extracts source and destination MAC and IP addresses.
- Stores captured addresses in an SQLite database.
- Avoids duplicate entries in the database.

## Requirements

- Python 3.x
- Scapy
- SQLite3
- keyboard (optional for stopping the process with Ctrl+C)

You can install the required Python packages using pip:

```bash
pip install scapy keyboard
