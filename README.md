# Basic Network Sniffer

## Project Overview
This project is a Basic Network Sniffer developed using Python. The program captures and analyzes live network traffic packets moving through a local network interface. It is designed to assist in understanding lower-level data encapsulation and packet structure up the network stack.

## Objective
The objective of this project is to build a utility tool that listens to a network interface hardware card, intercepts live data streams, and displays structured packets including source/destination IP addresses, protocol types (TCP/UDP/ICMP), and application layer payloads.

## Technologies Used
* **Python 3**
* **Scapy Library** (Packet manipulation and decoding)
* **Npcap Driver** (Windows packet capture library)
* **Windows / Git Bash** (Development & testing environment)

## Features
* **Real-Time Analysis:** Intercepts live network data streams seamlessly.
* **Layer Dissection:** Decodes structural layers from Layer 3 (Network) to Layer 7 (Application).
* **Protocol Mapping:** Automatically translates IANA protocol numbers into recognizable human strings (`TCP`, `UDP`, `ICMP`).
* **Payload Scoping:** Safely extracts and presents raw payloads using standard text decoding parameters to inspect underlying application headers.
* **Graceful Termination:** Catching system interrupts (`Ctrl + C`) to close sockets and release network cards cleanly.

## Installation
1. Install Python 3 on your Windows system.
2. Install the **Npcap** packet capture driver for Windows (ensure *WinPcap API-compatible mode* is checked during setup).
3. Open your terminal and install Scapy using pip:
   ```bash
   pip install scapy
