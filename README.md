# Roku Pi-hole DNS Redirector

A Python tool that redirects DNS queries from Roku devices to a Pi-hole server without needing router access or configuration changes.

## Overview

This tool uses ARP spoofing techniques to intercept DNS queries from your Roku device and redirect them to your Pi-hole server. This allows you to block ads and trackers on your Roku device even if you:

- Don't have access to your router's settings
- Can't change the DNS settings on your Roku device
- Are in a managed network environment (apartment, dorm, etc.)

## Features

- Intercepts DNS queries from Roku devices
- Redirects queries to Pi-hole for ad blocking
- Text-based interactive interface
- Command-line arguments for scripting
- Comprehensive logging with configurable log levels
- Works on Windows, macOS, and Linux

## Requirements

- Python 3.6+
- Scapy library
- Administrator/root privileges
- A Roku device on your network
- A Pi-hole server on your network
- On Windows: Npcap installed (https://npcap.com/)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/maddog1110/pi-hole-on-roku-without-router-access.git
   cd pi-hole-on-roku-without-router-access
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. On Windows, install Npcap from https://npcap.com/

## Usage

### Interactive Mode

Simply run the script without any arguments to use the interactive text-based interface:

```
python roku_pihole.py
```

This will guide you through setting up the redirection with a simple menu system.

### Command-Line Mode

You can also run the script with command-line arguments for automation:

```
python roku_pihole.py --roku 192.168.1.100 --pihole 192.168.1.2 --log-level INFO
```

#### Available Arguments

- `--roku`: IP address of your Roku device (required)
- `--router`: IP address of your router (will try to auto-detect if not provided)
- `--pihole`: IP address of your Pi-hole server (default: 192.168.50.66)
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

## How It Works

1. The script uses ARP spoofing to position itself between your Roku device and your router
2. It intercepts DNS queries from your Roku device
3. These queries are forwarded to your Pi-hole server
4. Pi-hole filters out ad and tracking domains
5. Responses are sent back to your Roku device

## Troubleshooting

### Common Issues

- **"MAC address to reach destination not found"**: Make sure your Roku device is powered on and connected to the network.
- **Permission errors**: Make sure you're running the script with administrator/root privileges.
- **No DNS queries being intercepted**: Verify the IP addresses are correct and that your Roku is actively making network requests.

### Logging

Use the `--log-level DEBUG` option to get more detailed information about what's happening:

```
python roku_pihole.py --roku 192.168.1.100 --log-level DEBUG
```

## Legal Disclaimer

This tool is provided for educational purposes only. Using ARP spoofing on networks you don't own or have explicit permission to test on may violate laws or terms of service. Always get proper authorization before running this tool on any network.

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
