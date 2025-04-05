# Pi-hole on Roku Without Router Access

⚠️ **This project is for educational and personal use only. Use it only on networks and devices you own or have explicit permission to test on. The author is not responsible for any misuse.**

A Python-based solution for redirecting Roku device traffic through Pi-hole without requiring router configuration access.

## Overview

This project intercepts DNS queries from your Roku device and redirects them through Pi-hole for ad filtering, without requiring administrative access to your network router. It uses ARP spoofing techniques to position itself as a "man-in-the-middle" between your Roku and router.

## Ethical Use Notice

This tool is intended **only** to improve ad-blocking and privacy on your own devices. It is designed to filter unwanted content, not for spying or tampering with data. The ARP spoofing technique used is a powerful networking capability that should be used responsibly and ethically.

## Features

- Filters ads on Roku using Pi-hole without router configuration
- Uses ARP spoofing to intercept Roku DNS traffic
- Forwards DNS queries to Pi-hole and returns filtered responses
- Automatically detects router IP if not specified
- Cross-platform support (Windows, macOS, Linux)

## Prerequisites

- Python 3.6+
- Scapy library
- Pi-hole instance running on your network
- Roku device on the same network
- On Windows: Npcap installed and admin privileges

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/pi-hole-on-roku-without-router-access.git
   cd pi-hole-on-roku-without-router-access
   ```

2. Install required Python packages:
   ```
   pip install scapy
   ```

3. If you're on Windows, install [Npcap](https://npcap.com/)

## Usage

1. Find your Roku's IP address (available in Roku settings under Network)

2. Run the script with your Roku's IP address:
   ```
   python roku_pihole.py --roku 192.168.1.x
   ```

3. Optional parameters:
   - `--router` - Specify router IP (will attempt to auto-detect if not provided)
   - `--pihole` - Specify Pi-hole IP (defaults to 192.168.50.66)

   Example with all parameters:
   ```
   python roku_pihole.py --roku 192.168.1.100 --router 192.168.1.1 --pihole 192.168.1.50
   ```

4. The script will:
   - Get the MAC addresses of your Roku and router
   - Start intercepting DNS queries from your Roku
   - Forward these queries to Pi-hole
   - Return the filtered responses to your Roku

5. To stop the proxy, press `Ctrl+C` in the terminal (the script will restore normal ARP settings)

## How It Works

This solution uses several networking techniques:

1. **ARP Spoofing**: The script sends ARP packets making the Roku think your computer is the router, and making the router think your computer is the Roku.

2. **DNS Interception**: When the Roku sends DNS queries (thinking they're going to the router), your computer intercepts them.

3. **Pi-hole Forwarding**: The script forwards these DNS queries to your Pi-hole server.

4. **Response Handling**: Pi-hole's responses (with ad domains blocked) are sent back to the Roku.

5. **Cleanup**: When you stop the script, it restores the original ARP settings.

## Troubleshooting

- **Permission Errors**: You need to run as administrator/sudo on most systems
- **"Could not find Roku device"**: Double-check your Roku's IP address
- **Windows Issues**: Make sure Npcap is installed correctly
- **"Failed to spoof"**: Check your firewall settings or try disabling your firewall temporarily
- **No DNS Interception**: Verify all devices are on the same network segment

## Limitations

- Must be running continuously while using your Roku
- May be detected as a security threat by some network monitoring tools
- Requires Python and dependencies to be installed
- Does not affect non-DNS traffic (some ads may still appear)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License:

```
MIT License

Copyright (c) 2025 maddog

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The use of this software for any malicious purpose or in violation of any laws is expressly prohibited, and the author accepts no responsibility for such actions.

## Disclaimer

This software uses ARP spoofing techniques which may violate your ISP's terms of service or local network policies. It should only be used on networks you own or have permission to modify. The authors assume no liability for any misuse or damage caused by this software.
