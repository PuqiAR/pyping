# PyPing - Advanced Python Network Testing Utility

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

[![中文文档](https://img.shields.io/badge/文档-中文版-blue)](README_zh.md) [README_zh.md](README_zh.md)

## Features
- Multi-protocol support (ICMP/TCP/UDP)
- IPv4 & IPv6 dual-stack
- Detailed connection statistics
- Customizable testing parameters

## Installation

from source
git clone https://github.com/PuqiAR/pyping
cd pyping

## Usage

### Basic Commands
| Command                     | Description        | Example                       |
| --------------------------- | ------------------ | ----------------------------- |
| pyping <host>               | Basic ICMP ping    | pyping example.com            |
| pyping <host> -p <proto>    | Protocol selection | pyping example.com -p tcp     |
| pyping <host> --port <port> | Port specification | pyping example.com --port 443 |

### Advanced Options
| Option         | Description                  | Default |
| -------------- | ---------------------------- | ------- |
| -p, --protocol | Protocol type (icmp/tcp/udp) | icmp    |
| --port         | Target port number           | None    |
| -f, --family   | IP version (4/6)             | 4       |
| -n, --count    | Number of packets            | 4       |
| -t             | Continuous ping mode         | False   |
| -i, --interval | Ping interval (seconds)      | 1.0     |

## Examples

- Basic ICMP ping
  ```bash
    pyping 192.168.1.1
  ```

- TCP port test with IPv6
  ```bash
    pyping example.com -p tcp --port 80 -f 6
  ```

- Continuous UDP test
  ```bash
    pyping example.com -p udp --port 53 -t -i 0.5
  ```

## Requirements
See requirements.txt for dependencies

## License
MIT License © 2023 PuqiAR
