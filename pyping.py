# PyPing - Advanced Python Network Testing Utility
# Copyright (c) 2025 PuqiAR

import argparse
import dns.rdatatype, dns.resolver, dns.exception
import socket
import ipaddress
import signal
import struct
import requests
import sys
import json
from tqdm import tqdm
from pathlib import Path

version = '0.1.32'

verbose_build_info_file = 'build_info.json'

def get_verbose_build_info(file_name: str = verbose_build_info_file):
    try:
        if getattr(sys, 'frozen', False):
            base_path = Path(sys._MEIPASS)
        else:
            base_path = Path(__file__).parent
        
        info_path = base_path / file_name
        if not info_path.exists():
            return None

        with info_path.open() as f:
            return json.load(f)
    except:
        return None

build_info = {
    'version' : '',
    'build_date' : '',
    'git_sha' : '',
    'build_number' : '',
    'platform' : ''
}

from platform import system as platform_system
from sys import exit as sys_exit
from dataclasses import dataclass
from typing import Optional, Union, List
from time import sleep, time
from select import select as select_poll

from ping3 import ping as ping3_ping
from tcppinglib import tcpping

class Protocol:
    ICMP = 'icmp'
    TCP = 'tcp'
    UDP = 'udp'

@dataclass
class PingInfo:
    host: str          # ip/domain
    protocol: str      # 'icmp' / 'tcp' / 'udp'
    port: Optional[int] # port (only works when the protocol is 'tcp' or 'udp')
    ttl: int           # ttl
    size: int          # icmp data pack size
    family: int        # 4/6
    timeout: int       # timeout (millisecond)

@dataclass
class PingResult:
    info: PingInfo
    all_sent: int = 0
    success: int = 0
    total_delay: float = 0.0
    max_delay: float = 0.0
    min_delay: float = float('inf')
    error_count: int = 0

def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def resolve_domain(host: str, custom_dns_addr: Optional[str], family: int) -> Union[List[str], int]:
    custom_dns = dns.resolver.Resolver()
    if custom_dns_addr:
        if not is_valid_ip(custom_dns_addr):
            print(f"Invalid DNS server address: {custom_dns_addr}")
            return -1
        custom_dns.nameservers = [custom_dns_addr]
    
    query_type = dns.rdatatype.A if family == 4 else dns.rdatatype.AAAA
    
    try:
        answer = custom_dns.resolve(host, query_type)
        return [str(r) for r in answer]
    except dns.resolver.NoAnswer:
        print(f"Domain '{host}' has no {'IPv4' if family == 4 else 'IPv6'} records")
    except dns.resolver.NXDOMAIN:
        print(f"Domain '{host}' does not exist")
    except dns.exception.Timeout:
        print("DNS server timeout")
    except Exception as e:
        print(f"DNS resolution error: {e}")
    
    return -1

def print_result(result: PingResult) -> None:
    print(f"\n--- {result.info.host} ping statistics ---")
    print(f"  Protocol: {result.info.protocol.upper()}, Port: {result.info.port or 'N/A'}")
    print(f"  IPv{result.info.family}, Size: {result.info.size} bytes, TTL: {result.info.ttl}")
    
    if result.all_sent == 0:
        print("No packets sent")
        return
    
    loss_percent = 100 * (result.all_sent - result.success) / result.all_sent
    print(f"  {result.all_sent} packets transmitted, {result.success} received, "
          f"  {loss_percent:.1f}% packet loss")
    
    if result.success > 0:
        avg_delay = result.total_delay / result.success
        print(f"  Round-trip min/avg/max = {result.min_delay:.1f}/{avg_delay:.1f}/{result.max_delay:.1f} ms")

def ping_icmp_raw(info: PingInfo) -> Optional[float]:
    try:
        proto = socket.IPPROTO_ICMPV6 if info.family == 6 else socket.IPPROTO_ICMP
        sock = socket.socket(
            socket.AF_INET6 if info.family == 6 else socket.AF_INET,
            socket.SOCK_RAW,
            proto
        )
        sock.settimeout(info.timeout/1000)
        
        # packet
        header = struct.pack('!BBHHH', 
                           8 if info.family == 4 else 128,  # Type
                           0,                               # Code
                           0,                               # Checksum
                           0,                               # Identifier
                           1)                               # Sequence number
        
        # payload
        payload = b'PING' + b'X' * (info.size - 4) if info.size > 4 else b'PING'
        packet = header + payload
        
        # checksum
        if info.family == 4:
            checksum = 0
            for i in range(0, len(packet), 2):
                word = (packet[i] << 8) + packet[i+1]
                checksum += word
            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = ~checksum & 0xffff
            packet = packet[:2] + struct.pack('!H', checksum) + packet[4:]
        
        start = time()
        sock.sendto(packet, (info.host, 0))
        
        ready = select_poll([sock], [], [], info.timeout/1000)
        if ready[0]:
            recv_packet, addr = sock.recvfrom(1024)
            end = time()
            return (end - start) * 1000
        return -1  # Timeout code
        
    except socket.timeout:
        return -1
    except Exception as e:
        print(f"Raw ICMP ping error: {e}")
        return None
    finally:
        sock.close()

def ping_icmp(info: PingInfo) -> Optional[float]:
    try:
        delay = ping3_ping(
            info.host,
            timeout=info.timeout/1000,
            ttl=info.ttl,
            size=info.size,
            unit='ms'
        )
        return delay if delay is not None else -1
    except Exception as e:
        print(f"ICMP ping error: {e}")
        return None

def ping_tcp(info: PingInfo) -> Optional[float]:
    if info.port is None:
        print("Port must be specified for TCP ping")
        return None
    
    try:
        result = tcpping(
            info.host,
            port=info.port,
            timeout=info.timeout/1000,
            count=1
        )
        return result.avg_rtt if result.packets_received > 0 else -1
    except Exception as e:
        print(f"TCP ping error: {e}")
        return None

def ping_udp(info: PingInfo) -> Optional[float]:
    if info.port is None:
        print("Port must be specified for UDP ping")
        return None
    
    try:
        # Create UDP socket
        sock = socket.socket(
            socket.AF_INET if info.family == 4 else socket.AF_INET6,
            socket.SOCK_DGRAM
        )
        sock.settimeout(info.timeout / 1000)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, info.ttl)
        
        # Generate simple payload (can be customized)
        payload = b'PING' + b'X' * (info.size - 4) if info.size > 4 else b'PING'
        
        start_time = time()
        sock.sendto(payload, (info.host, info.port))
        
        try:
            # Try to receive response (some services may echo back)
            data, addr = sock.recvfrom(1024)
            end_time = time()
            return (end_time - start_time) * 1000  # Convert to ms
        except socket.timeout:
            return -1  # Timeout
        finally:
            sock.close()
            
    except Exception as e:
        print(f"UDP ping error: {e}")
        return None


def ping_single(info: PingInfo) -> Optional[float]:
    if info.protocol == Protocol.ICMP:
        # Use raw implementation for IPv6
        if info.family == 6:
            return ping_icmp_raw(info)
        return ping_icmp(info)
    elif info.protocol == Protocol.TCP:
        return ping_tcp(info)
    elif info.protocol == Protocol.UDP:
        return ping_udp(info)
    else:
        print(f"Unsupported protocol: {info.protocol}")
        return None

def ping_main(info: PingInfo, count: Union[int, bool], custom_dns_addr: Optional[str], interval: float = 1.0) -> int:
    # Ctrl+C
    interrupted = False
    
    def signal_handler(sig, frame):
        nonlocal interrupted
        interrupted = True
        print("\nPing interrupted by user")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Resolve
    if not is_valid_ip(info.host):
        answer = resolve_domain(info.host, custom_dns_addr, info.family)
        if answer == -1:
            return -1
        
        if len(answer) > 1 and count is True:
            print(f"\nWarning: Multiple IP addresses found for {info.host}:")
            for i, ip in enumerate(answer):
                print(f"  [{i+1}] {ip}")
            print(f"Using first address: {answer[0]}")
        
        info.host = answer[0]

    if info.protocol in (Protocol.TCP, Protocol.UDP) and info.port is None:
        print(f"Port must be specified for {info.protocol.upper()} ping")
        return -1
    
    if info.port is not None and not (0 < info.port <= 65535):
        print(f"Invalid port number: {info.port}")
        return -1
    
    print(f"Pinging {info.host} ({info.host}) using {info.protocol.upper()}", 
          f"port {info.port}" if info.port else "")
    
    result = PingResult(info)
    is_continuous = count is True
    
    try:
        while is_continuous or result.all_sent < count:
            if interrupted:
                break  # Ctrl+C
                
            result.all_sent += 1
            delay = ping_single(info)
            
            if delay is None:  # Error
                result.error_count += 1
                print(f"Error pinging {info.host}")
                continue
                
            if delay == -1:  # Timeout
                print(f"No response from {info.host}: timeout")
            else:
                result.success += 1
                result.total_delay += delay
                result.max_delay = max(result.max_delay, delay)
                result.min_delay = min(result.min_delay, delay)
                print(f"{info.size} bytes from {info.host}: time={delay:.1f} ms")
                
            if result.all_sent != count: # (is_continuous or result.all_sent == count)
                sleep(interval)
                
    except Exception as e:
        print(f"Ping error: {e}")
        return -1
    
    print_result(result)
    return 0 if result.success > 0 else 1

def download_update(release_info:dict, use_mirrored_github:bool = False) -> int:
    '''Download the latest release binary from GitHub releases.
    Parameters:
        release_info (dict): The release information from GitHub API.
        use_mirrored_github (bool): If True, use the mirrored GitHub URL. (Fuck you GFW)
    '''
    os_name = platform_system().lower()
    
    binary_url = None
    is_windows = 'windows' in os_name
    
    for release in release_info['assets']:
        if 'pyping' in str(release['name']):
            if os_name in release['name'].lower():
                binary_url = release['browser_download_url']
                break
    if not binary_url:
        print("No compatible assets found for update.")
        return -1
    if use_mirrored_github:
        binary_url:str = binary_url.replace('github.com', 'hgithub.xyz')
        print(f"Downloading update from (mirrored) {binary_url}...")
    else:
        print(f"Downloading update from {binary_url}...")
    
    try:
        response = requests.get(binary_url, stream=True)
        response.raise_for_status()
    
        total_size = int(response.headers.get('content-length', 0))
        progress = tqdm(
            total=total_size,
            unit='B',
            unit_scale=True,
            desc=f'Downloading {binary_url.split("/")[-1]}'
        )
        with open('pyping_update' + ('.exe' if is_windows else ''), 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    progress.update(len(chunk))
        progress.close()
        return 0  # Success
    except requests.RequestException as e:
        print(f"Error downloading update: {e}")
        if input('Using mirrored Github? (for China users) (y/n): ').strip().lower() == 'y':
            return download_update(release_info, use_mirrored_github=True)
        return -1
    
def check_update() -> int:
    release_url = 'https://api.github.com/repos/PuqiAR/pyping/releases'
    try:
        response = requests.get(release_url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error checking for updates: {e}")
        return -1
    
    try:
        releases = response.json()
        latest_release = releases[0]
        latest_version = latest_release['tag_name'].lstrip('v')
        draft = latest_release['draft']
        isprerelease = latest_release['prerelease']
        
        if latest_version > version and not draft and not isprerelease:
            print(f"New official version available: {latest_version}")
            print(f"Current version: {version}")
            if input("Download? (y/n): ").strip().lower() == 'y':
                if download_update(latest_release) == 0:
                    print('==============')
                    print("Download successful. Please manually reinstall and restart")
                    return 0
                else:
                    print("Download failed.")
                    return -1
            return 0
        else:
            print("You are using the latest version.")
            return 0
    except (ValueError, KeyError) as e:
        print(f"Error parsing release data: {e}, checking for updates failed.")
        return -1
    
def format_build_info(info: dict) -> str:
    if not info:
        return "No build information available."
    
    return f'''
    Build Information:
        Version: {info.get('version', 'N/A')},
        Build Date: {info.get('build_date', 'N/A')},
        Git SHA: {info.get('git_sha', 'N/A')},
        Build Number: {info.get('build_number', 'N/A')},
        Platform: {info.get('platform', 'N/A')}
    '''

def main() -> int:
    global build_info
    _info = get_verbose_build_info()
    if _info:
        build_info.update(_info)
    else:
        print(f'PyPing v{version}:')
        print('**Warning: Failed to load build information\n')
    
    parser = argparse.ArgumentParser(
        prog='PyPing',
        description='A network testing tool supporting ICMP, TCP and UDP',
        epilog='Copyright©PuqiAR, 2025'
    )
    
    parser.add_argument('host', type=str, nargs='?', default=None, help='Hostname or IP address to ping')
    parser.add_argument('-p', '--protocol', default=Protocol.ICMP, 
                       choices=[Protocol.ICMP, Protocol.TCP, Protocol.UDP],
                       help='Protocol to use for ping')
    parser.add_argument('--port', type=int, default=None,
                       help='Port number (required for TCP/UDP)')
    parser.add_argument('--ttl', type=int, default=52,
                       help='Time to live')
    parser.add_argument('--size', type=int, default=32,
                       help='Packet size (bytes)')
    parser.add_argument('-f', '--family', type=int, default=4, choices=[4, 6],
                       help='IP family (4 or 6)')
    parser.add_argument('--dns', type=str, default=None,
                       help='Custom DNS server address')
    parser.add_argument('--timeout', type=int, default=3000,
                       help='Timeout in milliseconds')
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-t', action='store_true', default=False,
                      help='Ping continuously until interrupted')
    group.add_argument('-n', '--count', type=int, default=4,
                      help='Number of ping requests to send')
    
    parser.add_argument('-i', '--interval', type=float, default=0.5,
                       help='Interval between pings in seconds (default: 0.5)')
    
    def format_version_info():
        return f"v{version}\n{format_build_info(build_info)}"
    
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {format_version_info()}', help='Show version and exit')
    
    parser.add_argument('-u', '--update', action='store_true', default=False,
                       help='Check for updates')
    
    args = parser.parse_args()
    
    info = PingInfo(
        host=args.host,
        protocol=args.protocol,
        port=args.port,
        ttl=args.ttl,
        size=args.size,
        family=args.family,
        timeout=args.timeout
    )
    if args.update:
        return check_update()
    if not args.host:
        parser.error("the following arguments are required: host")
        return -1
    return ping_main(info, args.t if args.t else args.count, args.dns, args.interval)

if __name__ == '__main__':
    sys_exit(main())