import asyncio
import base64
import json
import time
from urllib.parse import urlparse, parse_qs, unquote
import aiohttp
from typing import List, Dict, Optional

class V2RayScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.results = []

    async def fetch_subscription(self, url: str) -> List[str]:
        """Fetch and decode v2ray subscription"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    decoded = base64.b64decode(content).decode('utf-8')
                    configs = [line.strip() for line in decoded.split('\n') if line.strip()]
                    return configs
        except Exception as e:
            print(f"Failed to fetch subscription {url}: {e}")
            return []

    def parse_vmess(self, config: str) -> Optional[Dict]:
        """Parse vmess:// config"""
        try:
            if not config.startswith('vmess://'):
                return None
            encoded = config[8:]
            decoded = base64.b64decode(encoded).decode('utf-8')
            data = json.loads(decoded)
            return {
                'type': 'vmess',
                'address': data.get('add'),
                'port': int(data.get('port', 0)),
                'name': data.get('ps', 'Unknown'),
                'raw': config
            }
        except Exception as e:
            print(f"Failed to parse vmess: {e}")
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        """Parse vless:// config"""
        try:
            if not config.startswith('vless://'):
                return None
            url = urlparse(config)
            uuid = url.username
            address = url.hostname
            port = url.port
            params = parse_qs(url.query)
            name = unquote(url.fragment) if url.fragment else 'Unknown'
            
            return {
                'type': 'vless',
                'address': address,
                'port': port,
                'name': name,
                'raw': config
            }
        except Exception as e:
            print(f"Failed to parse vless: {e}")
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        """Parse trojan:// config"""
        try:
            if not config.startswith('trojan://'):
                return None
            url = urlparse(config)
            password = url.username
            address = url.hostname
            port = url.port
            name = unquote(url.fragment) if url.fragment else 'Unknown'
            
            return {
                'type': 'trojan',
                'address': address,
                'port': port,
                'name': name,
                'raw': config
            }
        except Exception as e:
            print(f"Failed to parse trojan: {e}")
            return None

    def parse_ss(self, config: str) -> Optional[Dict]:
        """Parse ss:// (Shadowsocks) config"""
        try:
            if not config.startswith('ss://'):
                return None
            url = urlparse(config)
            name = unquote(url.fragment) if url.fragment else 'Unknown'
            
            if '@' in config:
                parts = config[5:].split('@')
                decoded = base64.b64decode(parts[0]).decode('utf-8')
                server_part = parts[1].split('#')[0]
                address, port = server_part.split(':')
            else:
                decoded = base64.b64decode(url.netloc).decode('utf-8')
                parts = decoded.rsplit('@', 1)
                address, port = parts[1].split(':')
            
            return {
                'type': 'ss',
                'address': address,
                'port': int(port),
                'name': name,
                'raw': config
            }
        except Exception as e:
            print(f"Failed to parse ss: {e}")
            return None

    async def test_delay(self, address: str, port: int) -> Optional[float]:
        """Test connection delay via TCP connect"""
        try:
            start = time.time()
            conn = asyncio.open_connection(address, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            delay = (time.time() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return delay
        except Exception:
            return None

    async def scan_config(self, config_str: str) -> Optional[Dict]:
        """Parse and test a single config"""
        parsed = None
        
        if config_str.startswith('vmess://'):
            parsed = self.parse_vmess(config_str)
        elif config_str.startswith('vless://'):
            parsed = self.parse_vless(config_str)
        elif config_str.startswith('trojan://'):
            parsed = self.parse_trojan(config_str)
        elif config_str.startswith('ss://'):
            parsed = self.parse_ss(config_str)
        
        if not parsed or not parsed['address']:
            return None
        
        print(f"Testing {parsed['name']} ({parsed['address']}:{parsed['port']})...")
        delay = await self.test_delay(parsed['address'], parsed['port'])
        
        if delay is not None:
            parsed['delay'] = delay
            print(f"  ✓ {delay:.0f}ms")
            return parsed
        else:
            print(f"  ✗ Timeout")
            return None

    async def scan_all(self, configs: List[str]):
        """Scan all configs concurrently"""
        tasks = [self.scan_config(config) for config in configs]
        results = await asyncio.gather(*tasks)
        self.results = [r for r in results if r is not None]
        self.results.sort(key=lambda x: x['delay'])

    def save_results(self, filename: str = 'v2ray_sorted.txt'):
        """Save results to file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"V2Ray Configs Sorted by Delay\n")
            f.write(f"Scanned: {len(self.results)} working configs\n")
            f.write(f"=" * 80 + "\n\n")
            
            for i, config in enumerate(self.results, 1):
                f.write(f"{i}. {config['name']}\n")
                f.write(f"   Type: {config['type']}\n")
                f.write(f"   Server: {config['address']}:{config['port']}\n")
                f.write(f"   Delay: {config['delay']:.0f}ms\n")
                f.write(f"   Config: {config['raw']}\n\n")
        
        print(f"\nResults saved to {filename}")

def show_menu():
    """Display main menu"""
    print("\n" + "="*60)
    print("V2Ray Config Scanner")
    print("="*60)
    print("1. Scan from subscription URL(s)")
    print("2. Scan from file")
    print("3. Paste configs directly")
    print("4. Exit")
    print("="*60)

def get_choice():
    """Get user's menu choice"""
    while True:
        choice = input("\nSelect option (1-4): ").strip()
        if choice in ['1', '2', '3', '4']:
            return choice
        print("Invalid choice. Please enter 1, 2, 3, or 4.")

async def handle_subscription():
    """Handle subscription URL input"""
    configs = []
    scanner = V2RayScanner()
    
    print("\nPaste subscription URLs (one per line).")
    print("Press Enter twice when done:\n")
    
    urls = []
    while True:
        url = input().strip()
        if not url:
            break
        urls.append(url)
    
    if not urls:
        print("No URLs provided.")
        return []
    
    for url in urls:
        print(f"\nFetching: {url}")
        fetched = await scanner.fetch_subscription(url)
        configs.extend(fetched)
        print(f"Got {len(fetched)} configs")
    
    return configs

def handle_file():
    """Handle file input"""
    filename = input("\nEnter filename: ").strip()
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(configs)} configs from {filename}")
            return configs
    except Exception as e:
        print(f"Failed to read file: {e}")
        return []

def handle_paste():
    """Handle direct config paste"""
    print("\nPaste your configs (one per line).")
    print("Press Enter twice when done:\n")
    
    configs = []
    while True:
        config = input().strip()
        if not config:
            break
        configs.append(config)
    
    if configs:
        print(f"\nGot {len(configs)} configs")
    else:
        print("No configs provided.")
    
    return configs

async def main():
    """Main interactive loop"""
    while True:
        show_menu()
        choice = get_choice()
        
        if choice == '4':
            print("\nExiting...")
            break
        
        configs = []
        
        if choice == '1':
            configs = await handle_subscription()
        elif choice == '2':
            configs = handle_file()
        elif choice == '3':
            configs = handle_paste()
        
        if not configs:
            continue
        
        # Ask for timeout
        timeout_input = input("\nConnection timeout in seconds (default 5): ").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else 5
        
        # Ask for output filename
        output_input = input("Output filename (default v2ray_sorted.txt): ").strip()
        output = output_input if output_input else 'v2ray_sorted.txt'
        
        print(f"\n{'='*60}")
        print(f"Starting scan of {len(configs)} configs...")
        print(f"{'='*60}\n")
        
        scanner = V2RayScanner(timeout=timeout)
        await scanner.scan_all(configs)
        
        print(f"\n{'='*60}")
        print(f"Scan complete: {len(scanner.results)}/{len(configs)} configs working")
        scanner.save_results(output)
        
        # Ask if user wants to continue
        cont = input("\nScan more configs? (y/n): ").strip().lower()
        if cont != 'y':
            print("\nExiting...")
            break

if __name__ == '__main__':
    asyncio.run(main())
