import pywifi
from pywifi import const
import time
from dataclasses import dataclass

@dataclass
class AccessPointNode:
    bssid: str
    signal_rssi: int
    cipher_type: str

@dataclass
class DiscoveredNetwork:
    ssid: str
    auth_protocol: str
    access_points: list[AccessPointNode]

def parse_auth_type(auth_id_list) -> str:
    """Map native hardware status codes to clean text protocols."""
    # pywifi usually passes a list of auth IDs
    auth_id = auth_id_list[0] if isinstance(auth_id_list, list) and auth_id_list else auth_id_list
    mapping = {
        const.AUTH_ALG_OPEN: "Open / Unsecured",
        const.AUTH_ALG_SHARED: "Shared Key",
        const.AKM_TYPE_WPA: "WPA-Enterprise",
        const.AKM_TYPE_WPAPSK: "WPA-Personal",
        const.AKM_TYPE_WPA2: "WPA2-Enterprise",
        const.AKM_TYPE_WPA2PSK: "WPA2-Personal",
        7: "WPA3-Personal" 
    }
    return mapping.get(auth_id, f"Unknown Protocol ({auth_id})")

def parse_cipher_type(cipher_id) -> str:
    """Map structural data codes to clear text encryptions."""
    mapping = {
        const.CIPHER_TYPE_NONE: "None",
        const.CIPHER_TYPE_WEP: "WEP",
        const.CIPHER_TYPE_TKIP: "TKIP",
        const.CIPHER_TYPE_CCMP: "CCMP (AES)"
    }
    return mapping.get(cipher_id, f"Unknown/Other Cipher ({cipher_id})")

def force_airwave_scan() -> list[DiscoveredNetwork]:
    """Intersects native kernel wireless routines to pull down everything in the air."""
    wifi = pywifi.PyWiFi()
    
    if not wifi.interfaces():
        print("[-] Error: No physical Wi-Fi adapter cards detected on this computer.")
        return []
        
    interface = wifi.interfaces()[0] # Pull the primary network interface card
    
    print(f"[*] Hardware Card Detected: {interface.name()}")
    print("[*] Broadcasting active airwave probes... forcing radio infrastructure update.")
    
    interface.scan()
    time.sleep(3.5)  # Safe buffer window to let neighboring radio responses return
    
    raw_results = interface.scan_results()
    network_registry = {}
    
    for ap in raw_results:
        ssid = ap.ssid
        if isinstance(ssid, bytes):
            ssid = ssid.decode('utf-8', errors='replace')
        ssid = ssid.strip() or "<Hidden Network / Blind Beacon>"
        
        mac = str(ap.bssid).upper().replace("-", ":")
        if len(mac) > 17: 
            mac = mac[:17]
            
        auth_string = "Open"
        if ap.akm:
            auth_string = parse_auth_type(ap.akm)
            
        cipher_string = parse_cipher_type(ap.cipher)
        
        net_key = (ssid, auth_string)
        if net_key not in network_registry:
            network_registry[net_key] = DiscoveredNetwork(
                ssid=ssid,
                auth_protocol=auth_string,
                access_points=[]
            )
            
        existing_bssids = {node.bssid for node in network_registry[net_key].access_points}
        if mac not in existing_bssids:
            network_registry[net_key].access_points.append(
                AccessPointNode(bssid=mac, signal_rssi=ap.signal, cipher_type=cipher_string)
            )
            
    return list(network_registry.values())

def main():
    print("Executing native airwave scan for structural wireless topologies...\n")
    all_networks = force_airwave_scan()
    
    if not all_networks:
        print("[-] No network hardware infrastructure detected in scannable range.")
        return
        
    print(f"\n[+] Discovered {len(all_networks)} discrete wireless infrastructures near you:\n")
    for idx, net in enumerate(all_networks, 1):
        print(f"[{idx}] Logical Identifier (SSID): {net.ssid}")
        print(f"    ├─ Security Protocol:  {net.auth_protocol}")
        print(f"    └─ Active Base Transceiver Stations (Access Points): {len(net.access_points)}")
        
        sorted_nodes = sorted(net.access_points, key=lambda x: x.signal_rssi, reverse=True)
        
        for ap_idx, node in enumerate(sorted_nodes, 1):
            is_last = ap_idx == len(sorted_nodes)
            branch = "        └─" if is_last else "        ├─"
            sub_branch = "           " if is_last else "        │  "
            
            # Map RSSI values securely to generic percentage levels
            quality_percentage = min(max(2 * (node.signal_rssi + 100), 0), 100)
            
            print(f"{branch} Physical Hardware Node #{ap_idx} [MAC: {node.bssid}]")
            print(f"{sub_branch}├─ Signal Quality: {quality_percentage}% (RSSI: {node.signal_rssi} dBm)")
            print(f"{sub_branch}└─ Encryption Cipher: {node.cipher_type}")
        print("=" * 65)

if __name__ == "__main__":
    main()
