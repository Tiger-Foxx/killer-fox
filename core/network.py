"""
core/network.py
Module de découverte réseau avancé et abstraction Cross-Platform.
Gère la détection des interfaces, du routage et du mode moniteur.
"""
import socket
import ipaddress
import platform
import netifaces
import subprocess
import shutil
from typing import List, Dict, Optional
from scapy.all import conf as scapy_conf
from core.logger import log

class AutoDiscovery:
    IS_WINDOWS = platform.system() == "Windows"

    @staticmethod
    def get_interfaces() -> List[Dict[str, str]]:
        """Retourne la liste des interfaces valides (exclut loopback/docker)."""
        candidates = []
        try:
            for iface in netifaces.interfaces():
                # Filtrage basique des interfaces virtuelles inutiles
                if iface.startswith(('lo', 'docker', 'veth', 'br-')):
                    continue
                
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ipv4_info = addrs[netifaces.AF_INET][0]
                    ip = ipv4_info.get('addr')
                    
                    # On ignore les IPs locales ou invalides
                    if not ip or ip.startswith('127.'):
                        continue

                    candidates.append({
                        "name": iface,
                        "ip": ip,
                        "mac": AutoDiscovery._get_mac_address(iface)
                    })
        except Exception as e:
            log.error(f"Erreur lors du listage des interfaces : {e}")
        
        return candidates

    @staticmethod
    def get_network_details(iface_name: str) -> Dict[str, str]:
        """Récupère Gateway, CIDR et IP pour une interface donnée."""
        details = {"ip": "", "gateway": "", "cidr": "", "netmask": ""}
        
        try:
            # 1. IP & Masque
            addrs = netifaces.ifaddresses(iface_name)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                details["ip"] = ip_info.get('addr')
                details["netmask"] = ip_info.get('netmask')
                
                # Calcul du CIDR
                if details["ip"] and details["netmask"]:
                    network = ipaddress.IPv4Network(f"{details['ip']}/{details['netmask']}", strict=False)
                    details["cidr"] = str(network)

            # 2. Gateway
            gws = netifaces.gateways()
            default_gw = gws.get('default', {}).get(netifaces.AF_INET)
            if default_gw:
                gw_ip, gw_iface = default_gw
                # Vérifie que la GW correspond bien à l'interface choisie
                if gw_iface == iface_name or AutoDiscovery.IS_WINDOWS: 
                    # Sur Windows, le nom d'interface dans gateways() est un GUID, pas le nom user-friendly
                    details["gateway"] = gw_ip
            
            # Fallback Scapy si netifaces échoue pour la gateway
            if not details["gateway"]:
                try:
                    details["gateway"] = scapy_conf.route.route("8.8.8.8")[2]
                except:
                    pass

        except Exception as e:
            log.error(f"Erreur lors de l'analyse de {iface_name} : {e}")

        return details

    @staticmethod
    def _get_mac_address(iface_name: str) -> str:
        """Récupère l'adresse MAC de manière fiable."""
        try:
            mac = netifaces.ifaddresses(iface_name)[netifaces.AF_LINK][0]['addr']
            return mac
        except (KeyError, IndexError):
            return "00:00:00:00:00:00"

    @staticmethod
    def check_monitor_mode(iface_name: str) -> bool:
        """Vérifie si l'interface est en mode Monitor (Linux Only)."""
        if AutoDiscovery.IS_WINDOWS:
            return False # Pas de mode monitor natif simple sous Windows
            
        if not shutil.which("iwconfig"):
            return False

        try:
            result = subprocess.check_output(["iwconfig", iface_name], stderr=subprocess.STDOUT).decode()
            return "Mode:Monitor" in result
        except subprocess.CalledProcessError:
            return False