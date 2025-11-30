"""
core/network.py
Module de découverte et configuration réseau automatique.
Cross-platform (Windows/Linux) avec détection intelligente.
"""
import os
import socket
import platform
import subprocess
import ipaddress
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

import netifaces
from scapy.all import conf as scapy_conf, get_if_hwaddr, get_if_list, srp, Ether, ARP

from core.logger import log
from core.config import conf


@dataclass
class InterfaceInfo:
    """Informations sur une interface réseau."""
    name: str
    ip: str
    mac: str
    netmask: str
    cidr: str
    gateway: str
    is_up: bool
    is_wireless: bool
    supports_monitor: bool


class NetworkDiscovery:
    """Découverte et configuration réseau automatique."""
    
    IS_WINDOWS = platform.system() == "Windows"
    IS_LINUX = platform.system() == "Linux"
    
    @classmethod
    def get_all_interfaces(cls) -> List[InterfaceInfo]:
        """
        Récupère toutes les interfaces réseau valides.
        Exclut loopback, docker, etc.
        """
        interfaces = []
        excluded_prefixes = ('lo', 'docker', 'veth', 'br-', 'virbr', 'vbox', 'vmnet')
        
        try:
            for iface_name in netifaces.interfaces():
                # Filtrer les interfaces virtuelles
                if any(iface_name.lower().startswith(prefix) for prefix in excluded_prefixes):
                    continue
                
                # Récupérer les adresses
                addrs = netifaces.ifaddresses(iface_name)
                
                # Vérifier qu'on a une IPv4
                if netifaces.AF_INET not in addrs:
                    continue
                
                ipv4_info = addrs[netifaces.AF_INET][0]
                ip = ipv4_info.get('addr', '')
                
                # Ignorer les IPs locales
                if not ip or ip.startswith('127.') or ip == '0.0.0.0':
                    continue
                
                # Récupérer MAC
                mac = cls._get_mac_address(iface_name, addrs)
                if not mac or mac == '00:00:00:00:00:00':
                    continue
                
                # Récupérer netmask et calculer CIDR
                netmask = ipv4_info.get('netmask', '255.255.255.0')
                cidr = cls._calculate_cidr(ip, netmask)
                
                # Récupérer gateway
                gateway = cls._get_gateway(iface_name)
                
                # Détecter si wireless
                is_wireless = cls._is_wireless(iface_name)
                
                interfaces.append(InterfaceInfo(
                    name=iface_name,
                    ip=ip,
                    mac=mac,
                    netmask=netmask,
                    cidr=cidr,
                    gateway=gateway,
                    is_up=True,
                    is_wireless=is_wireless,
                    supports_monitor=is_wireless and cls.IS_LINUX
                ))
        
        except Exception as e:
            log.error(f"Erreur lors de l'énumération des interfaces: {e}")
        
        return interfaces
    
    @classmethod
    def _get_mac_address(cls, iface_name: str, addrs: dict = None) -> str:
        """Récupère l'adresse MAC de manière fiable."""
        try:
            if addrs is None:
                addrs = netifaces.ifaddresses(iface_name)
            
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0].get('addr', '')
                return mac.lower()
        except Exception:
            pass
        
        # Fallback Scapy
        try:
            return get_if_hwaddr(iface_name)
        except Exception:
            return ""
    
    @classmethod
    def _calculate_cidr(cls, ip: str, netmask: str) -> str:
        """Calcule le CIDR à partir de l'IP et du masque."""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception:
            return ""
    
    @classmethod
    def _get_gateway(cls, iface_name: str) -> str:
        """Récupère l'adresse de la gateway."""
        try:
            gateways = netifaces.gateways()
            default_gw = gateways.get('default', {}).get(netifaces.AF_INET)
            
            if default_gw:
                gw_ip, gw_iface = default_gw[0], default_gw[1]
                # Sur Windows, le nom d'interface peut être différent
                if cls.IS_WINDOWS or gw_iface == iface_name:
                    return gw_ip
        except Exception:
            pass
        
        # Fallback Scapy
        try:
            route = scapy_conf.route.route("8.8.8.8")
            return route[2] if route else ""
        except Exception:
            return ""
    
    @classmethod
    def _is_wireless(cls, iface_name: str) -> bool:
        """Détecte si l'interface est wireless."""
        iface_lower = iface_name.lower()
        
        # Heuristique basique
        if any(w in iface_lower for w in ['wlan', 'wifi', 'wl', 'wireless', 'wi-fi']):
            return True
        
        if cls.IS_LINUX:
            # Vérifier dans /sys
            wireless_path = f"/sys/class/net/{iface_name}/wireless"
            if os.path.exists(wireless_path):
                return True
        
        return False
    
    @classmethod
    def get_best_interface(cls) -> Optional[InterfaceInfo]:
        """
        Sélectionne automatiquement la meilleure interface.
        Préfère: 1) Interface avec gateway, 2) IP privée, 3) Interface filaire
        """
        interfaces = cls.get_all_interfaces()
        
        if not interfaces:
            return None
        
        # Trier par priorité
        def score(iface: InterfaceInfo) -> int:
            s = 0
            if iface.gateway:
                s += 100
            if iface.ip.startswith(('192.168.', '10.', '172.')):
                s += 50
            if not iface.is_wireless:
                s += 10
            return s
        
        interfaces.sort(key=score, reverse=True)
        return interfaces[0]
    
    @classmethod
    def resolve_mac(cls, ip: str, iface: str = None, timeout: float = 2.0) -> Optional[str]:
        """
        Résout l'adresse MAC d'une IP via ARP.
        Utilise le cache si disponible.
        """
        if not iface:
            iface = conf.interface
        
        # Vérifier le cache de conf
        if ip in conf.discovered_hosts:
            cached_mac = conf.discovered_hosts[ip].get('mac')
            if cached_mac:
                return cached_mac
        
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=timeout,
                iface=iface,
                verbose=False
            )
            if ans:
                mac = ans[0][1].hwsrc
                # Mettre en cache
                conf.add_discovered_host(ip, mac)
                return mac
        except Exception as e:
            log.warning(f"Échec résolution MAC pour {ip}: {e}")
        
        return None
    
    @classmethod
    def resolve_macs_batch(cls, ips: List[str], iface: str = None, timeout: float = 3.0) -> Dict[str, str]:
        """Résout les MACs de plusieurs IPs en une seule requête ARP."""
        if not iface:
            iface = conf.interface
        
        result = {}
        
        try:
            # Construire les paquets ARP pour toutes les IPs
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
                timeout=timeout,
                iface=iface,
                verbose=False
            )
            
            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                result[ip] = mac
                conf.add_discovered_host(ip, mac)
        
        except Exception as e:
            log.warning(f"Erreur résolution MAC batch: {e}")
        
        return result
    
    @classmethod
    def configure_from_interface(cls, iface: InterfaceInfo):
        """Configure la conf globale à partir d'une interface."""
        conf.interface = iface.name
        conf.attacker_ip = iface.ip
        conf.attacker_mac = iface.mac
        conf.gateway_ip = iface.gateway
        conf.subnet = iface.cidr
        conf.netmask = iface.netmask
        
        # Résoudre la MAC de la gateway
        if iface.gateway:
            gw_mac = cls.resolve_mac(iface.gateway, iface.name)
            if gw_mac:
                conf.gateway_mac = gw_mac
    
    @classmethod
    def auto_configure(cls) -> bool:
        """
        Configuration automatique complète.
        Retourne True si succès.
        """
        log.info("Auto-configuration du réseau...")
        
        iface = cls.get_best_interface()
        if not iface:
            log.error("Aucune interface réseau valide trouvée!")
            return False
        
        cls.configure_from_interface(iface)
        
        # Afficher la config
        log.success(f"Interface: {conf.interface}")
        log.info(f"IP Attaquant: {conf.attacker_ip}")
        log.info(f"MAC Attaquant: {conf.attacker_mac}")
        log.info(f"Gateway: {conf.gateway_ip} ({conf.gateway_mac or 'MAC en cours...'})")
        log.info(f"Subnet: {conf.subnet}")
        
        return True


class MonitorMode:
    """Gestion du mode monitor WiFi (Linux uniquement)."""
    
    @staticmethod
    def is_available() -> bool:
        """Vérifie si le mode monitor est disponible."""
        return platform.system() == "Linux"
    
    @staticmethod
    def enable(iface: str) -> Tuple[bool, str]:
        """
        Active le mode monitor sur une interface.
        Retourne (success, new_interface_name ou error_message)
        """
        if not MonitorMode.is_available():
            return False, "Mode monitor disponible uniquement sur Linux"
        
        try:
            # Méthode airmon-ng
            result = subprocess.run(
                ["airmon-ng", "start", iface],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Le nouveau nom est souvent iface + "mon" ou wlan0mon
                new_name = f"{iface}mon"
                if new_name in netifaces.interfaces():
                    return True, new_name
                
                # Sinon on garde le même nom
                return True, iface
            
            return False, result.stderr
        
        except FileNotFoundError:
            # Essayer avec iw
            try:
                subprocess.run(["ip", "link", "set", iface, "down"], check=True)
                subprocess.run(["iw", iface, "set", "monitor", "control"], check=True)
                subprocess.run(["ip", "link", "set", iface, "up"], check=True)
                return True, iface
            except Exception as e:
                return False, str(e)
        
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def disable(iface: str) -> bool:
        """Désactive le mode monitor."""
        if not MonitorMode.is_available():
            return False
        
        try:
            subprocess.run(["airmon-ng", "stop", iface], capture_output=True, timeout=10)
            return True
        except Exception:
            try:
                subprocess.run(["ip", "link", "set", iface, "down"], check=True)
                subprocess.run(["iw", iface, "set", "type", "managed"], check=True)
                subprocess.run(["ip", "link", "set", iface, "up"], check=True)
                return True
            except Exception:
                return False


# Alias pour compatibilité
AutoDiscovery = NetworkDiscovery