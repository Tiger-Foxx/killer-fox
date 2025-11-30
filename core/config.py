"""
core/config.py
Configuration globale centralisée pour FoxProwl.
Singleton thread-safe avec tous les paramètres d'attaque.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from threading import Lock
import ipaddress


@dataclass
class NetworkConfig:
    """Configuration réseau de l'attaquant."""
    # Interface et identité
    interface: str = ""
    interface_display: str = ""  # Nom lisible de l'interface
    attacker_ip: str = ""
    attacker_mac: str = ""
    
    # Gateway
    gateway_ip: str = ""
    gateway_mac: str = ""
    
    # Réseau
    subnet: str = ""  # CIDR (ex: 192.168.1.0/24)
    netmask: str = ""
    
    # Cibles actives
    targets: List[str] = field(default_factory=list)
    
    # Cache des hôtes découverts {ip: {"mac": "...", "vendor": "...", "hostname": "..."}}
    discovered_hosts: Dict[str, Dict] = field(default_factory=dict)
    
    # États système
    ip_forwarding_enabled: bool = False
    monitor_mode_enabled: bool = False
    arp_spoofing_active: bool = False
    
    # Paramètres d'attaque globaux
    aggressive_mode: bool = True  # Mode agressif = plus de paquets, plus rapide
    stealth_mode: bool = False    # Mode furtif = moins détectable
    
    # Verrou pour accès thread-safe
    _lock: Lock = field(default_factory=Lock, repr=False)
    
    def add_target(self, ip: str) -> bool:
        """Ajoute une cible de manière thread-safe."""
        with self._lock:
            if ip not in self.targets and ip != self.gateway_ip and ip != self.attacker_ip:
                self.targets.append(ip)
                return True
            return False
    
    def remove_target(self, ip: str) -> bool:
        """Retire une cible de manière thread-safe."""
        with self._lock:
            if ip in self.targets:
                self.targets.remove(ip)
                return True
            return False
    
    def add_discovered_host(self, ip: str, mac: str, vendor: str = "", hostname: str = ""):
        """Ajoute un hôte découvert au cache."""
        with self._lock:
            self.discovered_hosts[ip] = {
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "ports": []
            }
    
    def get_targets_in_subnet(self, exclude_gateway: bool = True, exclude_self: bool = True) -> List[str]:
        """Retourne toutes les IPs du subnet (pour attaque broadcast)."""
        if not self.subnet:
            return []
        
        try:
            network = ipaddress.IPv4Network(self.subnet, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            
            if exclude_gateway and self.gateway_ip:
                ips = [ip for ip in ips if ip != self.gateway_ip]
            if exclude_self and self.attacker_ip:
                ips = [ip for ip in ips if ip != self.attacker_ip]
            
            return ips
        except Exception:
            return []
    
    def is_valid_target(self, ip: str) -> bool:
        """Vérifie si une IP est une cible valide (pas nous, pas la gateway)."""
        return ip != self.gateway_ip and ip != self.attacker_ip


# Instance globale unique
conf = NetworkConfig()


def reset_config():
    """Réinitialise la configuration complète."""
    global conf
    conf = NetworkConfig()


class AttackConfig:
    """Configuration spécifique aux attaques."""
    
    # TCP Killer / Internet Blocker
    RST_PACKET_COUNT: int = 4          # Nombre de RST à envoyer par connexion
    RST_INTERVAL: float = 0.01         # Délai entre les RST (10ms)
    TCP_BLACKLIST_PORTS: List[int] = [22]  # Ports à ne jamais toucher (SSH de secours)
    
    # ARP Spoofing
    ARP_INTERVAL: float = 1.5          # Intervalle entre les paquets ARP (secondes)
    ARP_RESTORE_COUNT: int = 7         # Nombre de paquets de restauration
    ARP_QUIET_MODE: bool = False       # Mode quiet = réponse aux ARP requests uniquement
    
    # DNS Spoofing
    DNS_TTL: int = 1                   # TTL très court pour éviter le cache victime
    DNS_RESPONSE_DELAY: float = 0.0    # Pas de délai = on bat le vrai serveur DNS
    
    # Scanning
    SCAN_TIMEOUT: float = 2.0          # Timeout ARP scan
    PORT_SCAN_TIMEOUT: float = 0.5     # Timeout port scan
    COMMON_PORTS: List[int] = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080, 8443]
    
    # Session Hijacking
    HIJACK_INJECT_COUNT: int = 3       # Nombre de fois qu'on envoie le payload injecté
    
    # SSL Stripping
    SSLSTRIP_LISTEN_PORT: int = 8080   # Port d'écoute local pour le proxy


# Instance globale pour les paramètres d'attaque
attack_conf = AttackConfig()