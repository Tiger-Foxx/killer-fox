"""
core/config.py
Gestion de la configuration globale et de l'état du réseau.
Agit comme un singleton pour partager les données entre les modules.
"""
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class NetworkConfig:
    # Identité de l'attaquant
    interface: str = "eth0"
    attacker_ip: str = ""
    attacker_mac: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    
    # Cibles et paramètres réseau
    subnet: str = ""  # CIDR (ex: 192.168.1.0/24)
    targets: List[str] = field(default_factory=list)  # Liste des IPs victimes
    
    # Paramètres d'attaque
    packet_forwarding_enabled: bool = False
    monitor_mode_enabled: bool = False

# Instance globale unique
conf = NetworkConfig()

def reset_config():
    """Réinitialise la configuration (utile lors des tests ou redémarrages)."""
    global conf
    conf = NetworkConfig()