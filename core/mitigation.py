"""
core/mitigation.py
Gestion système: IP Forwarding, restauration ARP, nettoyage.
Assure que le réseau est restauré proprement après les attaques.
"""
import os
import sys
import atexit
import signal
import platform
import subprocess
from typing import Dict, List, Tuple, Callable
from threading import Lock

from scapy.all import send, sendp, Ether, ARP

from core.logger import log
from core.config import conf, attack_conf


class SystemControl:
    """Contrôle des paramètres système pour les attaques MITM."""
    
    IS_WINDOWS = platform.system() == "Windows"
    IS_LINUX = platform.system() == "Linux"
    
    _original_ip_forward: str = "0"
    _cleanup_registered: bool = False
    _cleanup_callbacks: List[Callable] = []
    _lock = Lock()
    
    @classmethod
    def set_ip_forwarding(cls, enable: bool) -> bool:
        """
        Active ou désactive l'IP forwarding.
        Nécessaire pour que le trafic passe à travers nous lors du MITM.
        """
        with cls._lock:
            if cls.IS_LINUX:
                return cls._set_ip_forwarding_linux(enable)
            elif cls.IS_WINDOWS:
                return cls._set_ip_forwarding_windows(enable)
            return False
    
    @classmethod
    def _set_ip_forwarding_linux(cls, enable: bool) -> bool:
        """IP Forwarding sous Linux via /proc."""
        path = "/proc/sys/net/ipv4/ip_forward"
        
        try:
            # Sauvegarder l'état original
            if not conf.ip_forwarding_enabled:
                with open(path, "r") as f:
                    cls._original_ip_forward = f.read().strip()
            
            # Appliquer le nouveau état
            with open(path, "w") as f:
                f.write("1" if enable else "0")
            
            conf.ip_forwarding_enabled = enable
            log.info(f"IP Forwarding: {'ON' if enable else 'OFF'}")
            return True
        
        except PermissionError:
            log.error("Permission refusée pour IP Forwarding. Lancez avec sudo.")
            return False
        except Exception as e:
            log.error(f"Erreur IP Forwarding: {e}")
            return False
    
    @classmethod
    def _set_ip_forwarding_windows(cls, enable: bool) -> bool:
        """IP Forwarding sous Windows via netsh."""
        try:
            # Sur Windows, c'est plus complexe. On utilise netsh.
            # Note: Nécessite des privilèges admin
            
            if enable:
                # Activer le service de routage
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface", 
                     conf.interface, "forwarding=enabled"],
                    capture_output=True,
                    check=False
                )
            else:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface",
                     conf.interface, "forwarding=disabled"],
                    capture_output=True,
                    check=False
                )
            
            conf.ip_forwarding_enabled = enable
            log.info(f"IP Forwarding Windows: {'ON' if enable else 'OFF'}")
            return True
        
        except Exception as e:
            log.warning(f"IP Forwarding Windows peut nécessiter une config manuelle: {e}")
            return False
    
    @classmethod
    def restore_arp(cls, target_ip: str, gateway_ip: str, 
                    target_mac: str, gateway_mac: str, 
                    count: int = None) -> bool:
        """
        Restaure les tables ARP correctes sur la victime et la gateway.
        Envoie plusieurs paquets pour s'assurer que ça passe.
        """
        if count is None:
            count = attack_conf.ARP_RESTORE_COUNT
        
        try:
            # Restaurer la table ARP de la victime
            # "La gateway est à gateway_mac, pas à attacker_mac"
            pkt_to_victim = Ether(dst=target_mac) / ARP(
                op=2,  # is-at
                pdst=target_ip,
                hwdst=target_mac,
                psrc=gateway_ip,
                hwsrc=gateway_mac
            )
            
            # Restaurer la table ARP de la gateway
            # "La victime est à target_mac, pas à attacker_mac"
            pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
                op=2,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                psrc=target_ip,
                hwsrc=target_mac
            )
            
            # Envoyer plusieurs fois
            for _ in range(count):
                sendp(pkt_to_victim, iface=conf.interface, verbose=False)
                sendp(pkt_to_gateway, iface=conf.interface, verbose=False)
            
            log.info(f"ARP restauré: {target_ip} <-> {gateway_ip}")
            return True
        
        except Exception as e:
            log.error(f"Erreur restauration ARP: {e}")
            return False
    
    @classmethod
    def restore_all_arp(cls):
        """Restaure les tables ARP pour toutes les cibles connues."""
        if not conf.gateway_mac:
            log.warning("MAC gateway inconnue, restauration ARP impossible")
            return
        
        for ip, info in conf.discovered_hosts.items():
            mac = info.get('mac')
            if mac and ip != conf.gateway_ip and ip != conf.attacker_ip:
                cls.restore_arp(ip, conf.gateway_ip, mac, conf.gateway_mac)
    
    @classmethod
    def register_cleanup(cls, callback: Callable):
        """Enregistre une fonction de nettoyage à appeler lors de l'arrêt."""
        with cls._lock:
            cls._cleanup_callbacks.append(callback)
            
            if not cls._cleanup_registered:
                cls._cleanup_registered = True
                atexit.register(cls._do_cleanup)
                
                # Gérer aussi les signaux d'interruption
                try:
                    signal.signal(signal.SIGINT, cls._signal_handler)
                    signal.signal(signal.SIGTERM, cls._signal_handler)
                except Exception:
                    pass  # Peut échouer sur Windows dans certains contextes
    
    @classmethod
    def _signal_handler(cls, signum, frame):
        """Gestionnaire de signaux pour arrêt propre."""
        log.warning("Signal d'arrêt reçu, nettoyage en cours...")
        cls._do_cleanup()
        sys.exit(0)
    
    @classmethod
    def _do_cleanup(cls):
        """Exécute toutes les fonctions de nettoyage enregistrées."""
        log.info("Nettoyage et restauration du réseau...")
        
        with cls._lock:
            # Exécuter les callbacks enregistrés
            for callback in cls._cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    log.error(f"Erreur cleanup: {e}")
            
            cls._cleanup_callbacks.clear()
        
        # Restaurer IP Forwarding
        if conf.ip_forwarding_enabled:
            cls.set_ip_forwarding(False)
        
        # Restaurer les ARP
        cls.restore_all_arp()
        
        log.success("Nettoyage terminé.")
    
    @classmethod
    def cleanup_now(cls):
        """Force le nettoyage immédiat."""
        cls._do_cleanup()
    
    @classmethod
    def cleanup(cls):
        """Alias pour cleanup_now() - pour compatibilité."""
        cls._do_cleanup()
    
    @classmethod
    def enable_ip_forwarding(cls) -> bool:
        """Active l'IP forwarding."""
        return cls.set_ip_forwarding(True)
    
    @classmethod
    def disable_ip_forwarding(cls) -> bool:
        """Désactive l'IP forwarding."""
        return cls.set_ip_forwarding(False)


class FirewallControl:
    """Contrôle du firewall pour certaines attaques."""
    
    IS_LINUX = platform.system() == "Linux"
    
    @classmethod
    def add_iptables_rule(cls, rule: str) -> bool:
        """Ajoute une règle iptables (Linux)."""
        if not cls.IS_LINUX:
            return False
        
        try:
            subprocess.run(
                f"iptables {rule}",
                shell=True,
                check=True,
                capture_output=True
            )
            return True
        except Exception:
            return False
    
    @classmethod
    def remove_iptables_rule(cls, rule: str) -> bool:
        """Supprime une règle iptables (Linux)."""
        if not cls.IS_LINUX:
            return False
        
        try:
            # Remplacer -A par -D pour supprimer
            delete_rule = rule.replace("-A ", "-D ").replace("--append ", "--delete ")
            subprocess.run(
                f"iptables {delete_rule}",
                shell=True,
                check=True,
                capture_output=True
            )
            return True
        except Exception:
            return False
    
    @classmethod
    def redirect_port(cls, src_port: int, dst_port: int, protocol: str = "tcp") -> bool:
        """
        Redirige un port vers un autre (utile pour SSL stripping).
        Ex: Rediriger le port 80 vers 8080 local.
        """
        if not cls.IS_LINUX:
            log.warning("Redirection de port non supportée sur Windows")
            return False
        
        rule = (
            f"-t nat -A PREROUTING -p {protocol} --dport {src_port} "
            f"-j REDIRECT --to-port {dst_port}"
        )
        
        if cls.add_iptables_rule(rule):
            log.info(f"Redirection: {protocol}/{src_port} -> {dst_port}")
            return True
        return False
    
    @classmethod
    def clear_nat_rules(cls):
        """Supprime toutes les règles NAT."""
        if not cls.IS_LINUX:
            return
        
        try:
            subprocess.run(
                "iptables -t nat -F",
                shell=True,
                capture_output=True
            )
            log.info("Règles NAT nettoyées")
        except Exception:
            pass