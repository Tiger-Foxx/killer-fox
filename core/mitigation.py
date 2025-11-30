"""
core/mitigation.py
Gestion de la propreté des attaques et restauration système.
Responsable de l'IP Forwarding et du Restore ARP.
"""
import os
import time
import platform
import subprocess
from scapy.all import *
from core.logger import log
from core.config import conf


class SystemControl:
    IS_WINDOWS = platform.system() == "Windows"

    @staticmethod
    def set_ip_forwarding(enable: bool):
        """Active ou désactive le routage de paquets (IP Forwarding)."""
        log.info(f"Configuration IP Forwarding : {'ON' if enable else 'OFF'}")
        
        if SystemControl.IS_WINDOWS:
            # Méthode Powershell/Netsh pour Windows (nécessite Admin)
            # Note: C'est complexe à faire de manière fiable scriptée sans savoir l'index précis
            # On log juste un avertissement si on ne peut pas le faire auto
            log.warning("Sur Windows, assurez-vous que 'Routing and Remote Access' est activé manuellement si nécessaire.")
            try:
                # Tentative générique via registre (peut nécessiter reboot, donc peu fiable en live)
                pass 
            except Exception:
                pass
        else:
            # Linux : méthode standard sysctl
            path = "/proc/sys/net/ipv4/ip_forward"
            try:
                with open(path, "w") as f:
                    f.write("1" if enable else "0")
            except PermissionError:
                log.error(f"Permission refusée pour écrire dans {path}. Lancez avec sudo.")

    @staticmethod
    def restore_arp(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str):
        """
        Envoie des paquets ARP corrects pour restaurer les tables des victimes.
        À appeler impérativement à la fin de l'attaque.
        """
        log.info(f"Restauration ARP : {target_ip} <-> {gateway_ip}")
        
        # Dire à la victime que la Gateway est bien la Gateway
        pkt_v = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        
        # Dire à la Gateway que la victime est bien la victime
        pkt_g = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        
        # Envoi multiple pour être sûr (UDP loss etc)
        send(pkt_v, count=5, verbose=False)
        send(pkt_g, count=5, verbose=False)