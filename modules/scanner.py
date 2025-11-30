"""
modules/scanner.py
Scanner réseau complet et professionnel.
- Découverte ARP avec mise à jour live
- Scan de ports TCP (SYN scan avec Scapy)
- Détection de services
- Lookup vendeur OUI
- Interface interactive Rich avec sélection de cibles
"""
import time
import threading
import socket
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from scapy.all import srp, sr1, Ether, ARP, IP, TCP, ICMP, conf as scapy_conf

from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.logger import log, console
from core.config import conf


@dataclass
class HostInfo:
    """Informations sur un hôte découvert."""
    ip: str
    mac: str
    vendor: str = "Unknown"
    hostname: str = ""
    
    # Ports ouverts
    open_ports: Set[int] = field(default_factory=set)
    services: Dict[int, str] = field(default_factory=dict)
    
    # Métadonnées
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    is_gateway: bool = False
    is_local: bool = False
    
    def __hash__(self):
        return hash(self.ip)


class OUILookup:
    """Lookup des vendeurs via fichier OUI local."""
    
    def __init__(self):
        self.oui_db: Dict[str, str] = {}
        self._load_oui_file()
    
    def _load_oui_file(self):
        """Charge le fichier OUI local."""
        oui_path = Path(__file__).parent.parent / "data" / "oui.txt"
        if not oui_path.exists():
            return
        
        try:
            with open(oui_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        prefix = parts[0].replace(":", "").replace("-", "").upper()[:6]
                        self.oui_db[prefix] = parts[1]
        except Exception:
            pass
    
    def lookup(self, mac: str) -> str:
        """Trouve le vendeur pour une adresse MAC."""
        prefix = mac.replace(":", "").replace("-", "").upper()[:6]
        return self.oui_db.get(prefix, "Unknown")


# Services communs par port
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

# Ports à scanner par défaut
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]


class NetworkScanner:
    """
    Scanner réseau professionnel.
    
    Fonctionnalités:
    - Découverte ARP rapide
    - Scan de ports TCP (SYN scan)
    - Résolution hostname
    - Lookup vendeur MAC
    - Interface interactive Rich
    """
    
    def __init__(
        self,
        interface: str = None,
        subnet: str = None,
        ports: List[int] = None
    ):
        """
        :param interface: Interface réseau (auto-détecté si None)
        :param subnet: Subnet CIDR à scanner (auto-détecté si None)
        :param ports: Ports à scanner
        """
        self.interface = interface or conf.interface
        self.subnet = subnet or conf.subnet
        self.ports = ports or DEFAULT_PORTS
        
        # Hosts découverts
        self.hosts: Dict[str, HostInfo] = {}
        self._lock = threading.Lock()
        
        # OUI lookup
        self.oui = OUILookup()
        
        # État
        self.running = False
        self._scan_thread: Optional[threading.Thread] = None
    
    def _resolve_hostname(self, ip: str) -> str:
        """Résout le hostname d'une IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return ""
    
    def _scan_ports(self, host: HostInfo, ports: List[int] = None):
        """Scan TCP SYN des ports d'un hôte."""
        ports_to_scan = ports or self.ports
        
        for port in ports_to_scan:
            if not self.running:
                break
            
            try:
                # SYN scan
                pkt = IP(dst=host.ip) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=0.5, verbose=False, iface=self.interface)
                
                if resp and resp.haslayer(TCP):
                    tcp_flags = resp[TCP].flags
                    if tcp_flags & 0x12:  # SYN-ACK
                        host.open_ports.add(port)
                        host.services[port] = COMMON_SERVICES.get(port, "Unknown")
                        
                        # Envoyer RST pour fermer proprement
                        rst = IP(dst=host.ip) / TCP(dport=port, flags="R", 
                                                     seq=resp[TCP].ack)
                        sr1(rst, timeout=0.1, verbose=False, iface=self.interface)
            except Exception:
                pass
    
    def _arp_scan(self) -> List[Tuple[str, str]]:
        """Scan ARP du subnet."""
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
            ans, _ = srp(pkt, timeout=3, iface=self.interface, verbose=False)
            
            results = []
            for _, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                results.append((ip, mac))
            
            return results
        except Exception as e:
            log.error(f"Erreur ARP scan: {e}")
            return []
    
    def _continuous_scan(self):
        """Scan continu en arrière-plan."""
        while self.running:
            try:
                results = self._arp_scan()
                
                for ip, mac in results:
                    with self._lock:
                        if ip not in self.hosts:
                            host = HostInfo(
                                ip=ip,
                                mac=mac,
                                vendor=self.oui.lookup(mac),
                                hostname=self._resolve_hostname(ip),
                                is_gateway=(ip == conf.gateway_ip),
                                is_local=(ip == conf.attacker_ip)
                            )
                            self.hosts[ip] = host
                        else:
                            self.hosts[ip].last_seen = time.time()
                
                time.sleep(3)
            except Exception:
                time.sleep(1)
    
    def quick_scan(self) -> Dict[str, HostInfo]:
        """Scan rapide unique (ARP uniquement)."""
        log.info(f"Scan rapide du subnet {self.subnet}...")
        
        results = self._arp_scan()
        
        for ip, mac in results:
            if ip not in self.hosts:
                host = HostInfo(
                    ip=ip,
                    mac=mac,
                    vendor=self.oui.lookup(mac),
                    hostname=self._resolve_hostname(ip),
                    is_gateway=(ip == conf.gateway_ip),
                    is_local=(ip == conf.attacker_ip)
                )
                self.hosts[ip] = host
        
        log.success(f"{len(self.hosts)} hôtes découverts")
        return self.hosts
    
    def full_scan(self, targets: List[str] = None, ports: List[int] = None):
        """Scan complet avec ports."""
        if not self.hosts:
            self.quick_scan()
        
        hosts_to_scan = targets or list(self.hosts.keys())
        ports_to_scan = ports or self.ports
        
        log.info(f"Scan de ports sur {len(hosts_to_scan)} hôtes...")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Scan...", total=len(hosts_to_scan))
            
            for ip in hosts_to_scan:
                if ip in self.hosts and not self.hosts[ip].is_local:
                    progress.update(task, description=f"[cyan]{ip}[/]")
                    self._scan_ports(self.hosts[ip], ports_to_scan)
                progress.advance(task)
        
        log.success("Scan de ports terminé")
    
    def generate_table(self, show_ports: bool = False) -> Table:
        """Génère une table Rich des résultats."""
        table = Table(title=f"🦊 Scan Réseau - {self.subnet}", border_style="green")
        
        table.add_column("#", style="dim", width=3)
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Vendor", style="yellow")
        table.add_column("Hostname", style="white")
        
        if show_ports:
            table.add_column("Open Ports", style="green")
        
        # Tri par IP
        sorted_ips = sorted(
            self.hosts.keys(),
            key=lambda ip: tuple(map(int, ip.split('.')))
        )
        
        for idx, ip in enumerate(sorted_ips, 1):
            host = self.hosts[ip]
            
            # Tags
            tags = []
            if host.is_gateway:
                tags.append("[red](GW)[/]")
            if host.is_local:
                tags.append("[blue](YOU)[/]")
            
            ip_display = f"{ip} {' '.join(tags)}".strip()
            
            row = [
                str(idx),
                ip_display,
                host.mac,
                host.vendor[:25],
                host.hostname[:20] if host.hostname else "-"
            ]
            
            if show_ports:
                ports_str = ", ".join(
                    f"{p}({host.services.get(p, '?')})" 
                    for p in sorted(host.open_ports)
                ) or "-"
                row.append(ports_str[:40])
            
            table.add_row(*row)
        
        return table
    
    def interactive_scan(self) -> List[str]:
        """
        Interface interactive pour scanner et sélectionner des cibles.
        Retourne la liste des IPs sélectionnées.
        """
        self.running = True
        self._scan_thread = threading.Thread(target=self._continuous_scan, daemon=True)
        self._scan_thread.start()
        
        log.info("Scan réseau actif. Ctrl+C pour arrêter et sélectionner des cibles.")
        
        try:
            with Live(self.generate_table(), refresh_per_second=2, console=console) as live:
                while True:
                    live.update(self.generate_table())
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.running = False
        
        # Sélection des cibles
        if not self.hosts:
            log.warning("Aucun hôte découvert")
            return []
        
        console.print("\n")
        console.print(self.generate_table())
        console.print("\n")
        
        selected: List[str] = []
        
        # Options de sélection
        console.print("[bold]Options de sélection:[/]")
        console.print("  [cyan]all[/] - Toutes les cibles (sauf gateway et vous)")
        console.print("  [cyan]1,2,3[/] - Numéros séparés par virgules")
        console.print("  [cyan]1-5[/] - Plage de numéros")
        console.print("  [cyan]IP[/] - Adresse IP directe")
        console.print()
        
        choice = Prompt.ask("[bold green]Sélectionnez les cibles[/]", default="all")
        
        sorted_ips = sorted(
            self.hosts.keys(),
            key=lambda ip: tuple(map(int, ip.split('.')))
        )
        
        if choice.lower() == "all":
            selected = [
                ip for ip in sorted_ips
                if not self.hosts[ip].is_gateway and not self.hosts[ip].is_local
            ]
        elif "-" in choice and choice.replace("-", "").replace(" ", "").isdigit():
            # Plage
            try:
                start, end = map(int, choice.split("-"))
                for i in range(start, end + 1):
                    if 1 <= i <= len(sorted_ips):
                        ip = sorted_ips[i - 1]
                        if not self.hosts[ip].is_local:
                            selected.append(ip)
            except ValueError:
                pass
        elif "," in choice or choice.isdigit():
            # Liste de numéros
            nums = [int(x.strip()) for x in choice.split(",") if x.strip().isdigit()]
            for n in nums:
                if 1 <= n <= len(sorted_ips):
                    ip = sorted_ips[n - 1]
                    if not self.hosts[ip].is_local:
                        selected.append(ip)
        elif "." in choice:
            # IP directe
            if choice in self.hosts:
                selected.append(choice)
        
        if selected:
            log.success(f"{len(selected)} cible(s) sélectionnée(s): {', '.join(selected)}")
        
        return selected
    
    def run(self):
        """Alias pour interactive_scan()."""
        return self.interactive_scan()
    
    def stop(self):
        """Arrête le scan."""
        self.running = False
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=2.0)


def scan_network(subnet: str = None, interface: str = None) -> Dict[str, HostInfo]:
    """Helper pour un scan rapide."""
    scanner = NetworkScanner(interface=interface, subnet=subnet)
    return scanner.quick_scan()