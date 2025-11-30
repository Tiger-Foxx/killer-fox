"""
modules/scanner.py
Scanner réseau intelligent avec persistance.
- Découverte ARP avec mise à jour live
- Persistance des hôtes dans un fichier JSON (jamais de suppression)
- Statut online/offline pour chaque hôte
- Sortie avec touche Q (pas Ctrl+C)
- Accumulation intelligente des connaissances réseau
"""
import time
import threading
import socket
import json
import warnings
import logging
import sys
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

# Supprimer les messages d'erreur Scapy sur Windows
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import srp, sr1, Ether, ARP, IP, TCP, conf as scapy_conf

from rich.live import Live
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.logger import log, console
from core.config import conf

# Pour capturer les touches clavier sans blocage
if sys.platform == 'win32':
    import msvcrt


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
    
    # Métadonnées temporelles
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Statut
    is_gateway: bool = False
    is_local: bool = False
    is_online: bool = True  # Statut actuel
    times_seen: int = 1     # Nombre de fois vu
    
    # Historique (pour persistance)
    first_seen_date: str = ""
    last_seen_date: str = ""
    
    def __post_init__(self):
        if not self.first_seen_date:
            self.first_seen_date = datetime.now().isoformat()
        self.last_seen_date = datetime.now().isoformat()
    
    def __hash__(self):
        return hash(self.ip)
    
    def to_dict(self) -> dict:
        """Convertit en dictionnaire pour JSON."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "open_ports": list(self.open_ports),
            "services": self.services,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_gateway": self.is_gateway,
            "is_local": self.is_local,
            "is_online": self.is_online,
            "times_seen": self.times_seen,
            "first_seen_date": self.first_seen_date,
            "last_seen_date": self.last_seen_date,
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'HostInfo':
        """Crée un HostInfo depuis un dictionnaire."""
        host = HostInfo(
            ip=data.get("ip", ""),
            mac=data.get("mac", ""),
            vendor=data.get("vendor", "Unknown"),
            hostname=data.get("hostname", ""),
            first_seen=data.get("first_seen", time.time()),
            last_seen=data.get("last_seen", time.time()),
            is_gateway=data.get("is_gateway", False),
            is_local=data.get("is_local", False),
            is_online=data.get("is_online", False),
            times_seen=data.get("times_seen", 1),
            first_seen_date=data.get("first_seen_date", ""),
            last_seen_date=data.get("last_seen_date", ""),
        )
        host.open_ports = set(data.get("open_ports", []))
        host.services = data.get("services", {})
        return host


class HostDatabase:
    """
    Base de données persistante des hôtes réseau.
    Les hôtes ne sont JAMAIS supprimés, seulement mis à jour.
    """
    
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or Path(__file__).parent.parent / "data" / "hosts_db.json"
        self.hosts: Dict[str, HostInfo] = {}
        self._lock = threading.Lock()
        self._load()
    
    def _load(self):
        """Charge la base de données depuis le fichier."""
        if not self.db_path.exists():
            return
        
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for ip, host_data in data.get("hosts", {}).items():
                host = HostInfo.from_dict(host_data)
                host.is_online = False  # Marquer offline par défaut
                self.hosts[ip] = host
            
            log.debug(f"Base de données chargée: {len(self.hosts)} hôtes connus")
        except Exception as e:
            log.warning(f"Erreur chargement DB: {e}")
    
    def save(self):
        """Sauvegarde la base de données dans le fichier."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                "version": "1.0",
                "last_updated": datetime.now().isoformat(),
                "total_hosts": len(self.hosts),
                "hosts": {ip: host.to_dict() for ip, host in self.hosts.items()}
            }
            
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            log.debug(f"Base de données sauvegardée: {len(self.hosts)} hôtes")
        except Exception as e:
            log.warning(f"Erreur sauvegarde DB: {e}")
    
    def update_host(self, ip: str, mac: str, vendor: str = "Unknown", 
                   hostname: str = "", is_gateway: bool = False, 
                   is_local: bool = False) -> HostInfo:
        """
        Met à jour ou ajoute un hôte.
        Ne supprime JAMAIS, met juste à jour le statut.
        """
        with self._lock:
            now = time.time()
            
            if ip in self.hosts:
                # Hôte existant - mise à jour
                host = self.hosts[ip]
                host.is_online = True
                host.last_seen = now
                host.last_seen_date = datetime.now().isoformat()
                host.times_seen += 1
                
                # Mettre à jour les infos si elles sont meilleures
                if mac and mac != "00:00:00:00:00:00":
                    host.mac = mac
                if vendor and vendor != "Unknown":
                    host.vendor = vendor
                if hostname:
                    host.hostname = hostname
                if is_gateway:
                    host.is_gateway = True
                if is_local:
                    host.is_local = True
            else:
                # Nouvel hôte
                host = HostInfo(
                    ip=ip,
                    mac=mac,
                    vendor=vendor,
                    hostname=hostname,
                    is_gateway=is_gateway,
                    is_local=is_local,
                    is_online=True,
                    times_seen=1
                )
                self.hosts[ip] = host
                log.debug(f"Nouvel hôte découvert: {ip}")
            
            return host
    
    def mark_all_offline(self):
        """Marque tous les hôtes comme offline avant un scan."""
        with self._lock:
            for host in self.hosts.values():
                host.is_online = False
    
    def get_online_hosts(self) -> Dict[str, HostInfo]:
        """Retourne seulement les hôtes en ligne."""
        return {ip: h for ip, h in self.hosts.items() if h.is_online}
    
    def get_stats(self) -> dict:
        """Retourne des statistiques sur la base de données."""
        online = sum(1 for h in self.hosts.values() if h.is_online)
        offline = len(self.hosts) - online
        return {
            "total": len(self.hosts),
            "online": online,
            "offline": offline
        }


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

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]


def key_pressed() -> Optional[str]:
    """
    Vérifie si une touche a été pressée (non-bloquant).
    Retourne la touche ou None.
    """
    if sys.platform == 'win32':
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            try:
                return ch.decode('utf-8').lower()
            except:
                return None
    return None


class NetworkScanner:
    """
    Scanner réseau intelligent avec persistance.
    
    Fonctionnalités:
    - Découverte ARP rapide avec mise à jour live
    - Persistance des hôtes (ne jamais supprimer)
    - Statut online/offline
    - Sortie avec touche Q
    - Accumulation intelligente
    """
    
    def __init__(
        self,
        interface: str = None,
        subnet: str = None,
        ports: List[int] = None
    ):
        self.interface = interface or conf.interface
        self.subnet = subnet or conf.subnet
        self.ports = ports or DEFAULT_PORTS
        
        # Base de données persistante
        self.db = HostDatabase()
        
        # Vue actuelle (hôtes de cette session)
        self.hosts = self.db.hosts
        
        # OUI lookup
        self.oui = OUILookup()
        
        # État
        self.running = False
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
    
    def _resolve_hostname(self, ip: str) -> str:
        """Résout le hostname d'une IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            return ""
    
    def _scan_ports(self, host: HostInfo, ports: List[int] = None):
        """Scan TCP SYN des ports d'un hôte."""
        ports_to_scan = ports or self.ports
        
        for port in ports_to_scan:
            if self._stop_event.is_set():
                break
            
            try:
                pkt = IP(dst=host.ip) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=0.5, verbose=False, iface=self.interface)
                
                if resp and resp.haslayer(TCP):
                    tcp_flags = resp[TCP].flags
                    if tcp_flags & 0x12:  # SYN-ACK
                        host.open_ports.add(port)
                        host.services[port] = COMMON_SERVICES.get(port, "Unknown")
                        
                        # RST pour fermer proprement
                        rst = IP(dst=host.ip) / TCP(dport=port, flags="R", seq=resp[TCP].ack)
                        sr1(rst, timeout=0.1, verbose=False, iface=self.interface)
            except Exception:
                pass
    
    def _arp_scan(self) -> List[Tuple[str, str]]:
        """Scan ARP du subnet."""
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=conf.attacker_mac) / ARP(
                pdst=self.subnet,
                hwsrc=conf.attacker_mac,
                psrc=conf.attacker_ip
            )
            ans, _ = srp(pkt, timeout=2, iface=self.interface, verbose=False)
            
            results = []
            for _, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                results.append((ip, mac))
            
            return results
        except Exception as e:
            if not hasattr(self, '_scan_error_logged'):
                log.debug(f"Erreur ARP scan: {e}")
                self._scan_error_logged = True
            return []
    
    def _continuous_scan(self):
        """Scan continu en arrière-plan."""
        while not self._stop_event.is_set():
            try:
                results = self._arp_scan()
                
                for ip, mac in results:
                    vendor = self.oui.lookup(mac)
                    hostname = self._resolve_hostname(ip)
                    
                    self.db.update_host(
                        ip=ip,
                        mac=mac,
                        vendor=vendor,
                        hostname=hostname,
                        is_gateway=(ip == conf.gateway_ip),
                        is_local=(ip == conf.attacker_ip)
                    )
                
                # Sauvegarder périodiquement
                self.db.save()
                
                # Pause entre les scans
                for _ in range(30):  # 3 secondes en petits morceaux
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.1)
                    
            except Exception:
                time.sleep(1)
    
    def generate_table(self, show_ports: bool = False) -> Table:
        """Génère une table Rich des résultats."""
        stats = self.db.get_stats()
        title = f"🦊 Scan Réseau - {self.subnet} | " \
                f"[green]{stats['online']} online[/] / [dim]{stats['offline']} offline[/] / {stats['total']} total"
        
        table = Table(title=title, border_style="green")
        
        table.add_column("#", style="dim", width=3)
        table.add_column("Status", width=6)
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Vendor", style="yellow")
        table.add_column("Hostname", style="white")
        table.add_column("Vu", style="dim", width=4)
        
        if show_ports:
            table.add_column("Open Ports", style="green")
        
        # Tri: online en premier, puis par IP
        sorted_hosts = sorted(
            self.hosts.values(),
            key=lambda h: (not h.is_online, tuple(map(int, h.ip.split('.'))))
        )
        
        for idx, host in enumerate(sorted_hosts, 1):
            # Statut
            if host.is_online:
                status = "[bold green]● ON[/]"
            else:
                status = "[dim red]○ OFF[/]"
            
            # Tags
            tags = []
            if host.is_gateway:
                tags.append("[red](GW)[/]")
            if host.is_local:
                tags.append("[blue](YOU)[/]")
            
            ip_display = f"{host.ip} {' '.join(tags)}".strip()
            
            row = [
                str(idx),
                status,
                ip_display,
                host.mac,
                host.vendor[:25] if host.vendor else "-",
                host.hostname[:20] if host.hostname else "-",
                str(host.times_seen)
            ]
            
            if show_ports:
                ports_str = ", ".join(
                    f"{p}({host.services.get(p, '?')})" 
                    for p in sorted(host.open_ports)
                ) or "-"
                row.append(ports_str[:40])
            
            # Style de ligne selon statut
            if not host.is_online:
                table.add_row(*row, style="dim")
            else:
                table.add_row(*row)
        
        return table
    
    def interactive_scan(self) -> List[str]:
        """
        Interface interactive pour scanner et sélectionner des cibles.
        Appuyez sur Q pour quitter le scan.
        Retourne la liste des IPs sélectionnées.
        """
        self.running = True
        self._stop_event.clear()
        
        # Ne PAS marquer tous les hôtes offline - on garde l'état précédent
        # et on met à jour seulement ceux qu'on voit
        # Marquer offline seulement ceux qu'on n'a pas vu depuis longtemps
        
        # Lancer le thread de scan
        self._scan_thread = threading.Thread(target=self._continuous_scan, daemon=True)
        self._scan_thread.start()
        
        console.print()
        log.info("Scan réseau actif. Appuyez sur [bold cyan]Q[/] pour arrêter et sélectionner.")
        
        if self.db.hosts:
            console.print(f"[dim]📁 {len(self.db.hosts)} hôte(s) connu(s) chargé(s) depuis la base.[/]")
        console.print("[dim]Les hôtes sont sauvegardés automatiquement dans data/hosts_db.json[/]\n")
        
        try:
            with Live(self.generate_table(), refresh_per_second=2, console=console) as live:
                while self.running:
                    live.update(self.generate_table())
                    
                    # Vérifier si Q est pressé
                    key = key_pressed()
                    if key == 'q':
                        log.info("Arrêt du scan demandé...")
                        break
                    
                    time.sleep(0.2)
        except KeyboardInterrupt:
            # Ctrl+C aussi accepté mais Q préféré
            pass
        finally:
            # Arrêter proprement
            self.running = False
            self._stop_event.set()
            if self._scan_thread and self._scan_thread.is_alive():
                self._scan_thread.join(timeout=2.0)
            
            # Sauvegarder final
            self.db.save()
        
        # Synchroniser avec conf
        self._sync_with_config()
        
        # Sélection des cibles
        online_hosts = self.db.get_online_hosts()
        
        if not online_hosts:
            log.warning("Aucun hôte en ligne découvert dans cette session")
            if self.db.hosts:
                console.print(f"[dim]({len(self.db.hosts)} hôtes connus au total dans la base)[/]")
            return []
        
        console.print("\n")
        console.print(self.generate_table())
        console.print("\n")
        
        # Stats
        stats = self.db.get_stats()
        console.print(f"[bold]📊 Statistiques:[/] [green]{stats['online']} en ligne[/], "
                     f"[dim]{stats['offline']} hors ligne[/], {stats['total']} total connus")
        console.print()
        
        # Options de sélection
        console.print("[bold]Options de sélection:[/]")
        console.print("  [cyan]all[/]    - Toutes les cibles en ligne (sauf gateway et vous)")
        console.print("  [cyan]1,2,3[/]  - Numéros séparés par virgules")
        console.print("  [cyan]1-5[/]    - Plage de numéros")
        console.print("  [cyan]IP[/]     - Adresse IP directe")
        console.print("  [cyan]skip[/]   - Ignorer la sélection")
        console.print()
        
        choice = Prompt.ask("[bold green]Sélectionnez les cibles[/]", default="all")
        
        if choice.lower() == "skip":
            return []
        
        # Liste triée des hôtes (online d'abord)
        sorted_hosts = sorted(
            self.hosts.values(),
            key=lambda h: (not h.is_online, tuple(map(int, h.ip.split('.'))))
        )
        
        selected: List[str] = []
        
        if choice.lower() == "all":
            selected = [
                h.ip for h in sorted_hosts
                if h.is_online and not h.is_gateway and not h.is_local
            ]
        elif "-" in choice and choice.replace("-", "").replace(" ", "").isdigit():
            try:
                start, end = map(int, choice.split("-"))
                for i in range(start, end + 1):
                    if 1 <= i <= len(sorted_hosts):
                        host = sorted_hosts[i - 1]
                        if host.is_online and not host.is_local:
                            selected.append(host.ip)
            except ValueError:
                pass
        elif "," in choice or choice.isdigit():
            nums = [int(x.strip()) for x in choice.split(",") if x.strip().isdigit()]
            for n in nums:
                if 1 <= n <= len(sorted_hosts):
                    host = sorted_hosts[n - 1]
                    if host.is_online and not host.is_local:
                        selected.append(host.ip)
        elif "." in choice:
            if choice in self.hosts and self.hosts[choice].is_online:
                selected.append(choice)
        
        if selected:
            log.success(f"{len(selected)} cible(s) sélectionnée(s): {', '.join(selected)}")
            conf.targets = selected
        
        return selected
    
    def _sync_with_config(self):
        """Synchronise les hôtes découverts avec la configuration globale."""
        for ip, host in self.hosts.items():
            if host.is_online:
                conf.add_discovered_host(
                    ip=ip,
                    mac=host.mac,
                    vendor=host.vendor,
                    hostname=host.hostname
                )
    
    def quick_scan(self) -> Dict[str, HostInfo]:
        """Scan rapide unique (ARP uniquement)."""
        log.info(f"Scan rapide du subnet {self.subnet}...")
        
        results = self._arp_scan()
        
        for ip, mac in results:
            vendor = self.oui.lookup(mac)
            hostname = self._resolve_hostname(ip)
            
            self.db.update_host(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostname=hostname,
                is_gateway=(ip == conf.gateway_ip),
                is_local=(ip == conf.attacker_ip)
            )
        
        # Sauvegarder
        self.db.save()
        
        online = self.db.get_online_hosts()
        log.success(f"{len(online)} hôtes en ligne ({len(self.hosts)} total connus)")
        
        return online
    
    def full_scan(self, targets: List[str] = None, ports: List[int] = None):
        """Scan complet avec ports."""
        online = self.db.get_online_hosts()
        if not online:
            self.quick_scan()
            online = self.db.get_online_hosts()
        
        hosts_to_scan = targets or list(online.keys())
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
        
        # Sauvegarder les ports découverts
        self.db.save()
        
        log.success("Scan de ports terminé")
    
    def run(self):
        """Alias pour interactive_scan()."""
        return self.interactive_scan()
    
    def stop(self):
        """Arrête le scan."""
        self.running = False
        self._stop_event.set()
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=2.0)
        self.db.save()
    
    def show_known_hosts(self):
        """Affiche tous les hôtes connus (online et offline)."""
        console.print(self.generate_table())
        stats = self.db.get_stats()
        console.print(f"\n[bold]Total:[/] {stats['total']} hôtes connus, "
                     f"{stats['online']} en ligne, {stats['offline']} hors ligne")


def scan_network(subnet: str = None, interface: str = None) -> Dict[str, HostInfo]:
    """Helper pour un scan rapide."""
    scanner = NetworkScanner(interface=interface, subnet=subnet)
    return scanner.quick_scan()
