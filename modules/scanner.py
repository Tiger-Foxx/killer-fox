"""
modules/scanner.py
Scanner réseau actif avec affichage temps réel.
Utilise ARP Requests et mise à jour dynamique de l'interface.
"""
import time
import threading
from typing import List, Dict
from scapy.all import srp, Ether, ARP, conf as scapy_conf
from rich.live import Live
from rich.table import Table
from mac_vendor_lookup import MacLookup
from core.logger import log, console
from core.config import conf

class NetworkScanner:
    def __init__(self, interface: str, subnet: str):
        self.interface = interface
        self.subnet = subnet
        self.hosts: Dict[str, Dict] = {} # Key: IP, Value: {mac, vendor}
        self.running = False
        self.mac_lookup = MacLookup()
        
        # Mise à jour OUI vendors (fail-safe)
        try:
            # self.mac_lookup.update_vendors() # Commenté pour éviter téléchargement à chaque fois
            pass
        except:
            pass

    def _get_vendor(self, mac: str) -> str:
        try:
            return self.mac_lookup.lookup(mac)
        except KeyError:
            return "Inconnu"
        except:
            return "-"

    def _scan_thread(self):
        """Thread d'arrière-plan qui envoie les paquets ARP."""
        while self.running:
            try:
                # Envoi ARP Broadcast
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet),
                    timeout=2,
                    iface=self.interface,
                    verbose=False
                )
                
                for _, rcv in ans:
                    ip = rcv.psrc
                    mac = rcv.hwsrc
                    
                    if ip not in self.hosts:
                        self.hosts[ip] = {
                            "mac": mac,
                            "vendor": self._get_vendor(mac),
                            "status": "Online"
                        }
                        # Mise à jour globale des cibles potentielles
                        if ip not in conf.targets and ip != conf.gateway_ip and ip != conf.attacker_ip:
                            # On ne l'ajoute pas auto à conf.targets (c'est pour l'attaque), 
                            # mais on pourrait stocker dans un conf.detected_hosts
                            pass
            except Exception as e:
                # log.error(f"Erreur scan thread: {e}")
                pass
            
            time.sleep(3) # Pause entre les scans

    def generate_table(self) -> Table:
        table = Table(title=f"Scan Réseau : {self.subnet}", style="green")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Vendor", style="yellow")
        
        # Tri par IP pour l'affichage
        sorted_ips = sorted(self.hosts.keys(), key=lambda ip: tuple(map(int, ip.split('.'))))
        
        for ip in sorted_ips:
            host = self.hosts[ip]
            is_gw = " (Gateway)" if ip == conf.gateway_ip else ""
            is_me = " (Me)" if ip == conf.attacker_ip else ""
            
            table.add_row(
                f"{ip}{is_gw}{is_me}",
                host["mac"],
                host["vendor"]
            )
        return table

    def run(self):
        """Lance le scan interactif."""
        self.running = True
        t = threading.Thread(target=self._scan_thread, daemon=True)
        t.start()
        
        log.info("Scan actif lancé. Appuyez sur Ctrl+C pour arrêter et revenir au menu.")
        
        try:
            with Live(self.generate_table(), refresh_per_second=4) as live:
                while True:
                    live.update(self.generate_table())
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.running = False
            log.info("Arrêt du scan.")