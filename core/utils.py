"""
core/utils.py
Utilitaires et helpers pour FoxProwl.
Résolution DNS avec cache, manipulation MAC, validation IP, etc.
"""
import re
import socket
import struct
import ipaddress
import threading
import time
from typing import Optional, List, Set, Dict, Tuple
from functools import lru_cache
from pathlib import Path

# Cache DNS thread-safe
_dns_cache: Dict[str, Tuple[Set[str], float]] = {}
_dns_cache_lock = threading.Lock()
_DNS_CACHE_TTL = 300  # 5 minutes


def resolve_domain(domain: str, use_cache: bool = True) -> Set[str]:
    """
    Résout un domaine en IPs (toutes les IPs, pas juste la première).
    Utilise un cache thread-safe pour la performance.
    """
    domain = domain.lower().strip()
    if domain.startswith("www."):
        # On résout aussi sans www
        pass
    
    # Vérifier le cache
    if use_cache:
        with _dns_cache_lock:
            if domain in _dns_cache:
                ips, timestamp = _dns_cache[domain]
                if time.time() - timestamp < _DNS_CACHE_TTL:
                    return ips
    
    ips = set()
    
    try:
        # Utiliser getaddrinfo pour obtenir toutes les IPs (IPv4)
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        for result in results:
            ips.add(result[4][0])
    except socket.gaierror:
        pass
    
    # Essayer avec www. si pas de résultat
    if not ips and not domain.startswith("www."):
        try:
            results = socket.getaddrinfo(f"www.{domain}", None, socket.AF_INET)
            for result in results:
                ips.add(result[4][0])
        except socket.gaierror:
            pass
    
    # Mettre en cache
    if ips:
        with _dns_cache_lock:
            _dns_cache[domain] = (ips, time.time())
    
    return ips


def resolve_domains_batch(domains: List[str]) -> Dict[str, Set[str]]:
    """Résout plusieurs domaines en parallèle."""
    results = {}
    threads = []
    lock = threading.Lock()
    
    def resolve_single(domain):
        ips = resolve_domain(domain)
        with lock:
            results[domain] = ips
    
    for domain in domains:
        t = threading.Thread(target=resolve_single, args=(domain,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join(timeout=5.0)
    
    return results


def expand_domain_wildcards(pattern: str, domain: str) -> bool:
    """
    Vérifie si un domaine correspond à un pattern avec wildcards.
    Supporte: *.domain.com, domain.*, *domain*
    """
    pattern = pattern.lower().strip()
    domain = domain.lower().strip()
    
    # Conversion du pattern en regex
    if pattern.startswith("regex:"):
        # Pattern regex explicite
        try:
            return bool(re.match(pattern[6:], domain, re.IGNORECASE))
        except re.error:
            return False
    
    # Wildcards simples
    regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
    try:
        return bool(re.fullmatch(regex_pattern, domain, re.IGNORECASE))
    except re.error:
        return False


def is_valid_ip(ip: str) -> bool:
    """Vérifie si une chaîne est une IPv4 valide."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Vérifie si une chaîne est un CIDR valide."""
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def expand_cidr(cidr: str) -> List[str]:
    """Expanse un CIDR en liste d'IPs."""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception:
        return []


def expand_ip_range(start_ip: str, end_ip: str) -> List[str]:
    """Génère une liste d'IPs entre start et end inclus."""
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
    except Exception:
        return []


def mac_to_bytes(mac: str) -> bytes:
    """Convertit une adresse MAC en bytes."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def bytes_to_mac(b: bytes) -> str:
    """Convertit des bytes en adresse MAC formatée."""
    return ":".join(f"{byte:02x}" for byte in b)


def normalize_mac(mac: str) -> str:
    """Normalise une adresse MAC au format aa:bb:cc:dd:ee:ff."""
    mac = mac.lower().replace("-", ":").replace(".", ":")
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    return mac


def ip_to_int(ip: str) -> int:
    """Convertit une IP en entier."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(ip_int: int) -> str:
    """Convertit un entier en IP."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def get_broadcast_mac() -> str:
    """Retourne l'adresse MAC broadcast."""
    return "ff:ff:ff:ff:ff:ff"


def is_private_ip(ip: str) -> bool:
    """Vérifie si une IP est privée (RFC 1918)."""
    try:
        return ipaddress.IPv4Address(ip).is_private
    except Exception:
        return False


def parse_port_range(port_str: str) -> List[int]:
    """
    Parse une chaîne de ports en liste.
    Supporte: "80", "80,443", "80-100", "80,443,8000-8100"
    """
    ports = []
    parts = port_str.replace(" ", "").split(",")
    
    for part in parts:
        if "-" in part:
            try:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    
    return sorted(set(ports))


def load_hosts_file(filepath: str) -> Dict[str, str]:
    """
    Charge un fichier hosts personnalisé.
    Format: IP DOMAINE [# commentaire]
    Retourne: {domaine: ip}
    """
    hosts = {}
    path = Path(filepath)
    
    if not path.exists():
        return hosts
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # Supprimer les commentaires inline
                if "#" in line:
                    line = line.split("#")[0].strip()
                
                parts = line.split()
                if len(parts) >= 2:
                    ip, domain = parts[0], parts[1]
                    if is_valid_ip(ip):
                        # Normaliser le domaine
                        if not domain.endswith("."):
                            domain += "."
                        hosts[domain.lower()] = ip
    except Exception:
        pass
    
    return hosts


def load_target_file(filepath: str) -> List[str]:
    """Charge un fichier de cibles (une IP/CIDR par ligne)."""
    targets = []
    path = Path(filepath)
    
    if not path.exists():
        return targets
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                if is_valid_ip(line):
                    targets.append(line)
                elif is_valid_cidr(line):
                    targets.extend(expand_cidr(line))
    except Exception:
        pass
    
    return list(set(targets))


class RateLimiter:
    """Limiteur de débit pour les attaques."""
    
    def __init__(self, max_rate: float):
        """
        :param max_rate: Nombre max d'opérations par seconde
        """
        self.min_interval = 1.0 / max_rate if max_rate > 0 else 0
        self.last_time = 0.0
        self._lock = threading.Lock()
    
    def wait(self):
        """Attend si nécessaire pour respecter le rate limit."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_time = time.time()


class Counter:
    """Compteur thread-safe."""
    
    def __init__(self, initial: int = 0):
        self._value = initial
        self._lock = threading.Lock()
    
    def increment(self, amount: int = 1) -> int:
        with self._lock:
            self._value += amount
            return self._value
    
    def decrement(self, amount: int = 1) -> int:
        with self._lock:
            self._value -= amount
            return self._value
    
    @property
    def value(self) -> int:
        with self._lock:
            return self._value
    
    def reset(self):
        with self._lock:
            self._value = 0


def format_bytes(size: int) -> str:
    """Formate une taille en bytes de manière lisible."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def format_duration(seconds: float) -> str:
    """Formate une durée en secondes de manière lisible."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
