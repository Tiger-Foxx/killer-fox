# 🦊 FoxProwl - Killer Fox v2.0

**Outil offensif réseau modulaire professionnel**  
Projet noté Sécurité Informatique - École Polytechnique 2025

> ⚠️ **Usage strictement pédagogique et laboratoire isolé**  
> Code source privé - jamais publié

---

## 🎯 Fonctionnalités

### Reconnaissance
- **Scanner réseau** - Découverte ARP avec lookup vendeur OUI
- **Scan de ports** - TCP SYN scan avec détection de services
- **Résolution hostname** - DNS inverse automatique
- **Interface interactive** - Sélection graphique des cibles avec Rich

### Attaques MITM
- **ARP Spoofing** - Multi-cibles, modes quiet/agressif, context manager
- **DNS Spoofing** - Support regex (`regex:.*porn.*`), wildcards (`*.google.com`), blocage DoH
- **SSL Stripping** - Suppression HSTS/CSP, downgrade HTTPS→HTTP, capture credentials

### Attaques DoS/Blocage
- **TCP Killer** - RST agressif (4x bidirectionnel), blocage par domaine/port
- **Internet Blocker** - Blocage total ou sélectif, intégration auto ARP

### Hijacking & Injection
- **Session Hijacking** - Machine à états TCP, injection phishing/BeEF
- **HTTP Injector** - Templates (keylogger, cookie stealer, etc.), injection intelligente

---

## 🚀 Installation

### Prérequis
- Python 3.11+
- Windows: [Npcap](https://npcap.com/) (avec WinPcap API-compatible)
- Linux: Droits root (`sudo`)

### Installation
```bash
# Cloner le repo
cd foxprowl

# Installer les dépendances
pip install -r requirements.txt

# Lancer (Windows Admin / Linux sudo)
python killerfox.py
```

---

## 📖 Utilisation

### Mode Interactif (Recommandé)
```bash
python killerfox.py
```
Menu Rich avec toutes les options d'attaque.

### CLI Directe
```bash
# Scanner le réseau
python killerfox.py scan --subnet 192.168.1.0/24 --ports

# MITM sur une cible
python killerfox.py mitm 192.168.1.50 --aggressive

# Bloquer l'accès Internet
python killerfox.py block 192.168.1.50 --full
python killerfox.py block 192.168.1.50 --domains youtube.com,netflix.com

# DNS Spoofing
python killerfox.py dns "*.google.com:192.168.1.100,facebook.com:192.168.1.100"
```

---

## 🏗️ Architecture

```
foxprowl/
├── killerfox.py          # Point d'entrée CLI
├── core/
│   ├── config.py         # Configuration globale thread-safe
│   ├── logger.py         # Logging Rich thématique
│   ├── network.py        # Découverte réseau automatique
│   ├── mitigation.py     # IP forwarding, restauration ARP
│   └── utils.py          # DNS, rate limiting, helpers
└── modules/
    ├── scanner.py        # Scanner ARP + Ports
    ├── arp_spoof.py      # ARP MITM multi-cibles
    ├── dns_spoof.py      # DNS Spoofing regex/wildcards
    ├── tcp_killer.py     # TCP RST par domaine/port
    ├── internet_control.py # Blocage Internet
    ├── session_hijack.py # Hijacking TCP avec injection
    ├── ssl_strip.py      # SSL Stripping + capture
    └── http_injector.py  # Injection HTML/JS
```

---

## 🔧 Configuration

### `core/config.py`
```python
# Paramètres d'attaque
attack_conf.RST_PACKET_COUNT = 4      # RST par connexion
attack_conf.ARP_INTERVAL = 1.5        # Intervalle ARP (s)
attack_conf.DNS_TTL = 1               # TTL DNS très court
```

---

## 🎓 Contexte Académique

Ce projet est développé dans le cadre du cours de Sécurité Informatique à l'École Polytechnique. Il démontre les techniques d'attaque réseau suivantes:

1. **ARP Cache Poisoning** - Empoisonnement des tables ARP
2. **DNS Spoofing** - Redirection de requêtes DNS
3. **TCP Reset Attack** - Interruption de connexions TCP
4. **SSL Stripping** - Downgrade de connexions HTTPS
5. **Session Hijacking** - Prise de contrôle de sessions HTTP

**À utiliser uniquement en environnement de laboratoire isolé!**

---

## 📝 License

Projet académique privé - École Polytechnique 2025  
Reproduction et distribution interdites
