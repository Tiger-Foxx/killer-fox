"""
killerfox.py
Point d'entrée principal - CLI Interactive & Automatisée.
"""
import sys
import time
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text

# Imports Core & Modules
from core.logger import log, console
from core.config import conf
from core.network import AutoDiscovery
from modules.arp_spoof import ARPSpoofer
from modules.dns_spoof import DNSSpoofer
# from modules.internet_control import InternetBlocker (Importé à la demande)

app = typer.Typer(help="Killer Fox - Offensive Network Tool", add_completion=False)

def check_root():
    import os
    if os.name == 'nt': return # Windows Admin check complex, skipped for brevity
    elif os.geteuid() != 0:
        console.print("[bold red]Erreur: Doit être lancé en ROOT (sudo).[/bold red]")
        sys.exit(1)

def setup_network():
    """Configuration initiale automatique."""
    console.print("[yellow]Auto-configuration du réseau...[/yellow]")
    iface_list = AutoDiscovery.get_interfaces()
    if not iface_list:
        log.error("Aucune interface trouvée.")
        sys.exit(1)
    
    # Choix auto ou manuel simplifie: on prend la 1ere non-loopback
    # Dans une vraie interactive, on listerait
    selected = iface_list[0]
    conf.interface = selected['name']
    
    net_info = AutoDiscovery.get_network_details(conf.interface)
    conf.attacker_ip = net_info.get('ip')
    conf.gateway_ip = net_info.get('gateway')
    conf.subnet = net_info.get('cidr')
    
    console.print(Panel(
        f"Interface : [bold cyan]{conf.interface}[/bold cyan]\n"
        f"IP        : [green]{conf.attacker_ip}[/green]\n"
        f"Gateway   : [yellow]{conf.gateway_ip}[/yellow]\n"
        f"Subnet    : [blue]{conf.subnet}[/blue]",
        title="Configuration Active"
    ))

def interactive_menu():
    """Mode Menu Interactif."""
    setup_network()
    
    spoofer = None
    dns_module = None
    
    while True:
        console.print("\n[bold underline]Menu Principal Killer Fox[/bold underline]")
        console.print("1. [cyan]Scanner le réseau[/cyan] (ARP Discovery)")
        console.print("2. [red]Lancer ARP MITM[/red] (Spoofing)")
        console.print("3. [magenta]Activer DNS Spoofing[/magenta]")
        console.print("4. [yellow]Bloquer Internet (TCP Kill)[/yellow]")
        console.print("4. [yellow]Bloquer Internet[/yellow] (Targeted DoS)")
        console.print("5. [bold red]Session Hijacking[/bold red] (Phishing/BeEF)")
        console.print("6. [bold blue]SSL Stripping[/bold blue] (Downgrade)")
        console.print("9. [bold]Quitter[/bold]")
        
        
        choice = Prompt.ask("Choix", choices=["1", "2", "3", "4", "5", "6", "9"], default="1")
        
        if choice == "1":
            from modules.scanner import NetworkScanner
            scan = NetworkScanner(conf.interface, conf.subnet)
            scan.run() # Bloquant jusqu'à Ctrl+C
            
        elif choice == "2":
            target = Prompt.ask("IP Victime (ou 'all' pour tout le réseau)", default="all")
            # Logique simplifiée pour l'exemple interactif
            if target == "all":
                # Dans un vrai cas, on prendrait la liste du scanner
                log.warning("Mode 'all' nécessite un scan préalable. Utilisation d'une IP test pour démo.")
                target_list = ["192.168.1.50"] # Placeholder
            else:
                target_list = [target]
                
            conf.targets = target_list
            spoofer = ARPSpoofer(targets=conf.targets)
            spoofer.start()
            
        elif choice == "3":
            if not spoofer or not spoofer.running:
                log.warning("Attention: DNS Spoofing inefficace sans ARP Spoofing (Option 2).")
            dns_module = DNSSpoofer()
            dns_module.start()
            
         
        elif choice == "4":
            t_ip = Prompt.ask("IP Victime")
            dom = Prompt.ask("Domaine à bloquer (vide pour tout Internet)", default="")
            from modules.internet_control import InternetBlocker
            domains = [dom] if dom else None
            full = dom == ""
            blocker = InternetBlocker(t_ip, blocked_domains=domains, full_block=full)
            blocker.start() # Bloquant, Ctrl+C pour sortir
            
        elif choice == "5":
            t_ip = Prompt.ask("IP Victime")
            mode = Prompt.ask("Mode", choices=["phishing", "beef"], default="phishing")
            from modules.session_hijack import SessionHijacker
            hijacker = SessionHijacker(t_ip, mode=mode)
            try:
                hijacker.start()
            except KeyboardInterrupt:
                hijacker.stop()
                
        elif choice == "6":
            from modules.ssl_strip import SSLStripper
            stripper = SSLStripper()
            try:
                stripper.start()
            except KeyboardInterrupt:
                stripper.stop()

        elif choice == "9":
            console.print("[bold red]Arrêt des modules...[/bold red]")
            if spoofer: spoofer.stop()
            if dns_module: dns_module.stop()
            break

@app.command()
def start():
    """Lance le mode interactif par défaut."""
    check_root()
    interactive_menu()

@app.command("quick-mitm")
def cmd_mitm(target: str):
    """Lance une attaque MITM rapide en ligne de commande."""
    check_root()
    setup_network()
    spoofer = ARPSpoofer(targets=[target])
    try:
        spoofer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        spoofer.stop()

if __name__ == "__main__":
    # Si aucun argument n'est passé, on lance le mode interactif
    if len(sys.argv) == 1:
        check_root()
        interactive_menu()
    else:
        app()