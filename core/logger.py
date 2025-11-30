"""
core/logger.py
Système de logging avancé avec Rich.
Support des niveaux, fichiers log, et affichage temps réel.
"""
import os
import datetime
from typing import Optional
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.live import Live
from threading import Lock

# Thème FoxProwl - Esthétique offensive security
FOXPROWL_THEME = Theme({
    "info": "cyan",
    "warning": "yellow bold",
    "error": "red bold",
    "success": "green bold",
    "critical": "white on red bold",
    "attack": "magenta bold",
    "victim": "red",
    "data": "blue",
    "subtle": "dim white",
    "highlight": "bold cyan underline"
})

# Console principale
console = Console(theme=FOXPROWL_THEME, highlight=False)

# Verrou pour les écritures concurrentes
_log_lock = Lock()


class FoxLogger:
    """Logger centralisé pour FoxProwl."""
    
    def __init__(self, log_to_file: bool = True, log_dir: str = "logs"):
        self.log_to_file = log_to_file
        self.log_dir = log_dir
        self.log_file: Optional[str] = None
        self._file_handle = None
        
        if log_to_file:
            os.makedirs(log_dir, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_file = os.path.join(log_dir, f"foxprowl_{timestamp}.log")
    
    def _timestamp(self) -> str:
        return datetime.datetime.now().strftime("%H:%M:%S")
    
    def _write_to_file(self, level: str, msg: str):
        """Écrit dans le fichier log si activé."""
        if self.log_to_file and self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    # Strip Rich markup pour le fichier
                    clean_msg = msg
                    f.write(f"[{timestamp}] [{level}] {clean_msg}\n")
            except Exception:
                pass
    
    def info(self, msg: str):
        """Information générale."""
        with _log_lock:
            console.print(f"[subtle]{self._timestamp()}[/subtle] [info]●[/info] {msg}")
            self._write_to_file("INFO", msg)
    
    def success(self, msg: str):
        """Opération réussie."""
        with _log_lock:
            console.print(f"[subtle]{self._timestamp()}[/subtle] [success]✓[/success] {msg}")
            self._write_to_file("SUCCESS", msg)
    
    def warning(self, msg: str):
        """Avertissement."""
        with _log_lock:
            console.print(f"[subtle]{self._timestamp()}[/subtle] [warning]⚠[/warning] {msg}")
            self._write_to_file("WARNING", msg)
    
    def error(self, msg: str):
        """Erreur."""
        with _log_lock:
            console.print(f"[subtle]{self._timestamp()}[/subtle] [error]✗[/error] {msg}")
            self._write_to_file("ERROR", msg)
    
    def critical(self, msg: str):
        """Erreur critique."""
        with _log_lock:
            console.print(f"[subtle]{self._timestamp()}[/subtle] [critical] FATAL [/critical] {msg}")
            self._write_to_file("CRITICAL", msg)
    
    def attack(self, msg: str):
        """Log d'attaque en cours."""
        with _log_lock:
            console.print(f"[subtle]{self._timestamp()}[/subtle] [attack]⚡[/attack] {msg}")
            self._write_to_file("ATTACK", msg)
    
    def victim(self, ip: str, msg: str):
        """Log spécifique à une victime."""
        with _log_lock:
            console.print(f"[subtle]{self._timestamp()}[/subtle] [victim]🎯 {ip}[/victim] → {msg}")
            self._write_to_file("VICTIM", f"{ip}: {msg}")
    
    def packet(self, direction: str, src: str, dst: str, proto: str, info: str = ""):
        """Log de paquet réseau (mode verbose)."""
        with _log_lock:
            arrow = "→" if direction == "out" else "←"
            console.print(f"[subtle]{self._timestamp()}[/subtle] [data]{proto}[/data] {src} {arrow} {dst} {info}")
    
    def raw(self, msg: str):
        """Affichage brut sans formatage timestamp."""
        with _log_lock:
            console.print(msg)
    
    def banner(self):
        """Affiche la bannière FoxProwl."""
        banner_text = """
[bold red]
    ███████╗ ██████╗ ██╗  ██╗[/bold red][bold yellow]██████╗ ██████╗  ██████╗ ██╗    ██╗██╗     [/bold yellow]
[bold red]    ██╔════╝██╔═══██╗╚██╗██╔╝[/bold red][bold yellow]██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║     [/bold yellow]
[bold red]    █████╗  ██║   ██║ ╚███╔╝ [/bold red][bold yellow]██████╔╝██████╔╝██║   ██║██║ █╗ ██║██║     [/bold yellow]
[bold red]    ██╔══╝  ██║   ██║ ██╔██╗ [/bold red][bold yellow]██╔═══╝ ██╔══██╗██║   ██║██║███╗██║██║     [/bold yellow]
[bold red]    ██║     ╚██████╔╝██╔╝ ██╗[/bold red][bold yellow]██║     ██║  ██║╚██████╔╝╚███╔███╔╝███████╗[/bold yellow]
[bold red]    ╚═╝      ╚═════╝ ╚═╝  ╚═╝[/bold red][bold yellow]╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝[/bold yellow]
"""
        console.print(banner_text)
        console.print("[dim]    ═══════════════════════════════════════════════════════════════[/dim]")
        console.print("[bold cyan]    Offensive Network Toolkit[/bold cyan] [dim]│[/dim] [yellow]École Polytechnique 2025[/yellow]")
        console.print("[dim]    Usage strictement pédagogique - Environnement lab isolé[/dim]")
        console.print("[dim]    ═══════════════════════════════════════════════════════════════[/dim]\n")
    
    def status_panel(self, title: str, content: str, style: str = "cyan"):
        """Affiche un panel de statut."""
        console.print(Panel(content, title=title, border_style=style))
    
    def table(self, title: str, columns: list, rows: list, style: str = "cyan"):
        """Affiche un tableau formaté."""
        table = Table(title=title, border_style=style)
        for col in columns:
            table.add_column(col["name"], style=col.get("style", ""), justify=col.get("justify", "left"))
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        console.print(table)


# Instance globale
log = FoxLogger()


def get_progress() -> Progress:
    """Retourne un objet Progress pour les barres de progression."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    )


def get_live(renderable) -> Live:
    """Retourne un objet Live pour les mises à jour temps réel."""
    return Live(renderable, console=console, refresh_per_second=4)