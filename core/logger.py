"""
core/logger.py
Système de log centralisé utilisant Rich pour une interface CLI moderne.
"""
import datetime
from rich.console import Console
from rich.theme import Theme

# Thème personnalisé pour correspondre à l'esthétique 'Offensive Security'
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "data": "magenta"
})

console = Console(theme=custom_theme)

class Logger:
    @staticmethod
    def _timestamp() -> str:
        return datetime.datetime.now().strftime("[%H:%M:%S]")

    @staticmethod
    def info(msg: str):
        console.print(f"{Logger._timestamp()} [info][*][/info] {msg}")

    @staticmethod
    def success(msg: str):
        console.print(f"{Logger._timestamp()} [success][+][/success] {msg}")

    @staticmethod
    def warning(msg: str):
        console.print(f"{Logger._timestamp()} [warning][!][/warning] {msg}")

    @staticmethod
    def error(msg: str):
        console.print(f"{Logger._timestamp()} [error][-][/error] {msg}")

    @staticmethod
    def raw(msg: str):
        """Affiche un message sans formatage (pour les tableaux raw)."""
        console.print(msg)

# Instance globale
log = Logger()