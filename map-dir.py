from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text
import logging
import os

# ------------------------------------------------------------------------------
# Rich setup
# ------------------------------------------------------------------------------
console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)

logger = logging.getLogger("project-mapper")

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
SKIP_DIRS = {
    "sentinelai",          # virtual environment
    "__pycache__",
    ".git",
    ".idea",
    ".vscode",
    "node_modules",
    ".pytest_cache",
    ".tmp",
    ".vendor",
}

# ------------------------------------------------------------------------------
# Directory mapping logic
# ------------------------------------------------------------------------------
def map_directory(base_path: Path, indent: int = 0):
    try:
        entries = sorted(base_path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except PermissionError:
        logger.warning(f"Permission denied: {base_path}")
        return

    for entry in entries:
        if entry.name in SKIP_DIRS:
            logger.info(f"{' ' * indent}⏭  [yellow]Skipping[/yellow] {entry.name}/")
            continue

        if entry.is_dir():
            text = Text(f"{' ' * indent}📁 {entry.name}/", style="bold blue")
            console.print(text)
            map_directory(entry, indent + 4)
        else:
            text = Text(f"{' ' * indent}📄 {entry.name}", style="green")
            console.print(text)

# ------------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------------
def main():
    root = Path(os.getcwd())
    logger.info(f"📍 Mapping project directory: [bold]{root}[/bold]\n")
    map_directory(root)
    logger.info("\n✅ Project mapping complete.")

if __name__ == "__main__":
    main()
