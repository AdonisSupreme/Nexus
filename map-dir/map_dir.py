import os
import logging
from pathlib import Path

# ---- COLOR CODES ----
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# ---- DIRECTORIES TO IGNORE ----
IGNORED_DIRS = {"sentinelenv", "__pycache__"}

# ---- LOGGING SETUP ----
logging.basicConfig(
    level=logging.WARNING,  # hide INFO noise, show warnings/errors
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger(__name__)


def map_directory(path: Path, prefix: str = ""):
    """Recursively print a clean, visually appealing directory tree."""

    try:
        items = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except Exception as e:
        logger.error(f"Error reading directory {path}: {e}")
        return

    count = len(items)
    for index, item in enumerate(items):
        connector = "└── " if index == count - 1 else "├── "

        if item.is_dir():
            if item.name in IGNORED_DIRS:
                print(prefix + connector + f"{YELLOW}{item.name}/{RESET} (skipped)")
                logger.info(f"Skipping ignored directory: {item}")
                continue

            print(prefix + connector + f"{BLUE}{item.name}/{RESET}")
            next_prefix = prefix + ("    " if index == count - 1 else "│   ")
            map_directory(item, next_prefix)

        elif item.is_symlink():
            print(prefix + connector + f"{YELLOW}{item.name}@{RESET}")

        elif item.is_file():
            print(prefix + connector + f"{GREEN}{item.name}{RESET}")

        else:
            print(prefix + connector + f"{RED}{item.name} (unknown){RESET}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Visually map a directory tree with colors.")
    parser.add_argument(
        "--path",
        type=str,
        help="Optional: directory to map. Defaults to the parent directory of this script."
    )
    args = parser.parse_args()

    if args.path:
        target_path = Path(args.path).resolve()
    else:
        script_dir = Path(__file__).resolve().parent
        target_path = script_dir.parent
        logger.info(f"Auto-targeting project root: {target_path}")

    if not target_path.exists():
        logger.error(f"Path does not exist: {target_path}")
        exit(1)

    print(f"\nMapping: {BLUE}{target_path}{RESET}\n")
    map_directory(target_path)
    print("\nDone.\n")
