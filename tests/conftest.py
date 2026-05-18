"""Pytest bootstrap for local package imports."""

from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Keep unit tests deterministic and avoid native tokenizer/runtime crashes on Windows.
os.environ.setdefault("EMBEDDING_BACKEND", "hash")
os.environ.setdefault("ENABLE_RERANKING", "False")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TQDM_DISABLE", "1")
