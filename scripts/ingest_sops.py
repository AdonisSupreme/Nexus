#!/usr/bin/env python3
"""Normalize, chunk, and index the SOP corpus."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.rag.indexer import KnowledgeIndexer


def main() -> int:
    indexer = KnowledgeIndexer()
    result = indexer.ingest()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
