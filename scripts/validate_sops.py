#!/usr/bin/env python3
"""Validate and summarize corpus normalization readiness."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.rag.indexer import KnowledgeIndexer


def main() -> int:
    indexer = KnowledgeIndexer()
    result = indexer.validate_sources()
    print(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))
    return 1 if result.invalid_sops else 0


if __name__ == "__main__":
    raise SystemExit(main())
