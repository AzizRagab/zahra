#!/usr/bin/env python3
"""Index external RAG material (e.g. D:\\RAG HACK) into the Zahra brain.

This script ingests a directory of hacking-course / research material into the
ZahraAgent's local RAG corpus (the `documents` table), seeds the attack library,
and reports what was loaded so the model can recall it during chat / research.

Usage:
    python ingest_rag_material.py "D:\\RAG HACK"
    python ingest_rag_material.py "D:\\RAG HACK" --learn
    python ingest_rag_material.py "D:\\RAG HACK" --list
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from zahra_agent import ZahraAgent  # noqa: E402


def list_ingested(brain: ZahraAgent) -> None:
    docs = brain.memory.get_documents(limit=100000)
    print(f"\n{'=' * 60}")
    print(f"📚 Ingested RAG documents: {len(docs)}")
    print("=" * 60)
    for d in docs[:200]:
        print(f"  [id={d['id']}] {d['title']}  ({d['size']} chars)")
    print("=" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Index hacking-course / research material into the Zahra RAG brain."
    )
    parser.add_argument("directory", nargs="?", default=r"D:\RAG HACK",
                        help="Path to the material directory to ingest")
    parser.add_argument("--learn", action="store_true",
                        help="Also run deep-adaptive learning on each chunk")
    parser.add_argument("--list", action="store_true",
                        help="Only list already-ingested documents")
    parser.add_argument("--chunk", type=int, default=6000,
                        help="Chunk size in characters (default 6000)")
    parser.add_argument("--overlap", type=int, default=300,
                        help="Chunk overlap in characters (default 300)")
    args = parser.parse_args()

    brain = ZahraAgent()
    print(f"🧠 Zahra brain loaded: {brain.memory.db_path}")
    print(f"   Autonomous mode: {brain.unrestricted}")

    if args.list:
        list_ingested(brain)
        return 0

    directory = os.path.abspath(args.directory)
    if not os.path.isdir(directory):
        print(f"❌ Not a directory: {directory}")
        return 1

    print(f"\n📁 Ingesting: {directory}")
    result = brain.ingest_local_files(
        directory,
        recursive=True,
        chunk_chars=args.chunk,
        overlap=args.overlap,
        learn=args.learn,
    )

    print(f"\n{'=' * 60}")
    print("✅ Ingestion complete")
    print(f"   Ingested chunks : {result['ingested']}")
    print(f"   Skipped (binary) : {result['skipped']}")
    print(f"   Learned skills  : {result['learned']}")
    print(f"   Errors          : {len(result['errors'])}")
    for err in result["errors"][:20]:
        print(f"     - {err}")
    print("=" * 60)

    list_ingested(brain)

    print("\n🔍 RAG recall test queries:")
    for q in ("nmap port scan", "SQL injection", "reverse shell", "Metasploit exploit"):
        hits = brain.memory.recall_documents(q, top_k=2, min_score=0.02)
        if hits:
            print(f"\n  Query: {q}")
            for h in hits:
                prev = h["content"][:120].replace(chr(10), " ")
                print(f"    → [{h['similarity']}] {h['title']}: {prev}...")
        else:
            print(f"\n  Query: {q}\n    → No results")

    print("\n✅ Done. The model can now recall this material during chat/research.")
    return 0


if __name__ == "__main__":
    sys.exit(main())