#!/usr/bin/env python3
"""Build a fine-tuning dataset for the ZAHRA model from the RAG corpus.

This assembles the ingested hacking-course material (D:\\RAG HACK, plus any
own project docs) into a JSONL dataset of (instruction, context, output) triples
ready for fine-tuning (e.g. Ollama / llama.cpp / LoRA), and also exports the
conversation log for continuous training.

Usage:
    python build_training_dataset.py                         # use default RAG material dirs
    python build_training_dataset.py --dirs "D:\\RAG HACK" "docs"
    python build_training_dataset.py --out zahra_model/data/train.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from zahra_agent import ZahraAgent  # noqa: E402

DEFAULT_DIRS = [
    r"D:\RAG HACK",
    "docs",
]


def build(brain: ZahraAgent, dirs, out_path) -> int:
    """Ingest material, then emit a training dataset (instruction + context + output)."""
    # 1) Ingest all material into the RAG corpus (idempotent)
    total_ingested = 0
    for d in dirs:
        d = os.path.abspath(d)
        if not os.path.isdir(d):
            print(f"  - skipping (not a dir): {d}")
            continue
        res = brain.ingest_local_files(d, recursive=True, chunk_chars=6000, overlap=300,
                                       learn=True)
        total_ingested += res["total_chunks"]
        print(f"  - {d}: {res['total_chunks']} chunk(s) [learned {res['learned']} skill(s)]")

    # 2) Pull the full document corpus
    docs = brain.memory.get_documents(limit=100000)
    skills = brain.memory.get_skills()
    print(f"  corpus: {len(docs)} document chunks, {len(skills)} skills")

    # 3) Build instruction/output pairs
    rows = []
    seen = set()

    # a) Documents -> "explain/teach" pairs
    for d in docs:
        title = d["title"]
        content = " ".join(d["content"].split())
        if not content:
            continue
        key = f"doc:{title}"
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "instruction": f"Explain {title.split(' (part')[0]} from the course material.",
            "input": content[:4000],
            "output": content[:2000],
            "source": "document",
        })

    # b) Skills -> "how to" pairs
    for s in skills:
        if s["name"] in seen:
            continue
        seen.add(s["name"])
        rows.append({
            "instruction": f"How do I use {s['name']}?",
            "input": s.get("description", "")[:1000],
            "output": s.get("command_template", "")[:1500],
            "source": "skill",
        })

    # c) Conversation log (continuous learning) — only successful/complete turns
    conv_path = os.path.join("zahra_model", "data", "conversations.jsonl")
    if os.path.exists(conv_path):
        try:
            with open(conv_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not rec.get("user") or not rec.get("assistant"):
                        continue
                    rows.append({
                        "instruction": rec["user"],
                        "input": "",
                        "output": rec["assistant"],
                        "source": "conversation",
                    })
        except OSError:
            pass

    # 4) Deduplicate + write
    unique = {}
    for r in rows:
        unique[(r["instruction"], r["output"][:100])] = r
    final = list(unique.values())

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for r in final:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n✅ Training dataset written: {out_path}")
    print(f"   Total records: {len(final)}")
    by_src = {}
    for r in final:
        by_src[r["source"]] = by_src.get(r["source"], 0) + 1
    for src, n in sorted(by_src.items()):
        print(f"     {src:<14} {n}")
    return len(final)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a ZAHRA fine-tuning dataset.")
    parser.add_argument("--dirs", nargs="*", default=DEFAULT_DIRS,
                        help="Directories to ingest into the RAG corpus")
    parser.add_argument("--out", default="zahra_model/data/train.jsonl",
                        help="Output JSONL dataset path")
    parser.add_argument("--no-learn", action="store_true",
                        help="Do not deep-learn skills from ingested material")
    args = parser.parse_args()

    brain = ZahraAgent()
    print("🧠 Building training dataset from RAG corpus...")

    if args.no_learn:
        # Ingest without learning (we still build doc/skill pairs from existing corpus)
        total = 0
        for d in args.dirs:
            d = os.path.abspath(d)
            if os.path.isdir(d):
                res = brain.ingest_local_files(d, recursive=True, learn=False)
                total += res["total_chunks"]
                print(f"  - {d}: {res['total_chunks']} chunk(s)")
        n = build(brain, [], args.out)
    else:
        n = build(brain, args.dirs, args.out)

    print("\n📈 Next: feed data/train.jsonl to your fine-tuning tool "
          "(Ollama create --from, LoRA, etc.).")
    return 0


if __name__ == "__main__":
    sys.exit(main())