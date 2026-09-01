"""ZAHRA training-data generator.

Builds a JSONL instruction dataset from the project's real knowledge so
the open-source base model can be fine-tuned into the ZAHRA model:

  1. ATTACK_LIBRARY entries from zahra_agent.py  -> Q/A pairs (technique, tool, command)
  2. Learned skills from zahra_brain.db          -> Q/A pairs (what command to run)
  3. Past experiences from zahra_brain.db        -> Q/A pairs (what worked/failed)
  4. RAG corpus documents (zahra_data/rag)       -> Q/A pairs (knowledge chunks)
  5. Chat conversation log (zahra_model/data/conversations.jsonl) -> ongoing turns

Usage:
    python -m ai_agent.zahra_dataset            # build default dataset
    python -m ai_agent.zahra_dataset --max 800  # cap sample count
    python -m ai_agent.zahra_dataset --out data.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zahra_agent import ATTACK_LIBRARY  # noqa: E402

DB_PATH = ROOT / "zahra_brain.db"
RAG_DIR = ROOT / "zahra_data" / "rag"
CONV_PATH = ROOT / "zahra_model" / "data" / "conversations.jsonl"
DEFAULT_OUT = ROOT / "zahra_model" / "training" / "zahra_train.jsonl"

SYSTEM_PROMPT = (
    "You are ZAHRA, a personal autonomous self-learning red-team assistant. "
    "Answer technically and directly in the user's language. "
    "Give the exact tool, command, and technique to use."
)


def qa(system: str, user: str, answer: str) -> dict[str, str]:
    """One instruction sample in Qwen chat format."""
    return {"system": system, "user": user, "answer": answer}


def build_attack_samples() -> list[dict[str, str]]:
    """Turn every ATTACK_LIBRARY entry into a Q/A sample."""
    out: list[dict[str, str]] = []
    for service, entries in ATTACK_LIBRARY.items():
        for e in entries:
            question = (
                f"How do I {e['name'].replace('-', ' ')} for {service}?"
            )
            answer = (
                f"Technique: {e['name']} ({e['category']}). "
                f"Description: {e['description']} "
                f"Command: {e['command']}"
            )
            out.append(qa(SYSTEM_PROMPT, question, answer))
    return out


def build_skill_samples() -> list[dict[str, str]]:
    """Learned skills from the brain DB -> Q/A pairs."""
    out: list[dict[str, str]] = []
    if not DB_PATH.exists():
        return out
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT name, command_template, category, description FROM skills "
            "ORDER BY timestamp DESC LIMIT 250"
        ).fetchall()
        for r in rows:
            out.append(qa(
                SYSTEM_PROMPT,
                f"What command should I run to {r['name'].replace('_', ' ')}?",
                f"Tool: {r['name']} ({r['category']}). "
                f"Command: {r['command_template']}. {r['description'] or ''}",
            ))
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return out


def build_experience_samples() -> list[dict[str, str]]:
    """Past experiences -> Q/A pairs about what worked/failed."""
    out: list[dict[str, str]] = []
    if not DB_PATH.exists():
        return out
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT command, success FROM experiences "
            "ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()
        for r in rows:
            verdict = "worked and is proven" if r["success"] else "failed and should be avoided"
            out.append(qa(
                SYSTEM_PROMPT,
                f"Is the command '{r['command']}' a good approach?",
                f"This command {verdict}: {r['command']}",
            ))
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return out


def build_rag_samples(max_samples: int = 120) -> list[dict[str, str]]:
    """RAG documents table -> grounded knowledge Q/A samples."""
    out: list[dict[str, str]] = []
    if not DB_PATH.exists():
        return out
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT title, content FROM documents WHERE length(content) > 80 "
            "ORDER BY timestamp DESC LIMIT ?", (max_samples,)
        ).fetchall()
        for r in rows:
            text = re.sub(r"\s+", " ", r["content"])[:1200]
            title = (r["title"] or "document").replace("_", " ").replace("-", " ")[:80]
            out.append(qa(
                SYSTEM_PROMPT,
                f"Tell me about: {title} (from ZAHRA's local knowledge).",
                text,
            ))
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return out


def build_conversation_samples(max_recent: int = 300) -> list[dict[str, str]]:
    """Recent chat exchanges -> continuing-learning samples."""
    out: list[dict[str, str]] = []
    if not CONV_PATH.exists():
        return out
    records: list[dict] = []
    with open(CONV_PATH, encoding="utf-8") as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for r in records[-max_recent:]:
        user = r.get("user", "")
        answer = r.get("assistant", "")
        if user and answer and len(answer) > 20:
            out.append(qa(SYSTEM_PROMPT, user, answer))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Build ZAHRA training dataset")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--max", type=int, default=0,
                        help="Cap total samples (0 = no cap)")
    args = parser.parse_args()

    samples: list[dict[str, str]] = []
    samples += build_attack_samples()
    samples += build_skill_samples()
    samples += build_experience_samples()
    samples += build_rag_samples()
    samples += build_conversation_samples()

    if args.max:
        samples = samples[: args.max]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"ZAHRA dataset: {len(samples)} samples -> {out_path}")
    print(f"  - attack library: {len(build_attack_samples())}")
    print(f"  - skills: {len(build_skill_samples())}")
    print(f"  - experiences: {len(build_experience_samples())}")
    print(f"  - RAG docs: {len(build_rag_samples())}")
    print(f"  - conversations: {len(build_conversation_samples())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
