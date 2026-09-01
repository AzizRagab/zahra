"""ZAHRA continuous learning loop.

Every run:
  1. Rebuilds the training dataset from the brain DB + conversation log.
  2. If enough new samples accumulated, launches a LoRA fine-tune
     (CPU by default) and rebuilds the 'zahra' Ollama model.

Schedule (Windows):
  schtasks /create /tn "ZAHRA-Learn" /tr "python ai_agent\\zahra_learn.py" /sc daily /st 03:00
Or run manually: python -m ai_agent.zahra_learn

Configure via env:
  ZAHRA_LEARN_MIN_SAMPLES  (default 600)   min dataset size to start a run
  ZAHRA_LEARN_AUTO         (default 0)     set 1 to auto-train without asking
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ai_agent.zahra_dataset import main as build_dataset  # noqa: E402

DATASET = ROOT / "zahra_model" / "training" / "zahra_train.jsonl"
MIN_SAMPLES = int(os.environ.get("ZAHRA_LEARN_MIN_SAMPLES", "600"))
AUTO = os.environ.get("ZAHRA_LEARN_AUTO", "0") == "1"


def main() -> int:
    print("[ZAHRA-LEARN] step 1: rebuild dataset from brain + conversations")
    build_dataset()

    lines = DATASET.read_text(encoding="utf-8").count("\n") if DATASET.exists() else 0
    print(f"[ZAHRA-LEARN] dataset has {lines} samples (min {MIN_SAMPLES})")
    if lines < MIN_SAMPLES:
        print("[ZAHRA-LEARN] not enough new knowledge yet; skipping fine-tune.")
        return 0

    if not AUTO:
        answer = input(f"[ZAHRA-LEARN] fine-tune now with {lines} samples? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("[ZAHRA-LEARN] skipped.")
            return 0

    from ai_agent.zahra_finetune import main as train_main
    print("[ZAHRA-LEARN] step 2: fine-tuning ZAHRA weights (LoRA)...")
    rc = train_main()
    if rc != 0:
        print("[ZAHRA-LEARN] fine-tune failed.")
        return rc

    print("[ZAHRA-LEARN] step 3: rebuild ollama 'zahra-finetuned'")
    import subprocess
    subprocess.run(["ollama", "create", "zahra-finetuned",
                    "-f", str(ROOT / "zahra_model" / "Modelfile.finetuned")],
                   check=False)
    print("[ZAHRA-LEARN] done. ZAHRA has learned new knowledge. Use "
          "`python zahra_agent.py chat` — it now answers from the new weights.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
