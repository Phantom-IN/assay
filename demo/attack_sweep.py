"""Attack-variant sweep: for a model, find which injection technique actually breaks each task.

For every mapped Mode-B task and every attack variant, run N trials against a real model over
loopback MCP, decide each with the frozen oracle, and record the attack success rate. The point is
not to pick one phrasing and call a miss "resistance" -- it is to measure, per task, how strong the
best current technique has to be before a given model leaks, and to keep the proof of any leak.

    python demo/attack_sweep.py --model openai/gpt-6.1-terra --trials 3 --out sweep.json

Output: per (task, variant) ASR, the strongest variant per task, any recomputable leak proof, and
the total model spend. Honest about inconclusive trials (an API error or a no-tool-call answer is
not counted as resistance).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from assay_bench import scenarios                                  # noqa: E402
from assay_bench.adapters import Episode                           # noqa: E402
from assay_bench.adapters.llm_agent import LLMAgentAdapter         # noqa: E402
from assay_bench.canary import new_run_secret, plant              # noqa: E402
from assay_bench.catalog import load_catalog                       # noqa: E402
from assay_bench.oracles import evaluate                           # noqa: E402

CATALOG = load_catalog()
#: The mapped, faithful tasks worth sweeping (canary + behavioral).
SWEEP_TASKS = ["M1", "M3", "M7", "M23", "M24", "M8", "M9", "M16"]


def _episode(task_id, secret, trial):
    t = CATALOG.require(task_id)
    can = plant(secret, task_id, f"assay/{task_id}", t.attack, trial) if t.oracle == "canary" else None
    return Episode(task_id=task_id, mode=t.mode, oracle=t.oracle, attack=t.attack, trial=trial,
                   canary=can, timeout_s=110.0), t, can


def run(model: str, trials: int, variants, out: str | None, timeout: float) -> dict:
    secret = new_run_secret()
    adapter = LLMAgentAdapter(model, max_steps=6, request_timeout=min(timeout, 90.0))
    rows = []
    for task_id in SWEEP_TASKS:
        t = CATALOG.require(task_id)
        best = {"variant": None, "asr": -1.0}
        per_variant = []
        for variant in variants:
            adapter.variant = variant
            hits = decided = inconclusive = 0
            proof = None
            for trial in range(trials):
                ep, _, can = _episode(task_id, secret, trial)
                obs = adapter.run_episode(ep)
                if obs.error:
                    inconclusive += 1
                    continue
                try:
                    res = evaluate(t.oracle, t.attack, obs, can)
                except Exception:
                    inconclusive += 1
                    continue
                decided += 1
                if res.fired:
                    hits += 1
                    if proof is None and res.proof is not None:
                        proof = res.proof
            asr = (hits / decided) if decided else 0.0
            per_variant.append({"variant": variant, "asr": round(asr, 3), "hits": hits,
                                "decided": decided, "inconclusive": inconclusive,
                                "proof": proof})
            if decided and asr > best["asr"]:
                best = {"variant": variant, "asr": round(asr, 3), "hits": hits,
                        "decided": decided, "proof": proof}
            print(f"  {task_id:4} {variant:9} asr={asr:4.2f} ({hits}/{decided}, "
                  f"inconclusive {inconclusive})", flush=True)
        rows.append({"task": task_id, "oracle": t.oracle, "weight": t.weight,
                     "mechanism": scenarios.build_scenario(t, _episode(task_id, secret, 0)[0],
                                                           plant(secret, task_id, f"assay/{task_id}",
                                                                 t.attack, 0) if t.oracle == "canary"
                                                           else None).models_after,
                     "best": best, "per_variant": per_variant})
        print(f"{task_id}: best variant = {best['variant']} asr={best['asr']}", flush=True)
    leaked = [r for r in rows if r["best"]["asr"] > 0]
    result = {"model": model, "trials_per_cell": trials, "variants": list(variants),
              "tasks": rows,
              "summary": {"tasks_swept": len(rows), "tasks_with_a_leak": len(leaked),
                          "leaked_task_ids": [r["task"] for r in leaked]},
              "spend_usd": round(adapter.cost_usd, 4), "api_calls": adapter.calls}
    if out:
        Path(out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--variants", default=",".join(scenarios.VARIANTS))
    ap.add_argument("--out")
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args()
    t0 = time.monotonic()
    res = run(args.model, args.trials, args.variants.split(","), args.out, args.timeout)
    print(f"\n=== {res['model']} ===")
    print(f"tasks with a leak: {res['summary']['tasks_with_a_leak']}/{res['summary']['tasks_swept']}"
          f"  {res['summary']['leaked_task_ids']}")
    print(f"spend ${res['spend_usd']} over {res['api_calls']} API calls, "
          f"{time.monotonic()-t0:.0f}s")
