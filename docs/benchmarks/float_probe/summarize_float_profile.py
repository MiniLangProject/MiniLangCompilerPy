#!/usr/bin/env python3
"""Recompute category, period and leaf-runtime summaries from sampled IP records."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--images", type=Path, required=True)
    args = parser.parse_args()
    rows = json.loads((args.profiles / "profiles.json").read_text())
    summaries = []
    for case in sorted({row["case"] for row in rows}):
        selected = [row for row in rows if row["case"] == case]
        counts = Counter()
        for row in selected:
            assert row["correct"] and row["lost_samples"] == 0
            assert sum(row["category_counts"].values()) == row["samples"]
            counts.update(row["category_counts"])
        total = sum(counts.values())
        mapping = json.loads((args.profiles / (case + ".ranges.json")).read_text())
        labels = sorted((int(value) + mapping["image_base"], name) for name, value in
                        re.findall(r"(?m)^\[label\] ([^ ]+) (\d+)\s*$",
                                   (args.images / case / "python.labels").read_text())
                        if name.startswith("fn_"))
        functions = Counter()
        for row in selected:
            for sample in row["samples_by_ip"]:
                if sample["category"] == "executable_other":
                    name = next((name for offset, name in reversed(labels)
                                 if offset <= sample["ip"]), "<before-first-function>")
                    functions[name] += sample["samples"]
        groups = []
        for period in sorted({row["period_ns"] for row in selected}):
            subcounts = Counter()
            for row in selected:
                if row["period_ns"] == period:
                    subcounts.update(row["category_counts"])
            subtotal = sum(subcounts.values())
            groups.append(dict(
                period_ns=period, samples=subtotal,
                raw_normalizer_share=(subcounts["raw_normalizer_int_guard"] +
                                      subcounts["raw_normalizer_f32_probe"]) / subtotal,
                ordinary_path_share=sum(value for key, value in subcounts.items()
                                        if key.startswith("ordinary")) / subtotal,
                integer_rejoin_share=subcounts["integer_rejoin"] / subtotal,
                executable_other_share=subcounts["executable_other"] / subtotal))
        repetitions = {row["reps"] for row in selected}
        assert len(repetitions) == 1
        summaries.append(dict(
            case=case, processes=len(selected), calls_per_process=repetitions.pop(),
            samples=total, lost_samples=sum(row["lost_samples"] for row in selected),
            category_counts=dict(counts),
            sample_shares={key: value / total for key, value in counts.items()},
            raw_normalizer_share=(counts["raw_normalizer_int_guard"] +
                                  counts["raw_normalizer_f32_probe"]) / total,
            period_groups=groups, runtime_function_samples=dict(functions.most_common())))
    (args.profiles / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
