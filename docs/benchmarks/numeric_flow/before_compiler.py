#!/usr/bin/env python3
"""Reproduce the measured pre-numeric images for the published benchmark inputs.

Set MINILANG_PY_REPO to the matching final Python compiler checkout. This is a
benchmark ablation, not a replacement for the historical compiler on all inputs.
The captured-parameter and NaN constant-fold parity fixes remain present.
"""
import os
from pathlib import Path
import sys

repo = Path(os.environ["MINILANG_PY_REPO"]).resolve()
sys.path.insert(0, str(repo))
from mlc.codegen import Codegen
from mlc.compiler import main

legacy_type_query = Codegen._opt_expr_known_type
Codegen._opt_expr_known_type = lambda self, expr, extended=False: legacy_type_query(self, expr, False)
Codegen._opt_emit_float_parent_without_child_box = lambda self, expr: False
raise SystemExit(main([str(repo / "mlc_win64.py"), *sys.argv[1:], "--no-object-pipeline"]))
