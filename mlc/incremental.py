"""Conservative persistent native-function cache.

The frontend and global planning still run on every changed build. A fragment
is reusable only with the same declarations, inline bodies, module contents,
and incoming native layout. Section dictionaries are journalled: replay must
restore constant interning as well as bytes and relocations. Cache files are
data, never pickle/code, and are atomically replaced after a successful emit.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile

SCHEMA = "MiniLang-function-cache-py-1"
MAX_ENTRY = 64 * 1024 * 1024


def _view(value, *, interface=False):
    """Produce a deterministic, explicitly typed tree without object addresses."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return ["float", struct.pack("<d", value).hex()]
    if isinstance(value, (bytes, bytearray)):
        return ["bytes", base64.b64encode(value).decode("ascii")]
    if isinstance(value, (list, tuple)):
        return ["tuple" if isinstance(value, tuple) else "list",
                [_view(x, interface=interface) for x in value]]
    if isinstance(value, (set, frozenset)):
        return ["set", sorted((_view(x, interface=interface) for x in value), key=repr)]
    if isinstance(value, dict):
        # Insertion order is observable in section builders and binding maps.
        return ["dict", [[_view(k), _view(v, interface=interface)] for k, v in value.items()]]
    if dataclasses.is_dataclass(value):
        name = type(value).__name__
        fields = []
        for f in dataclasses.fields(value):
            if f.name.startswith("_ml_") or f.name in ("_pos", "_line", "_col", "decl_node"):
                continue
            if interface and name == "FunctionDef" and f.name == "body":
                continue
            fields.append([f.name, _view(getattr(value, f.name), interface=interface)])
        return [name, fields, getattr(value, "_filename", None)]
    raise TypeError(f"unsupported incremental value: {type(value).__name__}")


def _unview(value):
    """Decode only primitive cache data; no class names are instantiated."""
    if not isinstance(value, list):
        if value is None or isinstance(value, (bool, int, str)):
            return value
        raise ValueError("invalid primitive")
    if len(value) != 2:
        raise ValueError("invalid record")
    tag, data = value
    if tag == "bytes":
        return base64.b64decode(data, validate=True)
    if tag == "float":
        raw = bytes.fromhex(data)
        if len(raw) != 8:
            raise ValueError("invalid float record")
        return struct.unpack("<d", raw)[0]
    if tag == "list":
        return [_unview(x) for x in data]
    if tag == "tuple":
        return tuple(_unview(x) for x in data)
    if tag == "set":
        return set(_unview(x) for x in data)
    if tag == "dict":
        return {_unview(k): _unview(v) for k, v in data}
    raise ValueError("unknown cache record")


def _encode(value):
    return json.dumps(_view(value), ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


class _JournalDict(dict):
    """Record only writes made during one function, including alias updates."""

    def __init__(self, original):
        super().__init__(original)
        self.changes = {}

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.changes[key] = value

    def update(self, *args, **kwargs):
        for key, value in dict(*args, **kwargs).items():
            self[key] = value


class FunctionCache:
    """Memoize function lowering while preserving the canonical native stream."""

    _state_fields = ("_label_id", "_binding_id", "_inline_emitted_bytes",
                     "used_helpers", "ext_widebuf_labels")
    _section_dicts = (("data", "labels"), ("rdata", "labels"), ("bss", "labels"),
                      ("rdata", "_pool_raw"), ("rdata", "_pool_obj_string"),
                      ("rdata", "_pool_obj_float"))

    def __init__(self, directory, options, *, source_ids=None, frontend_path=None):
        self.directory = Path(directory) / "functions-py-v1"
        self.options = options
        compiler = hashlib.sha256(SCHEMA.encode())
        for path in sorted(Path(__file__).parent.rglob("*.py")):
            compiler.update(path.relative_to(Path(__file__).parent).as_posix().encode())
            compiler.update(path.read_bytes())
        # The loader also supports a parser beside the input file. Its code
        # is part of the compiler even when it lives outside the mlc package.
        if frontend_path:
            path = Path(frontend_path).resolve()
            compiler.update(b"\0selected-frontend\0" + str(path).encode())
            compiler.update(path.read_bytes())
        self.compiler_id = compiler.hexdigest()
        self.interface = None
        self.context = None
        self.sections = hashlib.sha256()
        self.files = dict(source_ids or {})
        self.hits = self.misses = self.invalid = 0

    def prepare(self, program):
        """Hash global declarations; non-inline bodies have per-module keys."""
        try:
            self.interface = _digest(_view(program, interface=True))
        except (TypeError, ValueError, RecursionError):
            self.interface = None  # Unknown future AST nodes fail closed.

    def _initialize(self, cg):
        functions = dict(cg.user_functions)
        functions.update(getattr(cg, "nested_user_functions", {}))
        contracts = []
        for name, fn in sorted(functions.items()):
            # This body-derived fact affects allocation in callers even when
            # the callee is not inline. Force the proof before making a key.
            safe = cg._variadic_param_stack_safe(fn)
            contracts.append((name, safe, _view(fn, interface=True)))
        self.context = _digest((self.compiler_id, self.options, self.interface,
            contracts, _view(getattr(cg, "inline_functions", {})),
            [(name, self.files[getattr(fn, "_filename", cg.filename)])
             for name, fn in sorted(getattr(cg, "inline_functions", {}).items())],
            getattr(cg, "_dead_functions", set()), cg.native_threads_possible,
            getattr(cg, "mutable_user_functions", set()),
            getattr(cg, "_max_inline_call_args_global", 0),
            _view(cg._scope_stack[0])))
        initial = []
        for owner, field in self._section_dicts:
            obj = getattr(cg, owner)
            original = getattr(obj, field)
            initial.append((owner, field, original))
            setattr(obj, field, _JournalDict(original))
        self.sections.update(_encode((initial, cg.data.data, cg.rdata.data,
                                      cg.data.patches, cg.rdata.patches, cg.bss.size)))

    def _state(self, cg):
        # Round-trip copies mutable budget/helper containers without retaining
        # any AST, scope arena, or executable Python object in the cache.
        return {name: _unview(_view(getattr(cg, name))) for name in self._state_fields}

    def emit(self, cg, fn, emit):
        if self.interface is None or cg.asm._trace_enabled:
            return emit(fn)
        try:
            if self.context is None:
                self._initialize(cg)
            filename = str(getattr(fn, "_filename", cg.filename))
            code_name = getattr(fn, "_ml_codegen_name", fn.name)
            state_before = self._state(cg)
            key = _digest((self.context, code_name, filename, self.files[filename],
                           state_before, cg.asm.pos, self.sections.hexdigest()))
            path = self.directory / (_digest((filename, code_name, cg.target)) + ".mfc")
        except (OSError, TypeError, ValueError, AttributeError, KeyError, RecursionError):
            # Unsupported semantic state must never turn into a guessed hit.
            self.interface = None
            return emit(fn)

        record = None
        try:
            if path.stat().st_size <= MAX_ENTRY:
                raw = path.read_bytes()
                header, payload = raw.split(b"\n", 1)
                if header.decode("ascii") != hashlib.sha256(payload).hexdigest():
                    raise ValueError("checksum mismatch")
                candidate = _unview(json.loads(payload))
                if not isinstance(candidate, list) or len(candidate) != 3:
                    raise ValueError("invalid cache envelope")
                if candidate[0] == SCHEMA and candidate[1] == key:
                    if not self._valid_record(candidate[2], cg.asm.pos):
                        raise ValueError("invalid fragment shape")
                    record = candidate[2]
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, IndexError, KeyError, RecursionError):
            self.invalid += 1

        for owner, field in self._section_dicts:
            getattr(getattr(cg, owner), field).changes.clear()
        if record is not None:
            self._replay(cg, record)
            self.hits += 1
        else:
            before = (cg.asm.pos, len(cg.asm._label_defs), len(cg.asm.patches),
                      len(cg.data.data), len(cg.rdata.data),
                      len(cg.data.patches), len(cg.rdata.patches))
            emit(fn)  # Diagnostics/exceptions never publish a cache entry.
            record = self._capture(cg, before)
            self.misses += 1
            payload = _encode([SCHEMA, key, record])
            if len(payload) <= MAX_ENTRY:
                temporary = None
                try:
                    self.directory.mkdir(parents=True, exist_ok=True)
                    with tempfile.NamedTemporaryFile(dir=self.directory, delete=False) as handle:
                        temporary = Path(handle.name)
                        handle.write(hashlib.sha256(payload).hexdigest().encode() + b"\n" + payload)
                    os.replace(temporary, path)
                except OSError:
                    pass  # A cache is optional, including on read-only disks.
                finally:
                    if temporary is not None:
                        try:
                            temporary.unlink(missing_ok=True)
                        except OSError:
                            pass
        # Code bytes are deliberately excluded: changing an integer immediate
        # need not invalidate later fragments if layout and pools still match.
        self.sections.update(_encode(record[4:10]))

    def _capture(self, cg, before):
        pos, labels, patches, db, rb, dp, rp = before
        changes = [(owner, field, dict(getattr(getattr(cg, owner), field).changes))
                   for owner, field in self._section_dicts]
        return [bytes(cg.asm.buf[pos:]), cg.asm._label_defs[labels:], cg.asm.patches[patches:],
                self._state(cg), bytes(cg.data.data[db:]), bytes(cg.rdata.data[rb:]),
                cg.data.patches[dp:], cg.rdata.patches[rp:], changes, cg.bss.size,
                [cg.asm._peephole_last_push, cg.asm._peephole_last_jump,
                 cg.asm._peephole_prev_jump, cg.asm._forward_branch]]

    @classmethod
    def _valid_record(cls, rec, start):
        """Reject malformed data before mutating any live compiler state."""
        if not isinstance(rec, list) or len(rec) != 11:
            return False
        if not all(isinstance(rec[i], bytes) for i in (0, 4, 5)):
            return False
        if not isinstance(rec[3], dict) or set(rec[3]) != set(cls._state_fields):
            return False
        if not all(isinstance(rec[i], list) for i in (1, 2, 6, 7, 8, 10)):
            return False
        if len(rec[10]) != 4 or not isinstance(rec[9], int) or rec[9] < 0:
            return False
        if not isinstance(rec[3]["_label_id"], int) or not isinstance(rec[3]["_binding_id"], int):
            return False
        if not isinstance(rec[3]["_inline_emitted_bytes"], dict) or not isinstance(rec[3]["used_helpers"], set):
            return False
        for item in rec[1]:
            if (not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], int)
                    or not start <= item[0] <= start + len(rec[0]) or not isinstance(item[1], str)):
                return False
        for item in rec[2] + rec[6] + rec[7]:
            if (not isinstance(item, tuple) or len(item) != 3 or not isinstance(item[0], int)
                    or not isinstance(item[1], str) or item[2] not in ("rel32", "rip32", "abs64")):
                return False
        if len(rec[8]) != len(cls._section_dicts):
            return False
        for expected, item in zip(cls._section_dicts, rec[8]):
            if (not isinstance(item, tuple) or len(item) != 3 or item[:2] != expected
                    or not isinstance(item[2], dict)):
                return False
        return True

    def _replay(self, cg, rec):
        cg.asm.buf.extend(rec[0])
        cg.asm._label_defs.extend(rec[1])
        for pos, name in rec[1]:
            cg.asm.labels[name] = pos
        cg.asm.patches.extend(rec[2])
        for name, value in rec[3].items():
            setattr(cg, name, value)
        cg.data.data.extend(rec[4])
        cg.rdata.data.extend(rec[5])
        cg.data.patches.extend(rec[6])
        cg.rdata.patches.extend(rec[7])
        for owner, field, changes in rec[8]:
            getattr(getattr(cg, owner), field).update(changes)
        cg.bss.size = rec[9]
        (cg.asm._peephole_last_push, cg.asm._peephole_last_jump,
         cg.asm._peephole_prev_jump, cg.asm._forward_branch) = rec[10]

    def report(self):
        print(f"[incremental] reused={self.hits} compiled={self.misses} invalid={self.invalid}")
