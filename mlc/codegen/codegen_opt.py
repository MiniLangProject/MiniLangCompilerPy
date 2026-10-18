"""Bounded, fail-closed local lifetime and escape analysis.

Unknown syntax disables these optional analyses, never ordinary code generation.
Intervals cover entire top-level statements, including every loop iteration.
"""

import re
from pathlib import Path


def unused_functions(cg):
    """Prove absence of all source references, conservatively including comments.

    A name must occur exactly once in the entire loaded source set, in a
    function declaration. Methods/generated names and profiling are excluded.
    This deliberately does not attempt the unsafe inline-fallback pruning.
    """
    if getattr(cg, 'call_profile', False):
        return set()
    counts, declarations = {}, {}
    files = set(cg.file_prefix_map)
    files.add(cg.filename)
    files.update(getattr(fn, '_filename', '') for fn in cg.user_functions.values())
    try:
        for filename in sorted({str(Path(f).resolve()) for f in files if f}):
            source = Path(filename).read_text(encoding='utf-8-sig')
            pending = False
            for match in re.finditer(r'[A-Za-z0-9_]+', source):
                name = match[0]
                counts[name] = min(2, counts.get(name, 0) + 1)
                if pending and name not in ('inline', 'synchronized', 'static'):
                    declarations[name] = min(2, declarations.get(name, 0) + 1)
                    pending = False
                if name == 'function':
                    pending = True
    except (OSError, UnicodeError):
        return set()
    result = set()
    for qname in cg.user_functions:
        parent, _, name = qname.rpartition('.')
        if not name:
            name = qname
        if (name == 'main' or '__' in qname or parent in cg.struct_fields
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name)):
            continue
        if counts.get(name) == 1 and declarations.get(name) == 1:
            result.add(qname)
    return result

_FIELDS = {
    'Num': (), 'Str': (), 'Bool': (), 'VoidLit': (), 'Var': (),
    'Break': (), 'Continue': (), 'Unary': ('right',),
    'Bin': ('left', 'right'), 'Coalesce': ('left', 'right'),
    'IsType': ('expr',), 'TypeGuard': ('expr',),
    'Call': ('callee', 'args'), 'Member': ('target',),
    'Index': ('target', 'index'), 'ArrayLit': ('items',),
    'Assign': ('expr',), 'ConstDecl': ('expr',), 'Print': ('expr',),
    'ExprStmt': ('expr',), 'Return': ('expr',),
    'SetMember': ('obj', 'expr'), 'SetIndex': ('target', 'index', 'expr'),
    'If': ('cond', 'then_body', 'elifs', 'else_body'),
    'While': ('cond', 'body'), 'DoWhile': ('body', 'cond'),
    'For': ('start', 'end', 'body'), 'ForEach': ('iterable', 'body'),
}


def accesses(body):
    """Return (node,parent,statement) records, or None for unsupported syntax."""
    result = []
    work = [(node, None, i) for i, node in enumerate(body)]
    while work:
        node, parent, index = work.pop()
        if node is None:
            continue
        if isinstance(node, (list, tuple)):
            work.extend((item, parent, index) for item in node)
            continue
        fields = _FIELDS.get(type(node).__name__)
        if fields is None or len(result) >= 4096:
            return None
        result.append((node, parent, index))
        work.extend((getattr(node, key, None), node, index) for key in fields)
    return result


def intervals(body):
    """Conservative lifetimes for noncaptured primitive register mirrors."""
    records = accesses(body)
    if records is None:
        return None
    result = {}
    for node, _, index in records:
        kind = type(node).__name__
        name = (getattr(node, 'var', '') if kind in ('For', 'ForEach') else
                getattr(node, 'name', '') if kind in ('Var', 'Assign', 'ConstDecl') else '')
        if name:
            old = result.setdefault(name, [index, index, 0, 0, False])
            old[0] = min(old[0], index)
            old[1] = max(old[1], index)
            old[4] |= kind in ('For', 'ForEach')
            # Additional mirrors must amortize one GPR-to-XMM transfer per
            # store. Cheap single-read accumulators stay in L1 stack slots.
            if type(body[index]).__name__ in ('For', 'ForEach', 'While', 'DoWhile'):
                old[2 if kind == 'Var' else 3] += 1
    return result


def scalar_candidates(cg, fn):
    """Plan rooted scalar slots for unaliased, untyped local struct fields.

    Only an unconditional top-level constructor assignment may establish the
    object. Every use must be a known field read/write after that assignment.
    Calls receive fields, never the object; reflection/identity/closures escape.
    """
    if not any(type(st).__name__ == 'Assign' and type(st.expr).__name__ == 'Call' for st in fn.body):
        return []
    records = accesses(fn.body)
    if records is None:
        return []
    plans = []
    bindings = list(getattr(cg, '_function_locals', []))
    for index, stmt in enumerate(fn.body):
        if type(stmt).__name__ != 'Assign' or getattr(stmt, 'declared_type', None):
            continue
        call = stmt.expr
        if type(call).__name__ != 'Call' or type(call.callee).__name__ != 'Var':
            continue
        name = stmt.name
        local = [b for b in bindings if b.name == name]
        if len(local) != 1 or local[0].boxed or local[0].kind != 'local':
            continue
        raw = call.callee.name
        if any(b.name == raw for b in bindings) or raw in fn.params:
            continue
        qname = cg._qualify_identifier(raw, call, kind='struct')
        fields = cg.struct_fields.get(qname, [])
        if qname == 'error' or not 1 <= len(fields) <= 8 or len(call.args) != len(fields):
            continue
        if any(n not in (None, '') for n in (getattr(call, 'arg_names', []) or [])):
            continue
        contracts = getattr(cg, 'struct_field_types', {}).get(qname, [])
        if any(c[0] not in (None, '') for c in contracts):
            continue
        valid = True
        for node, parent, at in records:
            kind = type(node).__name__
            if kind in ('Assign', 'ConstDecl') and node.name == name and node is not stmt:
                valid = False
            if kind in ('For', 'ForEach') and node.var == name:
                valid = False
            if kind == 'Var' and node.name == name:
                pk = type(parent).__name__
                field = (parent.name if pk == 'Member' and parent.target is node else
                         parent.field if pk == 'SetMember' and parent.obj is node else None)
                if field not in fields or at <= index:
                    valid = False
        if valid:
            plans.append([stmt, local[0], list(fields), []])
    return plans


def scalar_slot(cg, target, field):
    """Resolve only the original binding, never an inline parameter shadow."""
    if type(target).__name__ != 'Var' or getattr(cg, '_inline_call_stack', []):
        return None
    binding = cg.resolve_binding(target.name)
    for _, original, fields, offsets in getattr(cg, '_scalar_structs', []):
        if binding is original and field in fields:
            return offsets[fields.index(field)]
    return None
