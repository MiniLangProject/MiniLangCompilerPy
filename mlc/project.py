"""Project-manifest loading and conservative incremental build caching."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
import sys
from typing import Any, Iterable, List, Optional, Sequence, Tuple

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.11+ is supported.
    tomllib = None  # type: ignore[assignment]


class ProjectError(ValueError):
    pass


@dataclass(frozen=True)
class ProjectBuild:
    manifest: Path
    cache_dir: Path
    incremental: bool
    expanded_args: Tuple[str, ...]

    @property
    def state_path(self) -> Path:
        return self.cache_dir / "build.state"

    @property
    def artifact_path(self) -> Path:
        return self.cache_dir / "build.exe"


_KEYS = {
    "entry", "input", "output", "include", "import_paths", "subsystem",
    "object_pipeline", "incremental", "cache_dir", "compiler_args",
}


def _path(base: Path, value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ProjectError(f"project field '{field}' must be a non-empty string")
    p = Path(value)
    if not p.is_absolute():
        p = base / p
    return p.resolve()


def _string_list(value: Any, field: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ProjectError(f"project field '{field}' must be an array of strings")
    return list(value)


def expand_project_args(argv: Sequence[str]) -> tuple[List[str], Optional[ProjectBuild]]:
    """Expand ``--project FILE`` into the ordinary compiler command line."""
    raw = list(argv)
    if len(raw) < 2 or raw[1] != "--project":
        return raw, None
    if len(raw) < 3 or not raw[2]:
        raise ProjectError("--project expects a TOML manifest path")
    if tomllib is None:
        raise ProjectError("project manifests require Python 3.11 or newer")

    manifest = Path(raw[2]).resolve()
    if not manifest.is_file():
        raise ProjectError(f"project manifest not found: {manifest}")
    try:
        parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ProjectError(f"invalid project manifest: {exc}") from exc
    cfg = parsed.get("project", parsed)
    if not isinstance(cfg, dict):
        raise ProjectError("project manifest must contain a [project] table")
    unknown = sorted(set(cfg) - _KEYS)
    if unknown:
        raise ProjectError("unknown project field(s): " + ", ".join(unknown))

    base = manifest.parent
    entry = _path(base, cfg.get("entry", cfg.get("input")), "entry")
    output = _path(base, cfg.get("output"), "output")
    includes = _string_list(cfg.get("include", cfg.get("import_paths", [])), "include")
    compiler_args = _string_list(cfg.get("compiler_args", []), "compiler_args")
    incremental = cfg.get("incremental", True)
    object_pipeline = cfg.get("object_pipeline", False)
    if not isinstance(incremental, bool):
        raise ProjectError("project field 'incremental' must be a boolean")
    if not isinstance(object_pipeline, bool):
        raise ProjectError("project field 'object_pipeline' must be a boolean")

    expanded = [raw[0], str(entry), str(output)]
    for item in includes:
        expanded.extend(["-I", str(_path(base, item, "include"))])
    subsystem = cfg.get("subsystem")
    if subsystem is not None:
        if not isinstance(subsystem, str):
            raise ProjectError("project field 'subsystem' must be a string")
        expanded.extend(["--subsystem", subsystem])
    if object_pipeline:
        expanded.append("--object-pipeline")
    expanded.extend(compiler_args)

    extra = raw[3:]
    if "--no-incremental" in extra:
        incremental = False
        extra = [x for x in extra if x != "--no-incremental"]
    expanded.extend(extra)

    cache_dir = _path(base, cfg.get("cache_dir", ".minilang-cache"), "cache_dir")
    return expanded, ProjectBuild(manifest, cache_dir, incremental, tuple(expanded[1:]))


def _iter_ml_files(roots: Iterable[Path], excluded: Path) -> Iterable[Path]:
    seen: set[str] = set()
    excluded_key = os.path.normcase(str(excluded.resolve()))
    for root in roots:
        if root.is_file():
            candidates: Iterable[Path] = [root]
        elif root.is_dir():
            candidates = root.rglob("*.ml")
        else:
            continue
        for path in candidates:
            resolved = path.resolve()
            key = os.path.normcase(str(resolved))
            if key.startswith(excluded_key + os.sep) or key in seen:
                continue
            seen.add(key)
            yield resolved


def fingerprint(project: ProjectBuild, input_path: str, include_dirs: Sequence[str]) -> str:
    h = hashlib.sha256()
    h.update(b"MiniLang-project-cache-v1\0")
    h.update("\0".join(project.expanded_args).encode("utf-8"))
    h.update(project.manifest.read_bytes())

    roots = [Path(input_path).resolve().parent, Path(input_path)]
    roots.extend(Path(x) for x in include_dirs)
    files = sorted(_iter_ml_files(roots, project.cache_dir), key=lambda p: os.path.normcase(str(p)))
    for path in files:
        h.update(b"\0source\0")
        h.update(os.path.normcase(str(path)).encode("utf-8"))
        h.update(b"\0")
        h.update(path.read_bytes())

    # Compiler changes invalidate project artifacts as well.
    compiler_root = Path(__file__).resolve().parent
    compiler_files = [Path(sys.argv[0]).resolve(), *sorted(compiler_root.rglob("*.py"))]
    for path in compiler_files:
        if path.is_file():
            h.update(b"\0compiler\0")
            h.update(str(path).encode("utf-8"))
            h.update(path.read_bytes())
    return h.hexdigest().upper()


def restore(project: Optional[ProjectBuild], digest: str, output_path: str) -> bool:
    if project is None or not project.incremental:
        return False
    try:
        if project.state_path.read_text(encoding="ascii").strip() != digest:
            return False
        if not project.artifact_path.is_file():
            return False
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(project.artifact_path, output)
        return True
    except OSError:
        return False


def store(project: Optional[ProjectBuild], digest: str, output_path: str) -> None:
    if project is None or not project.incremental:
        return
    project.cache_dir.mkdir(parents=True, exist_ok=True)
    artifact_tmp = project.cache_dir / "build.exe.tmp"
    state_tmp = project.cache_dir / "build.state.tmp"
    shutil.copyfile(output_path, artifact_tmp)
    state_tmp.write_text(digest + "\n", encoding="ascii")
    os.replace(artifact_tmp, project.artifact_path)
    os.replace(state_tmp, project.state_path)
