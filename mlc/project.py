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
    """Raised when a project manifest or incremental cache is invalid."""


@dataclass(frozen=True)
class ProjectBuild:
    """Validated project configuration carried through compilation and caching."""

    manifest: Path
    cache_dir: Path
    incremental: bool
    expanded_args: Tuple[str, ...]

    @property
    def state_path(self) -> Path:
        """Return the digest metadata path inside the project cache."""

        return self.cache_dir / "build.state"

    @property
    def artifact_path(self) -> Path:
        """Return the cached executable path inside the project cache."""

        return self.cache_dir / "build.exe"


_KEYS = {
    "entry", "input", "output", "include", "import_paths", "subsystem",
    "target", "object_pipeline", "incremental", "cache_dir", "compiler_args",
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


def _define_args(value: Any) -> List[str]:
    """Convert a TOML defines table into deterministic typed CLI arguments."""
    if value is None:
        return []
    if not isinstance(value, dict):
        raise ProjectError("project defines must be a table")
    result: List[str] = []
    for name in sorted(value):
        if not isinstance(name, str) or not name or not (name[0].isalpha() or name[0] == "_") or not all(
                ch.isalnum() or ch == "_" for ch in name):
            raise ProjectError(f"invalid compile definition name: {name!r}")
        item = value[name]
        if isinstance(item, bool):
            encoded = "true" if item else "false"
        elif isinstance(item, int):
            encoded = str(item)
        elif isinstance(item, str):
            encoded = '"' + item.replace("\\", "\\\\").replace('"', '\\"') + '"'
        else:
            raise ProjectError(f"compile definition {name} must be bool, int, or string")
        result.extend(["-D", f"{name}={encoded}"])
    return result


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
    top_level_defines = parsed.get("defines")
    define_args = _define_args(top_level_defines)
    incremental = cfg.get("incremental", True)
    object_pipeline_set = "object_pipeline" in cfg
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
    target = cfg.get("target")
    if target is not None:
        if not isinstance(target, str):
            raise ProjectError("project field 'target' must be a string")
        expanded.extend(["--target", target])
    if object_pipeline_set:
        expanded.append("--object-pipeline" if object_pipeline else "--no-object-pipeline")
    expanded.extend(define_args)
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
    """Hash effective arguments plus all reachable project and compiler sources."""

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
    """Restore a cached artifact only when its recorded digest matches exactly."""

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
    """Atomically replace the cached artifact and its validation digest."""

    if project is None or not project.incremental:
        return
    project.cache_dir.mkdir(parents=True, exist_ok=True)
    artifact_tmp = project.cache_dir / "build.exe.tmp"
    state_tmp = project.cache_dir / "build.state.tmp"
    shutil.copyfile(output_path, artifact_tmp)
    state_tmp.write_text(digest + "\n", encoding="ascii")
    os.replace(artifact_tmp, project.artifact_path)
    os.replace(state_tmp, project.state_path)
