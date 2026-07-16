"""Project-relative runtime path resolution."""

from pathlib import Path


def project_root(start: Path | None = None) -> Path:
    """Find the nearest project root, falling back to the current directory."""
    current = (start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return current


def output_directory(start: Path | None = None) -> Path:
    """Return the repository-level runtime output directory."""
    return project_root(start) / "output"
