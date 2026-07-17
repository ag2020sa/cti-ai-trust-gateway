"""Paths to immutable resources distributed inside the package."""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def bundled_policy_path(name: str = "default") -> Path:
    if name not in {"default", "abstain"}:
        raise ValueError(f"Unknown bundled policy: {name}")
    path = PACKAGE_DIR / "data" / "policies" / f"{name}.yml"
    if not path.is_file():
        raise RuntimeError(f"Bundled policy is unavailable: {name}")
    return path
