from __future__ import annotations

from pathlib import Path

from cti_trust_gateway import __version__
from cti_trust_gateway.config import bundled_policy_path


def test_release_version_and_bundled_policies_match_repository() -> None:
    assert __version__ == "0.2.0b1"
    project = Path(__file__).resolve().parents[2]
    for name in ("default", "abstain"):
        assert (
            bundled_policy_path(name).read_bytes()
            == (project / "policies" / f"{name}.yml").read_bytes()
        )
