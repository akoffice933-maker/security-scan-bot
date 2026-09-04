from pathlib import Path

import pytest

from app.services import scanners

FIXTURE = Path(__file__).parent / "fixtures" / "smoke_src"


def test_smoke_bandit_flags_eval_in_fixture():
    if not scanners.tool_available("bandit"):
        pytest.skip("bandit not installed")
    result = scanners.scan_bandit(str(FIXTURE), timeout=60)
    assert result.findings, "Bandit should flag eval() / hardcoded password in the fixture"
    joined = " ".join(f.title + f.description for f in result.findings).lower()
    assert "eval" in joined or "hardcoded" in joined or "b307" in joined or "b105" in joined
