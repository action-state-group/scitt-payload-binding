# SPDX-License-Identifier: BSD-3-Clause
"""Installed-package checks for the cpb-check built-in vector suite."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_LIB_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _LIB_ROOT.parent
_SOURCE_VECTORS = _REPO_ROOT / "vectors" / "cpb-check"
_PACKAGED_VECTORS = _LIB_ROOT / "cpb" / "_vectors" / "cpb-check"


def test_packaged_self_test_vectors_match_the_canonical_copies() -> None:
    """The installable copies cannot silently drift from vectors/cpb-check."""
    source = {
        path.relative_to(_SOURCE_VECTORS): path.read_bytes()
        for path in _SOURCE_VECTORS.rglob("*.json")
    }
    packaged = {
        path.relative_to(_PACKAGED_VECTORS): path.read_bytes()
        for path in _PACKAGED_VECTORS.rglob("*.json")
    }
    assert packaged == source


def test_noneditable_install_can_run_self_test_outside_checkout(tmp_path: Path) -> None:
    """Regression: ``pip install ./lib`` used to look for ``../../vectors``.

    Install to an isolated target (a regular wheel install, not editable), run
    from a directory outside the checkout, and require all packaged vectors to
    execute. This reproduces the user-facing command without network access.
    """
    target = tmp_path / "site"
    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-build-isolation",
            "--target",
            str(target),
            str(_LIB_ROOT),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert install.returncode == 0, install.stdout + install.stderr

    env = os.environ.copy()
    env["PYTHONPATH"] = str(target)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    run = subprocess.run(
        [sys.executable, "-m", "cpb._cli", "--self-test"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "13/13 passed, 0 failed" in run.stdout
