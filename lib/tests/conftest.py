# SPDX-License-Identifier: BSD-3-Clause
import json
import pathlib

VECTORS_DIR = pathlib.Path(__file__).parent.parent.parent / "vectors"


def load_vectors(subpath: str) -> list[dict]:
    d = VECTORS_DIR / subpath
    vectors = []
    for f in sorted(d.glob("*.json")):
        vectors.append(json.loads(f.read_text()))
    return vectors
