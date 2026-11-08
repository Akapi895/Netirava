"""Config loading. Paths in the YAML are relative to the repo root."""

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def load(path):
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    raw = p.read_bytes()
    cfg = yaml.safe_load(raw)
    cfg["_path"] = str(p)
    cfg["_sha1"] = hashlib.sha1(raw).hexdigest()
    return cfg


def path(cfg, key):
    """Resolve cfg['paths'][key] against the repo root."""
    p = Path(cfg["paths"][key])
    return p if p.is_absolute() else ROOT / p


def section_hash(obj):
    return hashlib.sha1(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]


def sha1_file(p, chunk=1 << 22):
    h = hashlib.sha1()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()
