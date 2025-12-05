import re
import logging
from typing import List, Tuple

logger = logging.getLogger('sequential.scanner')

try:
    from rust_core import scan_text_for_secrets as rust_scan_text, scan_files as rust_scan_files
    RUST_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Rust scanner not available, using Python fallback: {e}")
    RUST_AVAILABLE = False

CANDIDATE_PATTERNS = [
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
    (r'sk-[A-Za-z0-9]{48}', 'OpenAI Secret'),
    (r'ghp_[A-Za-z0-9]{36}', 'GitHub PAT'),
    (r'([MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})', 'Discord Token')
]


def scan_text_for_secrets(text: str) -> List[Tuple[str, str]]:
    if RUST_AVAILABLE:
        try:
            return rust_scan_text(text)
        except Exception as e:
            logger.warning(f"Rust scan_text_for_secrets failed, using Python fallback: {e}")
    hits = []
    for pattern, label in CANDIDATE_PATTERNS:
        for m in re.findall(pattern, text):
            hits.append((label, m))
    return hits


def scan_files(paths: List[str]) -> List[Tuple[str, str, str]]:
    if RUST_AVAILABLE:
        try:
            return rust_scan_files(paths)
        except Exception as e:
            logger.warning(f"Rust scan_files failed, using Python fallback: {e}")
    results = []
    for p in paths:
        try:
            with open(p, 'r', errors='ignore') as f:
                txt = f.read()
            hits = scan_text_for_secrets(txt)
            for label, secret in hits:
                results.append((p, label, secret))
        except Exception:
            continue
    return results
