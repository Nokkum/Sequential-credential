import re
from typing import List, Tuple

CANDIDATE_PATTERNS = [
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
    (r'sk-[A-Za-z0-9]{48}', 'OpenAI Secret'),
    (r'ghp_[A-Za-z0-9]{36}', 'GitHub PAT'),
    (r'([MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})', 'Discord Token')
]


def scan_text_for_secrets(text: str) -> List[Tuple[str, str]]:
    hits = []
    for pattern, label in CANDIDATE_PATTERNS:
        for m in re.findall(pattern, text):
            hits.append((label, m))
    return hits


def scan_files(paths: List[str]) -> List[Tuple[str, str, str]]:
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
