import os
import json
from datetime import datetime
from typing import Dict, Any


class AuditLogger:
    """Append-only encrypted audit log. Each entry is a JSON object stored on its own line,
    encrypted with the master key via EncryptionManager passed to constructor.
    """

    BASE = '.sequential'
    LOG_FILE = os.path.join(BASE, 'audit.log.enc')

    def __init__(self, encryption_manager):
        os.makedirs(self.BASE, exist_ok=True)
        self.enc = encryption_manager

    def log_event(self, event: str, meta: Dict[str, Any] = None):
        meta = meta or {}
        entry = {'timestamp': datetime.utcnow().isoformat(), 'event': event, 'meta': meta}
        raw = json.dumps(entry).encode('utf-8')
        cipher = self.enc.encrypt(raw.decode('utf-8'))
        with open(self.LOG_FILE, 'ab') as f:
            f.write(cipher + b"\n")

    def read_recent(self, limit: int = 200):
        if not os.path.exists(self.LOG_FILE):
            return []
        out = []
        with open(self.LOG_FILE, 'rb') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    plain = self.enc.decrypt(line)
                    out.append(json.loads(plain))
                except Exception:
                    continue
        return out[-limit:]