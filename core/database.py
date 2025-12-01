import os
import json
import base64
import sqlite3
import logging
from threading import Lock
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger('sequential.db')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(handler)


class Database:
    JSON_FILE = 'server_settings.json'
    SQLITE_FILE = 'server_settings.db'

    def __init__(self, sqlite_path: Optional[str] = None, use_psql: bool = False, pg_conn_str: Optional[str] = None):
        self.lock = Lock()
        self.json_path = self.JSON_FILE
        self.sqlite_path = sqlite_path or self.SQLITE_FILE
        self.use_psql = use_psql
        self.pg_conn_str = pg_conn_str

        self._init_json()
        self._init_sqlite()

    def _init_json(self):
        if not os.path.exists(self.json_path):
            with open(self.json_path, 'w') as f:
                json.dump({}, f)

    def _read_json(self) -> Dict[str, Any]:
        try:
            with open(self.json_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_json(self, data: Dict[str, Any]):
        with open(self.json_path, 'w') as f:
            json.dump(data, f, indent=2)

    def _init_sqlite(self):
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    category TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    config_name TEXT NOT NULL,
                    info TEXT,
                    blob BLOB,
                    updated_at TIMESTAMP,
                    PRIMARY KEY (category, provider, config_name)
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    name TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            self._migrate_schema(cur)
            conn.commit()
        finally:
            conn.close()

    def _migrate_schema(self, cur):
        cur.execute("PRAGMA table_info(metadata)")
        columns = [row[1] for row in cur.fetchall()]
        if 'favorite' not in columns:
            cur.execute('ALTER TABLE metadata ADD COLUMN favorite INTEGER DEFAULT 0')
        if 'notes' not in columns:
            cur.execute('ALTER TABLE metadata ADD COLUMN notes TEXT')
        if 'expires_at' not in columns:
            cur.execute('ALTER TABLE metadata ADD COLUMN expires_at TIMESTAMP')
        for cat in ['tokens', 'apis']:
            cur.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', (cat,))

    # JSON-centric API (backward compatibility)
    def get(self, category: str, provider_config: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            data = self._read_json()
            return data.get(category, {}).get(provider_config)

    def set(self, category: str, provider_config: str, info: Dict[str, Any]):
        with self.lock:
            data = self._read_json()
            data.setdefault(category, {})[provider_config] = {**info, 'updated_at': datetime.utcnow().isoformat()}
            self._write_json(data)
            logger.debug('Wrote JSON metadata for %s/%s', category, provider_config)

            provider, cfg = provider_config.split('_', 1)
            self._sqlite_upsert(category, provider, cfg, json.dumps(info), None)

    def delete(self, category: str, provider_config: str):
        with self.lock:
            data = self._read_json()
            if category in data and provider_config in data[category]:
                del data[category][provider_config]
                if not data[category]:
                    del data[category]
                self._write_json(data)
                logger.debug('Deleted JSON metadata for %s/%s', category, provider_config)

            provider, cfg = provider_config.split('_', 1)
            self._sqlite_delete(category, provider, cfg)

    def list_all(self) -> Dict[str, Any]:
        with self.lock:
            return self._read_json()

    # sqlite operations
    def _sqlite_upsert(self, category, provider, cfg, info_text, blob_bytes):
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO metadata (category, provider, config_name, info, blob, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(category, provider, config_name) DO UPDATE SET
                    info = excluded.info,
                    blob = COALESCE(excluded.blob, metadata.blob),
                    updated_at = excluded.updated_at
            ''', (category, provider, cfg, info_text, blob_bytes, datetime.utcnow()))
            conn.commit()
        finally:
            conn.close()

    def _sqlite_delete(self, category, provider, cfg):
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('DELETE FROM metadata WHERE category=? AND provider=? AND config_name=?', (category, provider, cfg))
            conn.commit()
        finally:
            conn.close()

    def set_blob(self, category, provider, cfg, meta: Dict[str, Any]):
        with self.lock:
            blob_b64 = meta.get('blob')
            blob_bytes = base64.b64decode(blob_b64) if blob_b64 else None
            info = {k: v for k, v in meta.items() if k != 'blob'}
            # JSON mirror
            self.set(category, f"{provider}_{cfg}", info)
            # sqlite store
            self._sqlite_upsert(category, provider, cfg, json.dumps(info), blob_bytes)
            logger.debug('Stored blob in sqlite for %s/%s/%s', category, provider, cfg)

    def get_blob_entry(self, category, provider, cfg) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('SELECT info, blob, updated_at FROM metadata WHERE category=? AND provider=? AND config_name=?', (category, provider, cfg))
            row = cur.fetchone()
            if not row:
                return None
            info_text, blob, updated = row
            info = json.loads(info_text) if info_text else {}
            blob_b64 = base64.b64encode(blob).decode('utf-8') if blob else None
            return {'info': info, 'blob': blob_b64, 'updated_at': updated}
        finally:
            conn.close()

    def export_provider(self, category, provider) -> Dict[str, Any]:
        out = {}
        all_meta = self._read_json().get(category, {})
        for key, meta in all_meta.items():
            if key.startswith(provider + '_'):
                out[key] = meta
                parts = key.split('_', 1)
                cfg = parts[1]
                entry = self.get_blob_entry(category, provider, cfg)
                if entry and entry.get('blob'):
                    out[key]['blob'] = entry['blob']
        return out

    def export_to_file(self, data: Dict[str, Any], path: str):
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def import_from_file(self, path: str):
        with open(path, 'r') as f:
            data = json.load(f)
        for key, meta in data.items():
            parts = key.split('_', 1)
            if len(parts) != 2:
                continue
            provider, cfg = parts
            blob = meta.get('blob')
            info = {k: v for k, v in meta.items() if k != 'blob'}
            self.set('tokens', key, info)
            if blob:
                self.set_blob('tokens', provider, cfg, {'blob': blob})

    def list_categories(self) -> list:
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('SELECT name FROM categories ORDER BY name')
            return [row[0] for row in cur.fetchall()]
        finally:
            conn.close()

    def add_category(self, name: str):
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', (name,))
            conn.commit()
        finally:
            conn.close()

    def delete_category(self, name: str):
        if name in ('tokens', 'apis'):
            return False
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('DELETE FROM categories WHERE name = ?', (name,))
            conn.commit()
            return True
        finally:
            conn.close()

    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
            row = cur.fetchone()
            return row[0] if row else default
        finally:
            conn.close()

    def set_setting(self, key: str, value: str):
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
            conn.commit()
        finally:
            conn.close()

    def _ensure_metadata_row(self, category: str, provider: str, cfg: str):
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM metadata WHERE category = ? AND provider = ? AND config_name = ?',
                       (category, provider, cfg))
            exists = cur.fetchone() is not None
            if not exists:
                cur.execute('''
                    INSERT INTO metadata (category, provider, config_name, info, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (category, provider, cfg, '{}', datetime.utcnow()))
                conn.commit()
        finally:
            conn.close()
        with self.lock:
            data = self._read_json()
            key = f"{provider}_{cfg}"
            if category not in data:
                data[category] = {}
            if key not in data[category]:
                data[category][key] = {
                    'provider': provider,
                    'config_name': cfg,
                    'updated_at': datetime.utcnow().isoformat()
                }
                self._write_json(data)

    def sync_filesystem_entry(self, category: str, provider: str, cfg: str, has_credential: bool = True):
        self._ensure_metadata_row(category, provider, cfg)
        with self.lock:
            data = self._read_json()
            key = f"{provider}_{cfg}"
            if category in data and key in data[category]:
                data[category][key]['stored'] = 'filesystem' if has_credential else 'metadata_only'
                data[category][key]['updated_at'] = datetime.utcnow().isoformat()
                self._write_json(data)

    def set_favorite(self, category: str, provider: str, cfg: str, favorite: bool):
        self._ensure_metadata_row(category, provider, cfg)
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('UPDATE metadata SET favorite = ?, updated_at = ? WHERE category = ? AND provider = ? AND config_name = ?',
                       (1 if favorite else 0, datetime.utcnow(), category, provider, cfg))
            conn.commit()
        finally:
            conn.close()
        with self.lock:
            data = self._read_json()
            key = f"{provider}_{cfg}"
            if category in data and key in data[category]:
                data[category][key]['favorite'] = favorite
                data[category][key]['updated_at'] = datetime.utcnow().isoformat()
                self._write_json(data)

    def set_notes(self, category: str, provider: str, cfg: str, notes: str):
        self._ensure_metadata_row(category, provider, cfg)
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('UPDATE metadata SET notes = ?, updated_at = ? WHERE category = ? AND provider = ? AND config_name = ?',
                       (notes, datetime.utcnow(), category, provider, cfg))
            conn.commit()
        finally:
            conn.close()
        with self.lock:
            data = self._read_json()
            key = f"{provider}_{cfg}"
            if category in data and key in data[category]:
                data[category][key]['notes'] = notes
                data[category][key]['updated_at'] = datetime.utcnow().isoformat()
                self._write_json(data)

    def set_expiry(self, category: str, provider: str, cfg: str, expires_at: Optional[str]):
        self._ensure_metadata_row(category, provider, cfg)
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('UPDATE metadata SET expires_at = ?, updated_at = ? WHERE category = ? AND provider = ? AND config_name = ?',
                       (expires_at, datetime.utcnow(), category, provider, cfg))
            conn.commit()
        finally:
            conn.close()
        with self.lock:
            data = self._read_json()
            key = f"{provider}_{cfg}"
            if category in data and key in data[category]:
                data[category][key]['expires_at'] = expires_at
                data[category][key]['updated_at'] = datetime.utcnow().isoformat()
                self._write_json(data)

    def get_all_entries(self, category: str = None) -> list:
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            if category:
                cur.execute('''SELECT category, provider, config_name, info, favorite, notes, expires_at, updated_at 
                              FROM metadata WHERE category = ? ORDER BY favorite DESC, provider, config_name''', (category,))
            else:
                cur.execute('''SELECT category, provider, config_name, info, favorite, notes, expires_at, updated_at 
                              FROM metadata ORDER BY favorite DESC, category, provider, config_name''')
            rows = cur.fetchall()
            entries = []
            for row in rows:
                entries.append({
                    'category': row[0],
                    'provider': row[1],
                    'config_name': row[2],
                    'info': json.loads(row[3]) if row[3] else {},
                    'favorite': bool(row[4]),
                    'notes': row[5] or '',
                    'expires_at': row[6],
                    'updated_at': row[7]
                })
            return entries
        finally:
            conn.close()

    def search_entries(self, query: str) -> list:
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            pattern = f'%{query}%'
            cur.execute('''SELECT category, provider, config_name, info, favorite, notes, expires_at, updated_at 
                          FROM metadata 
                          WHERE provider LIKE ? OR config_name LIKE ? OR notes LIKE ?
                          ORDER BY favorite DESC, provider, config_name''', (pattern, pattern, pattern))
            rows = cur.fetchall()
            entries = []
            for row in rows:
                entries.append({
                    'category': row[0],
                    'provider': row[1],
                    'config_name': row[2],
                    'info': json.loads(row[3]) if row[3] else {},
                    'favorite': bool(row[4]),
                    'notes': row[5] or '',
                    'expires_at': row[6],
                    'updated_at': row[7]
                })
            return entries
        finally:
            conn.close()

    def get_expiring_entries(self, days: int = 7) -> list:
        conn = sqlite3.connect(self.sqlite_path)
        try:
            cur = conn.cursor()
            cur.execute('''SELECT category, provider, config_name, expires_at 
                          FROM metadata 
                          WHERE expires_at IS NOT NULL 
                          AND expires_at != ''
                          ORDER BY expires_at''')
            rows = cur.fetchall()
            expiring = []
            now = datetime.utcnow()
            for row in rows:
                try:
                    exp_date = datetime.fromisoformat(row[3].replace('Z', '+00:00').replace('+00:00', ''))
                    if (exp_date - now).days <= days:
                        expiring.append({
                            'category': row[0],
                            'provider': row[1],
                            'config_name': row[2],
                            'expires_at': row[3],
                            'days_remaining': (exp_date - now).days
                        })
                except Exception:
                    continue
            return expiring
        finally:
            conn.close()

    def import_from_csv(self, path: str, category: str = 'tokens'):
        import csv
        with open(path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                provider = row.get('provider', row.get('Provider', 'Other'))
                config_name = row.get('config_name', row.get('name', row.get('Name', f'imported_{count}')))
                notes = row.get('notes', row.get('Notes', ''))
                expires_at = row.get('expires_at', row.get('Expires', ''))
                info = {'imported': True, 'source': 'csv'}
                self.set(category, f"{provider}_{config_name}", info)
                if notes:
                    self.set_notes(category, provider, config_name, notes)
                if expires_at:
                    self.set_expiry(category, provider, config_name, expires_at)
                count += 1
            return count