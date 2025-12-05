use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rusqlite::{Connection, params};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value as JsonValue};
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};
use base64::{Engine as _, engine::general_purpose::STANDARD};

const JSON_FILE: &str = "server_settings.json";
const SQLITE_FILE: &str = "server_settings.db";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntryInfo {
    #[serde(flatten)]
    data: serde_json::Map<String, JsonValue>,
}

#[pyclass]
pub struct Database {
    json_path: String,
    sqlite_path: String,
    lock: Mutex<()>,
}

#[pymethods]
impl Database {
    #[new]
    #[pyo3(signature = (sqlite_path=None, use_psql=false, pg_conn_str=None))]
    fn new(sqlite_path: Option<String>, use_psql: bool, pg_conn_str: Option<String>) -> PyResult<Self> {
        let json_path = JSON_FILE.to_string();
        let sqlite_path = sqlite_path.unwrap_or_else(|| SQLITE_FILE.to_string());
        
        let db = Database {
            json_path: json_path.clone(),
            sqlite_path: sqlite_path.clone(),
            lock: Mutex::new(()),
        };
        
        db.init_json()?;
        db.init_sqlite()?;
        
        Ok(db)
    }
    
    fn get(&self, py: Python, category: &str, provider_config: &str) -> PyResult<Option<PyObject>> {
        let _guard = self.lock.lock();
        let data = self.read_json()?;
        
        if let Some(cat_data) = data.get(category) {
            if let Some(entry) = cat_data.get(provider_config) {
                return Ok(Some(json_to_pyobject(py, entry)?));
            }
        }
        
        Ok(None)
    }
    
    fn set(&self, py: Python, category: &str, provider_config: &str, info: &PyDict) -> PyResult<()> {
        let _guard = self.lock.lock();
        
        let mut data = self.read_json()?;
        
        let mut info_value = pydict_to_json(info)?;
        if let Some(obj) = info_value.as_object_mut() {
            obj.insert("updated_at".to_string(), JsonValue::String(Utc::now().to_rfc3339()));
        }
        
        if !data.as_object().map(|o| o.contains_key(category)).unwrap_or(false) {
            if let Some(obj) = data.as_object_mut() {
                obj.insert(category.to_string(), serde_json::Map::new().into());
            }
        }
        
        if let Some(cat_data) = data.get_mut(category).and_then(|v| v.as_object_mut()) {
            cat_data.insert(provider_config.to_string(), info_value.clone());
        }
        
        self.write_json(&data)?;
        
        let parts: Vec<&str> = provider_config.splitn(2, '_').collect();
        if parts.len() == 2 {
            let info_str = serde_json::to_string(&info_value)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON error: {}", e)))?;
            self.sqlite_upsert(category, parts[0], parts[1], &info_str, None)?;
        }
        
        Ok(())
    }
    
    fn delete(&self, category: &str, provider_config: &str) -> PyResult<()> {
        let _guard = self.lock.lock();
        
        let mut data = self.read_json()?;
        
        if let Some(cat_data) = data.get_mut(category).and_then(|v| v.as_object_mut()) {
            cat_data.remove(provider_config);
            if cat_data.is_empty() {
                data.as_object_mut().unwrap().remove(category);
            }
        }
        
        self.write_json(&data)?;
        
        let parts: Vec<&str> = provider_config.splitn(2, '_').collect();
        if parts.len() == 2 {
            self.sqlite_delete(category, parts[0], parts[1])?;
        }
        
        Ok(())
    }
    
    fn list_all(&self, py: Python) -> PyResult<PyObject> {
        let _guard = self.lock.lock();
        let data = self.read_json()?;
        json_to_pyobject(py, &data)
    }
    
    fn set_blob(&self, py: Python, category: &str, provider: &str, cfg: &str, meta: &PyDict) -> PyResult<()> {
        let _guard = self.lock.lock();
        
        let meta_json = pydict_to_json(meta)?;
        
        let blob_bytes = if let Some(blob_b64) = meta_json.get("blob").and_then(|v| v.as_str()) {
            Some(STANDARD.decode(blob_b64).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid base64: {}", e))
            })?)
        } else {
            None
        };
        
        let mut info: serde_json::Map<String, JsonValue> = meta_json.as_object()
            .cloned()
            .unwrap_or_default();
        info.remove("blob");
        
        let provider_config = format!("{}_{}", provider, cfg);
        
        let info_dict = PyDict::new(py);
        for (k, v) in &info {
            info_dict.set_item(k, json_to_pyobject(py, v)?)?;
        }
        
        drop(_guard);
        self.set(py, category, &provider_config, info_dict)?;
        
        let _guard = self.lock.lock();
        let info_str = serde_json::to_string(&info)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON error: {}", e)))?;
        self.sqlite_upsert(category, provider, cfg, &info_str, blob_bytes.as_deref())?;
        
        Ok(())
    }
    
    fn get_blob_entry(&self, py: Python, category: &str, provider: &str, cfg: &str) -> PyResult<Option<PyObject>> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        let mut stmt = conn.prepare(
            "SELECT info, blob, updated_at FROM metadata WHERE category=? AND provider=? AND config_name=?"
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        let result: Result<(Option<String>, Option<Vec<u8>>, Option<String>), _> = stmt.query_row(
            params![category, provider, cfg],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        );
        
        match result {
            Ok((info_text, blob, updated_at)) => {
                let dict = PyDict::new(py);
                
                let info: JsonValue = info_text
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(JsonValue::Object(serde_json::Map::new()));
                
                dict.set_item("info", json_to_pyobject(py, &info)?)?;
                
                if let Some(blob_data) = blob {
                    dict.set_item("blob", STANDARD.encode(&blob_data))?;
                } else {
                    dict.set_item("blob", py.None())?;
                }
                
                dict.set_item("updated_at", updated_at)?;
                
                Ok(Some(dict.into()))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))),
        }
    }
    
    fn list_categories(&self) -> PyResult<Vec<String>> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        let mut stmt = conn.prepare("SELECT name FROM categories ORDER BY name")
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        let categories: Vec<String> = stmt.query_map([], |row| row.get(0))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(categories)
    }
    
    fn add_category(&self, name: &str) -> PyResult<()> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute(
            "INSERT OR IGNORE INTO categories (name) VALUES (?)",
            params![name]
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        Ok(())
    }
    
    fn delete_category(&self, name: &str) -> PyResult<bool> {
        if name == "tokens" || name == "apis" {
            return Ok(false);
        }
        
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute("DELETE FROM categories WHERE name = ?", params![name])
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        Ok(true)
    }
    
    fn get_setting(&self, key: &str, default: Option<String>) -> PyResult<Option<String>> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?")
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        match stmt.query_row(params![key], |row| row.get::<_, String>(0)) {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(default),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))),
        }
    }
    
    fn set_setting(&self, key: &str, value: &str) -> PyResult<()> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            params![key, value]
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        Ok(())
    }
    
    fn set_favorite(&self, category: &str, provider: &str, cfg: &str, favorite: bool) -> PyResult<()> {
        self.ensure_metadata_row(category, provider, cfg)?;
        
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute(
            "UPDATE metadata SET favorite = ?, updated_at = ? WHERE category = ? AND provider = ? AND config_name = ?",
            params![favorite as i32, Utc::now().to_rfc3339(), category, provider, cfg]
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        self.update_json_field(category, provider, cfg, "favorite", JsonValue::Bool(favorite))?;
        
        Ok(())
    }
    
    fn set_notes(&self, category: &str, provider: &str, cfg: &str, notes: &str) -> PyResult<()> {
        self.ensure_metadata_row(category, provider, cfg)?;
        
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute(
            "UPDATE metadata SET notes = ?, updated_at = ? WHERE category = ? AND provider = ? AND config_name = ?",
            params![notes, Utc::now().to_rfc3339(), category, provider, cfg]
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        self.update_json_field(category, provider, cfg, "notes", JsonValue::String(notes.to_string()))?;
        
        Ok(())
    }
    
    fn set_expiry(&self, category: &str, provider: &str, cfg: &str, expires_at: Option<String>) -> PyResult<()> {
        self.ensure_metadata_row(category, provider, cfg)?;
        
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute(
            "UPDATE metadata SET expires_at = ?, updated_at = ? WHERE category = ? AND provider = ? AND config_name = ?",
            params![expires_at.as_deref(), Utc::now().to_rfc3339(), category, provider, cfg]
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        let json_value = expires_at.map(JsonValue::String).unwrap_or(JsonValue::Null);
        self.update_json_field(category, provider, cfg, "expires_at", json_value)?;
        
        Ok(())
    }
    
    fn get_all_entries(&self, py: Python, category: Option<String>) -> PyResult<PyObject> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        let entries = PyList::empty(py);
        
        type RowTuple = (String, String, String, Option<String>, i32, Option<String>, Option<String>, Option<String>);
        
        fn map_row(row: &rusqlite::Row) -> rusqlite::Result<RowTuple> {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        }
        
        let results: Vec<RowTuple> = if let Some(ref cat) = category {
            let mut stmt = conn.prepare(
                "SELECT category, provider, config_name, info, favorite, notes, expires_at, updated_at 
                 FROM metadata WHERE category = ? ORDER BY favorite DESC, provider, config_name"
            ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
            
            let mapped = stmt.query_map(params![cat], map_row)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
            mapped.filter_map(|r| r.ok()).collect()
        } else {
            let mut stmt = conn.prepare(
                "SELECT category, provider, config_name, info, favorite, notes, expires_at, updated_at 
                 FROM metadata ORDER BY favorite DESC, category, provider, config_name"
            ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
            
            let mapped = stmt.query_map([], map_row)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
            mapped.filter_map(|r| r.ok()).collect()
        };
        
        for (cat, provider, config_name, info_str, favorite, notes, expires_at, updated_at) in results {
            let dict = PyDict::new(py);
            dict.set_item("category", cat)?;
            dict.set_item("provider", provider)?;
            dict.set_item("config_name", config_name)?;
            
            let info: JsonValue = info_str
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(JsonValue::Object(serde_json::Map::new()));
            dict.set_item("info", json_to_pyobject(py, &info)?)?;
            
            dict.set_item("favorite", favorite != 0)?;
            dict.set_item("notes", notes.unwrap_or_default())?;
            dict.set_item("expires_at", expires_at)?;
            dict.set_item("updated_at", updated_at)?;
            
            entries.append(dict)?;
        }
        
        Ok(entries.into())
    }
    
    fn search_entries(&self, py: Python, query: &str) -> PyResult<PyObject> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        let pattern = format!("%{}%", query);
        
        let mut stmt = conn.prepare(
            "SELECT category, provider, config_name, info, favorite, notes, expires_at, updated_at 
             FROM metadata 
             WHERE provider LIKE ? OR config_name LIKE ? OR notes LIKE ?
             ORDER BY favorite DESC, provider, config_name"
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        let entries = PyList::empty(py);
        
        let rows = stmt.query_map(params![&pattern, &pattern, &pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i32>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        }).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        for row in rows {
            if let Ok((cat, provider, config_name, info_str, favorite, notes, expires_at, updated_at)) = row {
                let dict = PyDict::new(py);
                dict.set_item("category", cat)?;
                dict.set_item("provider", provider)?;
                dict.set_item("config_name", config_name)?;
                
                let info: JsonValue = info_str
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(JsonValue::Object(serde_json::Map::new()));
                dict.set_item("info", json_to_pyobject(py, &info)?)?;
                
                dict.set_item("favorite", favorite != 0)?;
                dict.set_item("notes", notes.unwrap_or_default())?;
                dict.set_item("expires_at", expires_at)?;
                dict.set_item("updated_at", updated_at)?;
                
                entries.append(dict)?;
            }
        }
        
        Ok(entries.into())
    }
    
    fn get_expiring_entries(&self, py: Python, days: Option<i64>) -> PyResult<PyObject> {
        let days = days.unwrap_or(7);
        
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        let mut stmt = conn.prepare(
            "SELECT category, provider, config_name, expires_at 
             FROM metadata 
             WHERE expires_at IS NOT NULL AND expires_at != ''
             ORDER BY expires_at"
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        let entries = PyList::empty(py);
        let now = Utc::now();
        
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        }).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        for row in rows {
            if let Ok((cat, provider, config_name, expires_at_str)) = row {
                let clean_str = expires_at_str
                    .replace("Z", "+00:00")
                    .replace("+00:00", "");
                
                if let Ok(exp_date) = DateTime::parse_from_rfc3339(&expires_at_str)
                    .or_else(|_| clean_str.parse::<DateTime<Utc>>().map(|d| d.into()))
                {
                    let days_remaining = (exp_date.with_timezone(&Utc) - now).num_days();
                    
                    if days_remaining <= days {
                        let dict = PyDict::new(py);
                        dict.set_item("category", cat)?;
                        dict.set_item("provider", provider)?;
                        dict.set_item("config_name", config_name)?;
                        dict.set_item("expires_at", expires_at_str)?;
                        dict.set_item("days_remaining", days_remaining)?;
                        entries.append(dict)?;
                    }
                }
            }
        }
        
        Ok(entries.into())
    }
    
    fn export_to_file(&self, py: Python, data: &PyDict, path: &str) -> PyResult<()> {
        let json_data = pydict_to_json(data)?;
        let content = serde_json::to_string_pretty(&json_data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON error: {}", e)))?;
        fs::write(path, content)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("IO error: {}", e)))
    }
    
    fn import_from_file(&self, py: Python, path: &str) -> PyResult<()> {
        let content = fs::read_to_string(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("IO error: {}", e)))?;
        
        let data: serde_json::Map<String, JsonValue> = serde_json::from_str(&content)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON error: {}", e)))?;
        
        for (key, meta) in data {
            let parts: Vec<&str> = key.splitn(2, '_').collect();
            if parts.len() != 2 {
                continue;
            }
            
            let provider = parts[0];
            let cfg = parts[1];
            
            let blob = meta.get("blob").and_then(|v| v.as_str()).map(|s| s.to_string());
            
            let mut info: serde_json::Map<String, JsonValue> = meta.as_object()
                .cloned()
                .unwrap_or_default();
            info.remove("blob");
            
            let info_dict = PyDict::new(py);
            for (k, v) in &info {
                info_dict.set_item(k, json_to_pyobject(py, v)?)?;
            }
            
            self.set(py, "tokens", &key, info_dict)?;
            
            if let Some(blob_data) = blob {
                let meta_dict = PyDict::new(py);
                meta_dict.set_item("blob", &blob_data)?;
                self.set_blob(py, "tokens", provider, cfg, meta_dict)?;
            }
        }
        
        Ok(())
    }
}

impl Database {
    fn init_json(&self) -> PyResult<()> {
        if !Path::new(&self.json_path).exists() {
            fs::write(&self.json_path, "{}")
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("IO error: {}", e)))?;
        }
        Ok(())
    }
    
    fn init_sqlite(&self) -> PyResult<()> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
                category TEXT NOT NULL,
                provider TEXT NOT NULL,
                config_name TEXT NOT NULL,
                info TEXT,
                blob BLOB,
                updated_at TIMESTAMP,
                PRIMARY KEY (category, provider, config_name)
            );
            CREATE TABLE IF NOT EXISTS categories (
                name TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );"
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        self.migrate_schema(&conn)?;
        
        conn.execute("INSERT OR IGNORE INTO categories (name) VALUES ('tokens')", [])
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        conn.execute("INSERT OR IGNORE INTO categories (name) VALUES ('apis')", [])
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        Ok(())
    }
    
    fn migrate_schema(&self, conn: &Connection) -> PyResult<()> {
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(metadata)")
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        
        if !columns.contains(&"favorite".to_string()) {
            conn.execute("ALTER TABLE metadata ADD COLUMN favorite INTEGER DEFAULT 0", [])
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        }
        
        if !columns.contains(&"notes".to_string()) {
            conn.execute("ALTER TABLE metadata ADD COLUMN notes TEXT", [])
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        }
        
        if !columns.contains(&"expires_at".to_string()) {
            conn.execute("ALTER TABLE metadata ADD COLUMN expires_at TIMESTAMP", [])
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        }
        
        Ok(())
    }
    
    fn read_json(&self) -> PyResult<JsonValue> {
        let content = fs::read_to_string(&self.json_path)
            .unwrap_or_else(|_| "{}".to_string());
        
        serde_json::from_str(&content)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON error: {}", e)))
    }
    
    fn write_json(&self, data: &JsonValue) -> PyResult<()> {
        let content = serde_json::to_string_pretty(data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON error: {}", e)))?;
        
        fs::write(&self.json_path, content)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("IO error: {}", e)))
    }
    
    fn sqlite_upsert(&self, category: &str, provider: &str, cfg: &str, info_text: &str, blob_bytes: Option<&[u8]>) -> PyResult<()> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute(
            "INSERT INTO metadata (category, provider, config_name, info, blob, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(category, provider, config_name) DO UPDATE SET
                info = excluded.info,
                blob = COALESCE(excluded.blob, metadata.blob),
                updated_at = excluded.updated_at",
            params![category, provider, cfg, info_text, blob_bytes, Utc::now().to_rfc3339()]
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        Ok(())
    }
    
    fn sqlite_delete(&self, category: &str, provider: &str, cfg: &str) -> PyResult<()> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        conn.execute(
            "DELETE FROM metadata WHERE category=? AND provider=? AND config_name=?",
            params![category, provider, cfg]
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        
        Ok(())
    }
    
    fn ensure_metadata_row(&self, category: &str, provider: &str, cfg: &str) -> PyResult<()> {
        let conn = Connection::open(&self.sqlite_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e))
        })?;
        
        let exists: bool = conn.query_row(
            "SELECT 1 FROM metadata WHERE category = ? AND provider = ? AND config_name = ?",
            params![category, provider, cfg],
            |_| Ok(true)
        ).unwrap_or(false);
        
        if !exists {
            conn.execute(
                "INSERT INTO metadata (category, provider, config_name, info, updated_at) VALUES (?, ?, ?, ?, ?)",
                params![category, provider, cfg, "{}", Utc::now().to_rfc3339()]
            ).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("SQLite error: {}", e)))?;
        }
        
        let _guard = self.lock.lock();
        let mut data = self.read_json()?;
        
        let key = format!("{}_{}", provider, cfg);
        
        if !data.get(category).map(|c| c.get(&key).is_some()).unwrap_or(false) {
            if !data.as_object().map(|o| o.contains_key(category)).unwrap_or(false) {
                data.as_object_mut().unwrap().insert(category.to_string(), JsonValue::Object(serde_json::Map::new()));
            }
            
            let entry = serde_json::json!({
                "provider": provider,
                "config_name": cfg,
                "updated_at": Utc::now().to_rfc3339()
            });
            
            data.get_mut(category).unwrap().as_object_mut().unwrap().insert(key, entry);
            self.write_json(&data)?;
        }
        
        Ok(())
    }
    
    fn update_json_field(&self, category: &str, provider: &str, cfg: &str, field: &str, value: JsonValue) -> PyResult<()> {
        let _guard = self.lock.lock();
        let mut data = self.read_json()?;
        
        let key = format!("{}_{}", provider, cfg);
        
        if let Some(cat_data) = data.get_mut(category).and_then(|v| v.as_object_mut()) {
            if let Some(entry) = cat_data.get_mut(&key).and_then(|v| v.as_object_mut()) {
                entry.insert(field.to_string(), value);
                entry.insert("updated_at".to_string(), JsonValue::String(Utc::now().to_rfc3339()));
                self.write_json(&data)?;
            }
        }
        
        Ok(())
    }
}

fn json_to_pyobject(py: Python, value: &JsonValue) -> PyResult<PyObject> {
    match value {
        JsonValue::Null => Ok(py.None()),
        JsonValue::Bool(b) => Ok(b.into_py(py)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Ok(py.None())
            }
        }
        JsonValue::String(s) => Ok(s.into_py(py)),
        JsonValue::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_to_pyobject(py, item)?)?;
            }
            Ok(list.into())
        }
        JsonValue::Object(obj) => {
            let dict = PyDict::new(py);
            for (k, v) in obj {
                dict.set_item(k, json_to_pyobject(py, v)?)?;
            }
            Ok(dict.into())
        }
    }
}

fn pydict_to_json(dict: &PyDict) -> PyResult<JsonValue> {
    let mut map = serde_json::Map::new();
    
    for (key, value) in dict.iter() {
        let key_str: String = key.extract()?;
        let json_value = pyany_to_json(value)?;
        map.insert(key_str, json_value);
    }
    
    Ok(JsonValue::Object(map))
}

fn pyany_to_json(obj: &PyAny) -> PyResult<JsonValue> {
    if obj.is_none() {
        Ok(JsonValue::Null)
    } else if let Ok(b) = obj.extract::<bool>() {
        Ok(JsonValue::Bool(b))
    } else if let Ok(i) = obj.extract::<i64>() {
        Ok(JsonValue::Number(i.into()))
    } else if let Ok(f) = obj.extract::<f64>() {
        Ok(serde_json::Number::from_f64(f)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null))
    } else if let Ok(s) = obj.extract::<String>() {
        Ok(JsonValue::String(s))
    } else if let Ok(list) = obj.downcast::<PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(pyany_to_json(item)?);
        }
        Ok(JsonValue::Array(arr))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        pydict_to_json(dict)
    } else {
        Ok(JsonValue::String(obj.str()?.to_string()))
    }
}
