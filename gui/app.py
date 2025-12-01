import os
import base64
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime, timedelta
import threading

try:
    import ttkbootstrap as tb
    HAS_BOOTSTRAP = True
except ImportError:
    HAS_BOOTSTRAP = False

from core.security import EncryptionManager
from core.configs import ConfigManager
from core.database import Database
from core.migration import migrate_filesystem_to_db
from core.audit import AuditLogger
from core.backup import BackupManager
from core.clipboard import secure_copy
from core.validators import validate_discord_token, validate_github_token


def check_password_strength(password: str) -> tuple:
    if not password:
        return 0, "No password"
    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("at least 8 characters")
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("uppercase letter")
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("lowercase letter")
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("number")
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 1
    else:
        feedback.append("special character")
    
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"
    
    if feedback:
        msg = f"{strength} - Add: " + ", ".join(feedback)
    else:
        msg = f"{strength}"
    return score, msg


class MasterPasswordDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text='Enter master password:').grid(row=0, column=0, columnspan=2, sticky='w')
        self.pw_var = tk.StringVar()
        self.entry = ttk.Entry(master, textvariable=self.pw_var, show='*', width=40)
        self.entry.grid(row=1, column=0, columnspan=2, sticky='we')
        
        self.strength_var = tk.StringVar(value="")
        self.strength_label = ttk.Label(master, textvariable=self.strength_var)
        self.strength_label.grid(row=2, column=0, columnspan=2, sticky='w')
        
        self.pw_var.trace('w', self._update_strength)
        return self.entry

    def _update_strength(self, *args):
        score, msg = check_password_strength(self.pw_var.get())
        self.strength_var.set(msg)

    def apply(self):
        self.result = self.pw_var.get()


class RotatePasswordDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text='Current master password:').grid(row=0, sticky='w')
        self.old_pw = tk.StringVar()
        ttk.Entry(master, textvariable=self.old_pw, show='*').grid(row=1, sticky='we')
        ttk.Label(master, text='New master password:').grid(row=2, sticky='w')
        self.new_pw = tk.StringVar()
        self.new_entry = ttk.Entry(master, textvariable=self.new_pw, show='*')
        self.new_entry.grid(row=3, sticky='we')
        
        self.strength_var = tk.StringVar(value="")
        ttk.Label(master, textvariable=self.strength_var).grid(row=4, sticky='w')
        self.new_pw.trace('w', self._update_strength)
        return None

    def _update_strength(self, *args):
        score, msg = check_password_strength(self.new_pw.get())
        self.strength_var.set(msg)

    def apply(self):
        self.result = (self.old_pw.get(), self.new_pw.get())


class CategoryDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text='Category name:').grid(row=0, sticky='w')
        self.name_var = tk.StringVar()
        self.entry = ttk.Entry(master, textvariable=self.name_var, width=30)
        self.entry.grid(row=1, sticky='we')
        return self.entry

    def apply(self):
        self.result = self.name_var.get().strip().lower()


class CredentialGUI:
    THEMES = ['flatly', 'darkly', 'superhero', 'solar', 'cyborg', 'vapor']
    AUTO_LOCK_OPTIONS = {'Disabled': 0, '1 minute': 60, '5 minutes': 300, '15 minutes': 900, '30 minutes': 1800}

    def __init__(self):
        self.db = Database()
        saved_theme = self.db.get_setting('theme', 'flatly')
        
        if HAS_BOOTSTRAP:
            try:
                self.style = tb.Style(saved_theme)
            except Exception:
                self.style = None
        else:
            self.style = None

        root = tk.Tk()
        root.withdraw()
        dlg = MasterPasswordDialog(root, title='Master Password')
        master_password = dlg.result or os.environ.get('MASTER_PASSWORD')
        root.destroy()

        if not master_password:
            raise SystemExit("No master password provided")

        self.encryption = EncryptionManager(master_password)
        self.cfg = ConfigManager(self.db, self.encryption)
        self.audit = AuditLogger(self.encryption)
        self.backup = BackupManager(self.encryption, self.db)

        self.root = tb.Window(themename=saved_theme) if self.style else tk.Tk()
        self.root.title('Sequential Credential Manager')
        self.root.geometry('1000x700')
        self.root.minsize(900, 600)

        self.category_var = tk.StringVar(value='tokens')
        self.provider_var = tk.StringVar(value='Discord')
        self.config_var = tk.StringVar(value='')
        self.data_var = tk.StringVar()
        self.notes_var = tk.StringVar()
        self.expiry_var = tk.StringVar()
        self.store_in_db = tk.BooleanVar(value=False)
        self.show_data = tk.BooleanVar(value=False)
        self.favorite_var = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar()
        self.theme_var = tk.StringVar(value=saved_theme)
        self.auto_lock_var = tk.StringVar(value=self.db.get_setting('auto_lock', 'Disabled'))

        self.locked = False
        self.last_activity = datetime.now()
        self.selected_entry = None

        self.build_ui()
        self.refresh_categories()
        self.refresh_credential_list()
        self.check_expiring_credentials()
        self.bind_shortcuts()
        self.start_auto_lock_timer()
        self.start_tray_if_available()
        
        self.root.bind('<Motion>', self._reset_activity)
        self.root.bind('<Key>', self._reset_activity)
        self.root.bind('<Button>', self._reset_activity)
        
        self.root.mainloop()

    def _reset_activity(self, event=None):
        self.last_activity = datetime.now()

    def bind_shortcuts(self):
        self.root.bind('<Control-s>', lambda e: self.on_save())
        self.root.bind('<Control-c>', lambda e: self.copy_to_clipboard())
        self.root.bind('<Control-f>', lambda e: self.search_entry.focus_set())
        self.root.bind('<Escape>', lambda e: self.clear_selection())

    def start_auto_lock_timer(self):
        def check_lock():
            if self.locked:
                return
            timeout = self.AUTO_LOCK_OPTIONS.get(self.auto_lock_var.get(), 0)
            if timeout > 0:
                elapsed = (datetime.now() - self.last_activity).total_seconds()
                if elapsed >= timeout:
                    self.lock_app()
            self.root.after(5000, check_lock)
        self.root.after(5000, check_lock)

    def lock_app(self):
        if self.locked:
            return
        self.locked = True
        self.lock_overlay = tk.Toplevel(self.root)
        self.lock_overlay.transient(self.root)
        self.lock_overlay.grab_set()
        self.lock_overlay.title('Locked')
        self.lock_overlay.geometry('300x150')
        self.lock_overlay.resizable(False, False)
        
        ttk.Label(self.lock_overlay, text='Application Locked', font=('Segoe UI', 14, 'bold')).pack(pady=10)
        ttk.Label(self.lock_overlay, text='Enter master password to unlock:').pack()
        
        pw_var = tk.StringVar()
        pw_entry = ttk.Entry(self.lock_overlay, textvariable=pw_var, show='*', width=30)
        pw_entry.pack(pady=10)
        pw_entry.focus_set()
        
        def unlock():
            try:
                test_enc = EncryptionManager(pw_var.get())
                self.locked = False
                self.last_activity = datetime.now()
                self.lock_overlay.destroy()
            except Exception:
                messagebox.showerror('Error', 'Invalid password', parent=self.lock_overlay)
        
        ttk.Button(self.lock_overlay, text='Unlock', command=unlock).pack(pady=5)
        pw_entry.bind('<Return>', lambda e: unlock())

    def start_tray_if_available(self):
        try:
            from gui.tray import start_tray, pystray
            if pystray:
                def run_tray():
                    start_tray({
                        'Show': lambda: self.root.deiconify(),
                        'Lock': lambda: self.root.after(0, self.lock_app),
                        'Exit': lambda: self.root.after(0, self.root.quit)
                    })
                tray_thread = threading.Thread(target=run_tray, daemon=True)
                tray_thread.start()
        except Exception:
            pass

    def build_ui(self):
        container = ttk.Frame(self.root)
        container.pack(fill='both', expand=True)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(container, width=200, padding=10)
        sidebar.grid(row=0, column=0, sticky='nsw')

        ttk.Label(sidebar, text='Sequential', font=('Segoe UI', 14, 'bold')).pack(pady=(4, 12))
        
        ttk.Button(sidebar, text='Profiles', command=self.show_profiles).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Audit Log', command=self.show_audit).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Backups', command=self.show_backups).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Categories', command=self.show_categories).pack(fill='x', pady=2)
        ttk.Separator(sidebar).pack(fill='x', pady=8)
        ttk.Button(sidebar, text='Rotate Password', command=self.rotate_master_password).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Create Backup', command=self.create_backup).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Restore Backup', command=self.restore_backup).pack(fill='x', pady=2)
        ttk.Separator(sidebar).pack(fill='x', pady=8)
        ttk.Button(sidebar, text='Import CSV', command=self.import_csv).pack(fill='x', pady=2)
        ttk.Button(sidebar, text='Migrate FS to DB', command=self.migrate_filesystem).pack(fill='x', pady=2)
        
        ttk.Separator(sidebar).pack(fill='x', pady=8)
        ttk.Label(sidebar, text='Settings', font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        
        ttk.Label(sidebar, text='Theme:').pack(anchor='w', pady=(4, 0))
        theme_combo = ttk.Combobox(sidebar, textvariable=self.theme_var, values=self.THEMES, state='readonly', width=15)
        theme_combo.pack(fill='x')
        theme_combo.bind('<<ComboboxSelected>>', self.change_theme)
        
        ttk.Label(sidebar, text='Auto-lock:').pack(anchor='w', pady=(8, 0))
        lock_combo = ttk.Combobox(sidebar, textvariable=self.auto_lock_var, 
                                  values=list(self.AUTO_LOCK_OPTIONS.keys()), state='readonly', width=15)
        lock_combo.pack(fill='x')
        lock_combo.bind('<<ComboboxSelected>>', self.save_auto_lock_setting)

        main = ttk.Frame(container, padding=12)
        main.grid(row=0, column=1, sticky='nsew')
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(1, weight=1)

        search_frame = ttk.Frame(main)
        search_frame.grid(row=0, column=0, columnspan=2, sticky='we', pady=(0, 8))
        ttk.Label(search_frame, text='Search:').pack(side='left')
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side='left', padx=5)
        self.search_var.trace('w', lambda *_: self.refresh_credential_list())

        list_frame = ttk.LabelFrame(main, text='Credentials', padding=5)
        list_frame.grid(row=1, column=0, sticky='nsew', padx=(0, 8))
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        self.cred_tree = ttk.Treeview(list_frame, columns=('provider', 'config', 'fav', 'expiry'), show='headings', selectmode='browse')
        self.cred_tree.heading('provider', text='Provider')
        self.cred_tree.heading('config', text='Name')
        self.cred_tree.heading('fav', text='Fav')
        self.cred_tree.heading('expiry', text='Expires')
        self.cred_tree.column('provider', width=80)
        self.cred_tree.column('config', width=100)
        self.cred_tree.column('fav', width=30)
        self.cred_tree.column('expiry', width=80)
        self.cred_tree.grid(row=0, column=0, sticky='nsew')
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.cred_tree.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.cred_tree.configure(yscrollcommand=scrollbar.set)
        self.cred_tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        cat_frame = ttk.Frame(list_frame)
        cat_frame.grid(row=1, column=0, columnspan=2, sticky='we', pady=(5, 0))
        ttk.Label(cat_frame, text='Category:').pack(side='left')
        self.category_combo = ttk.Combobox(cat_frame, textvariable=self.category_var, state='readonly', width=12)
        self.category_combo.pack(side='left', padx=5)
        self.category_var.trace('w', lambda *_: self.refresh_credential_list())

        detail_frame = ttk.LabelFrame(main, text='Details', padding=10)
        detail_frame.grid(row=1, column=1, sticky='nsew')
        detail_frame.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(detail_frame, text='Provider:', font=('Segoe UI', 10, 'bold')).grid(row=row, column=0, sticky='w')
        self.provider_combo = ttk.Combobox(detail_frame, textvariable=self.provider_var, 
                                           values=['Discord', 'OpenAI', 'Google', 'GitHub', 'Slack', 'AWS', 'Azure', 'Other'], 
                                           state='readonly')
        self.provider_combo.grid(row=row, column=1, sticky='we', pady=2)

        row += 1
        ttk.Label(detail_frame, text='Name:', font=('Segoe UI', 10, 'bold')).grid(row=row, column=0, sticky='w')
        self.config_entry = ttk.Entry(detail_frame, textvariable=self.config_var, width=30)
        self.config_entry.grid(row=row, column=1, sticky='we', pady=2)

        row += 1
        ttk.Label(detail_frame, text='Token/Key:', font=('Segoe UI', 10, 'bold')).grid(row=row, column=0, sticky='w')
        token_frame = ttk.Frame(detail_frame)
        token_frame.grid(row=row, column=1, sticky='we', pady=2)
        token_frame.columnconfigure(0, weight=1)
        self.data_entry = ttk.Entry(token_frame, textvariable=self.data_var, show='*')
        self.data_entry.grid(row=0, column=0, sticky='we')
        self.toggle_btn = ttk.Button(token_frame, text='Show', width=6, command=self.toggle_visibility)
        self.toggle_btn.grid(row=0, column=1, padx=(4, 0))
        ttk.Button(token_frame, text='Copy', width=6, command=self.copy_to_clipboard).grid(row=0, column=2, padx=(4, 0))

        row += 1
        ttk.Label(detail_frame, text='Notes:', font=('Segoe UI', 10, 'bold')).grid(row=row, column=0, sticky='nw')
        self.notes_text = tk.Text(detail_frame, height=3, width=30)
        self.notes_text.grid(row=row, column=1, sticky='we', pady=2)

        row += 1
        ttk.Label(detail_frame, text='Expires:', font=('Segoe UI', 10, 'bold')).grid(row=row, column=0, sticky='w')
        expiry_frame = ttk.Frame(detail_frame)
        expiry_frame.grid(row=row, column=1, sticky='we', pady=2)
        self.expiry_entry = ttk.Entry(expiry_frame, textvariable=self.expiry_var, width=20)
        self.expiry_entry.pack(side='left')
        ttk.Label(expiry_frame, text='(YYYY-MM-DD)').pack(side='left', padx=5)

        row += 1
        options_frame = ttk.Frame(detail_frame)
        options_frame.grid(row=row, column=0, columnspan=2, sticky='we', pady=8)
        ttk.Checkbutton(options_frame, text='Favorite', variable=self.favorite_var).pack(side='left')
        ttk.Checkbutton(options_frame, text='Store in DB', variable=self.store_in_db).pack(side='left', padx=20)

        row += 1
        btn_frame = ttk.Frame(detail_frame)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text='Save (Ctrl+S)', command=self.on_save).grid(row=0, column=0, padx=4)
        ttk.Button(btn_frame, text='Delete', command=self.on_delete).grid(row=0, column=1, padx=4)
        ttk.Button(btn_frame, text='New', command=self.clear_selection).grid(row=0, column=2, padx=4)

        row += 1
        export_frame = ttk.Frame(detail_frame)
        export_frame.grid(row=row, column=0, columnspan=2, pady=4)
        ttk.Button(export_frame, text='Export', command=self.export_configs).grid(row=0, column=0, padx=4)
        ttk.Button(export_frame, text='Import', command=self.import_configs).grid(row=0, column=1, padx=4)

        self.status_var = tk.StringVar(value='Ready - Press Ctrl+S to save, Ctrl+C to copy')
        status = ttk.Label(self.root, textvariable=self.status_var, relief='sunken', anchor='w')
        status.pack(side='bottom', fill='x')

    def change_theme(self, event=None):
        theme = self.theme_var.get()
        self.db.set_setting('theme', theme)
        if self.style:
            try:
                self.style.theme_use(theme)
            except Exception:
                pass

    def save_auto_lock_setting(self, event=None):
        self.db.set_setting('auto_lock', self.auto_lock_var.get())

    def refresh_categories(self):
        categories = self.db.list_categories()
        self.category_combo['values'] = categories
        if categories and self.category_var.get() not in categories:
            self.category_var.set(categories[0])

    def refresh_credential_list(self):
        for item in self.cred_tree.get_children():
            self.cred_tree.delete(item)
        
        search_query = self.search_var.get().strip()
        category = self.category_var.get()
        
        if search_query:
            entries = self.db.search_entries(search_query)
        else:
            entries = self.db.get_all_entries(category if category else None)
        
        for entry in entries:
            fav = '*' if entry.get('favorite') else ''
            expiry = entry.get('expires_at', '')
            if expiry:
                try:
                    exp_date = datetime.fromisoformat(expiry.replace('Z', ''))
                    days = (exp_date - datetime.utcnow()).days
                    if days < 0:
                        expiry = 'EXPIRED'
                    elif days <= 7:
                        expiry = f'{days}d left'
                    else:
                        expiry = exp_date.strftime('%Y-%m-%d')
                except Exception:
                    pass
            
            self.cred_tree.insert('', 'end', values=(
                entry['provider'],
                entry['config_name'],
                fav,
                expiry
            ), tags=(entry['category'],))

    def on_tree_select(self, event=None):
        selection = self.cred_tree.selection()
        if not selection:
            return
        
        item = self.cred_tree.item(selection[0])
        values = item['values']
        tags = item['tags']
        
        provider = values[0]
        config_name = values[1]
        category = tags[0] if tags else self.category_var.get()
        
        self.selected_entry = {'category': category, 'provider': provider, 'config_name': config_name}
        
        self.provider_var.set(provider)
        self.config_var.set(config_name)
        self.category_var.set(category)
        
        blob_entry = self.db.get_blob_entry(category, provider, config_name)
        if blob_entry and blob_entry.get('blob'):
            try:
                data = self.encryption.decrypt(base64.b64decode(blob_entry['blob']))
                self.data_var.set(data)
                self.store_in_db.set(True)
            except Exception:
                self.data_var.set('')
                self.store_in_db.set(True)
        else:
            token = self.cfg.load_from_filesystem(category, provider, config_name)
            self.data_var.set(token or '')
            self.store_in_db.set(False)
            self.db.sync_filesystem_entry(category, provider, config_name, has_credential=token is not None)
        
        entries = self.db.get_all_entries(category)
        for e in entries:
            if e['provider'] == provider and e['config_name'] == config_name:
                self.favorite_var.set(e.get('favorite', False))
                self.notes_text.delete('1.0', 'end')
                self.notes_text.insert('1.0', e.get('notes', ''))
                self.expiry_var.set(e.get('expires_at', '') or '')
                break

    def clear_selection(self):
        self.selected_entry = None
        self.cred_tree.selection_remove(self.cred_tree.selection())
        self.config_var.set('')
        self.data_var.set('')
        self.notes_text.delete('1.0', 'end')
        self.expiry_var.set('')
        self.favorite_var.set(False)
        self.config_entry.focus_set()

    def copy_to_clipboard(self):
        value = self.data_var.get()
        if value:
            secure_copy(value, timeout=30)
            self.set_status('Copied to clipboard (auto-clears in 30s)')
            self.audit.log_event('clipboard_copy', {'provider': self.provider_var.get()})
        else:
            self.set_status('Nothing to copy')

    def set_status(self, text: str):
        self.status_var.set(text)

    def toggle_visibility(self):
        if self.show_data.get():
            self.data_entry.config(show='*')
            self.toggle_btn.config(text='Show')
        else:
            self.data_entry.config(show='')
            self.toggle_btn.config(text='Hide')
        self.show_data.set(not self.show_data.get())

    def show_profiles(self):
        pm = tk.Toplevel(self.root)
        pm.title('Profiles')
        pm.geometry('300x200')
        ttk.Label(pm, text='Profiles', font=('Segoe UI', 12, 'bold')).pack(pady=6)
        from core.profiles import ProfileManager
        mgr = ProfileManager()
        for p in mgr.list_profiles():
            ttk.Label(pm, text=p).pack()

    def show_audit(self):
        logs = self.audit.read_recent(100)
        dlg = tk.Toplevel(self.root)
        dlg.title('Audit Log')
        dlg.geometry('800x400')
        txt = tk.Text(dlg, wrap='none', height=30, width=120)
        txt.pack(fill='both', expand=True)
        for entry in logs:
            txt.insert('end', f"{entry['timestamp']} {entry['event']} {entry.get('meta', {})}\n")

    def show_backups(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Backups')
        dlg.geometry('500x300')
        lst = tk.Listbox(dlg, width=80)
        lst.pack(fill='both', expand=True)
        for b in self.backup.list_backups():
            lst.insert('end', b)

    def show_categories(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Manage Categories')
        dlg.geometry('300x250')
        
        ttk.Label(dlg, text='Categories', font=('Segoe UI', 12, 'bold')).pack(pady=6)
        
        listbox = tk.Listbox(dlg, width=30, height=8)
        listbox.pack(fill='both', expand=True, padx=10)
        
        for cat in self.db.list_categories():
            listbox.insert('end', cat)
        
        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=10)
        
        def add_category():
            cat_dlg = CategoryDialog(dlg, title='Add Category')
            if cat_dlg.result:
                self.db.add_category(cat_dlg.result)
                listbox.insert('end', cat_dlg.result)
                self.refresh_categories()
        
        def delete_category():
            sel = listbox.curselection()
            if sel:
                cat = listbox.get(sel[0])
                if cat in ('tokens', 'apis'):
                    messagebox.showwarning('Warning', 'Cannot delete default categories', parent=dlg)
                    return
                if messagebox.askyesno('Confirm', f'Delete category "{cat}"?', parent=dlg):
                    self.db.delete_category(cat)
                    listbox.delete(sel[0])
                    self.refresh_categories()
        
        ttk.Button(btn_frame, text='Add', command=add_category).pack(side='left', padx=5)
        ttk.Button(btn_frame, text='Delete', command=delete_category).pack(side='left', padx=5)

    def check_expiring_credentials(self):
        expiring = self.db.get_expiring_entries(days=7)
        if expiring:
            msg = "The following credentials are expiring soon:\n\n"
            for e in expiring[:5]:
                days = e['days_remaining']
                if days < 0:
                    status = "EXPIRED"
                elif days == 0:
                    status = "TODAY"
                else:
                    status = f"in {days} days"
                msg += f"- {e['provider']}/{e['config_name']}: {status}\n"
            if len(expiring) > 5:
                msg += f"\n...and {len(expiring) - 5} more"
            messagebox.showwarning('Expiring Credentials', msg)

    def on_save(self):
        value = self.data_var.get().strip()
        cfg = self.config_var.get().strip()
        category = self.category_var.get()
        provider = self.provider_var.get()
        
        if not cfg:
            messagebox.showwarning('Missing', 'Provide a configuration name')
            return
        
        valid = True
        msg = ''
        if provider.lower() == 'discord' and value:
            valid, msg = validate_discord_token(value)
        elif provider.lower() == 'github' and value:
            valid, msg = validate_github_token(value)
        if not valid and value:
            if not messagebox.askyesno('Validation failed', f"Validation failed: {msg}\nSave anyway?"):
                return

        is_existing = self.selected_entry is not None
        has_existing_blob = False
        
        if is_existing:
            existing_blob = self.db.get_blob_entry(category, provider, cfg)
            has_existing_blob = existing_blob and existing_blob.get('blob')
            if not has_existing_blob:
                existing_token = self.cfg.load_from_filesystem(category, provider, cfg)
                has_existing_blob = existing_token is not None

        if value:
            encrypted = self.encryption.encrypt(value)
            if self.store_in_db.get():
                blob = base64.b64encode(encrypted).decode('utf-8')
                meta = {'blob': blob}
                self.db.set_blob(category, provider, cfg, meta)
            else:
                path_meta = self.cfg.save_to_filesystem(category, provider, cfg, encrypted)
                self.db.set(category, f"{provider}_{cfg}", path_meta)
        elif not is_existing:
            self.db.set(category, f"{provider}_{cfg}", {'placeholder': True})

        notes = self.notes_text.get('1.0', 'end').strip()
        expiry = self.expiry_var.get().strip()
        favorite = self.favorite_var.get()
        
        self.db.set_favorite(category, provider, cfg, favorite)
        self.db.set_notes(category, provider, cfg, notes)
        self.db.set_expiry(category, provider, cfg, expiry if expiry else None)

        self.audit.log_event('save', {'category': category, 'provider': provider, 'config': cfg})
        self.set_status(f"Saved {cfg}")
        messagebox.showinfo('Saved', f'Saved {cfg}')
        self.refresh_credential_list()

    def on_delete(self):
        cfg = self.config_var.get()
        category = self.category_var.get()
        provider = self.provider_var.get()
        
        if not cfg:
            return
            
        if messagebox.askyesno('Confirm', f'Delete {cfg}?'):
            self.db.delete(category, f"{provider}_{cfg}")
            self.cfg.delete_filesystem(category, provider, cfg)
            self.audit.log_event('delete', {'category': category, 'provider': provider, 'config': cfg})
            messagebox.showinfo('Deleted', f'Deleted {cfg}')
            self.clear_selection()
            self.refresh_credential_list()

    def export_configs(self):
        data = self.db.export_provider(self.category_var.get(), self.provider_var.get())
        if not data:
            messagebox.showinfo('Export', 'No configurations found')
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.seqcfg')
        if not file_path:
            return
        self.db.export_to_file(data, file_path)
        self.audit.log_event('export', {'path': file_path})
        messagebox.showinfo('Export', 'Export complete')

    def import_configs(self):
        file_path = filedialog.askopenfilename(filetypes=[('Sequential Config', '*.seqcfg')])
        if not file_path:
            return
        self.db.import_from_file(file_path)
        self.audit.log_event('import', {'path': file_path})
        messagebox.showinfo('Import', 'Import complete')
        self.refresh_credential_list()

    def import_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[('CSV files', '*.csv')])
        if not file_path:
            return
        try:
            count = self.db.import_from_csv(file_path, self.category_var.get())
            self.audit.log_event('import_csv', {'path': file_path, 'count': count})
            messagebox.showinfo('Import', f'Imported {count} entries from CSV')
            self.refresh_credential_list()
        except Exception as e:
            messagebox.showerror('Error', f'Failed to import CSV: {e}')

    def migrate_filesystem(self):
        migrated = migrate_filesystem_to_db(self.db, self.cfg)
        self.audit.log_event('migrate', {'migrated': migrated})
        messagebox.showinfo('Migrate', f'Migrated {migrated} entries from filesystem to DB')
        self.refresh_credential_list()

    def rotate_master_password(self):
        dlg = RotatePasswordDialog(self.root, title='Rotate Master Password')
        res = dlg.result
        if not res:
            return
        old_pw, new_pw = res
        
        score, _ = check_password_strength(new_pw)
        if score < 3:
            if not messagebox.askyesno('Weak Password', 'The new password is weak. Continue anyway?'):
                return
        
        try:
            self.encryption.rotate_master_password(old_pw, new_pw, self.db, self.cfg)
            self.audit.log_event('rotate_master', {})
            messagebox.showinfo('Success', 'Master password rotated successfully')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to rotate master password: {e}')

    def create_backup(self):
        path = self.backup.create_backup()
        self.audit.log_event('backup_create', {'path': path})
        messagebox.showinfo('Backup', f'Backup created: {path}')

    def restore_backup(self):
        file_path = filedialog.askopenfilename(filetypes=[('Backup', '*.seqbackup')])
        if not file_path:
            return
        self.backup.restore_backup(file_path)
        self.audit.log_event('backup_restore', {'path': file_path})
        messagebox.showinfo('Restore', 'Backup restored')
        self.refresh_credential_list()
