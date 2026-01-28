import sqlite3
import time
import pickle
import threading
import os
import bcrypt
import pandas as pd
import customtkinter as ctk
from pynput import keyboard
from sklearn.ensemble import IsolationForest
from tkinter import messagebox, filedialog, simpledialog
from cryptography.fernet import Fernet
import base64
import secrets
import string
import json
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip
from typing import Optional, List, Any, Tuple

# --- CONFIGURATION ---
DB_NAME = "secure_auth.db"
MIN_SAMPLES = 20          
LOCKOUT_THRESHOLD = 3
LOCKOUT_TIME = 30
CLIPBOARD_TIMEOUT = 30    
APP_VERSION = "1.0-Lokey"

# --- THEME (ORIGINAL DARK UI) ---
class Theme:
    BG_PRIMARY = "#0a0e27"
    BG_SECONDARY = "#151932"
    BG_CARD = "#1e2139"
    ACCENT_GREEN = "#00ff88"
    ACCENT_BLUE = "#00d4ff"
    ACCENT_PURPLE = "#a78bfa"
    ACCENT_RED = "#ff4444"
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#9ca3af"
    TEXT_MUTED = "#6b7280"
    SUCCESS = "#10b981"
    ERROR = "#ef4444"
    WARNING = "#f59e0b"
    INFO = "#3b82f6"

# --- DATABASE MANAGER (THREAD-SAFE) ---
class DatabaseManager:
    def __init__(self):
        self.lock = threading.Lock() 
        self.conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.create_tables()

    def create_tables(self):
        with self.lock, self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, password_hash BYTES, recovery_hash BYTES, 
                enc_salt BYTES, model_blob BYTES, is_trained BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS vault_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, site_name TEXT, 
                site_user TEXT, encrypted_pass BYTES, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    def add_user(self, u, p, r):
        ps = bcrypt.gensalt(); ph = bcrypt.hashpw(p.encode(), ps)
        rs = bcrypt.gensalt(); rh = bcrypt.hashpw(r.encode(), rs)
        es = os.urandom(16)
        try:
            with self.lock, self.conn: 
                self.conn.execute("INSERT INTO users VALUES (?,?,?,?,?,0,CURRENT_TIMESTAMP)", (u, ph, rh, es, None))
            return True
        except: return False

    def verify_password(self, u, p):
        with self.lock:
            cur = self.conn.execute("SELECT password_hash FROM users WHERE username=?", (u,))
            res = cur.fetchone()
        if not res: return False
        try: return bcrypt.checkpw(p.encode(), res[0])
        except: return False

    def verify_recovery(self, u, r):
        with self.lock:
            cur = self.conn.execute("SELECT recovery_hash FROM users WHERE username=?", (u,))
            res = cur.fetchone()
        return bcrypt.checkpw(r.encode(), res[0]) if res else False

    def get_enc_salt(self, u):
        with self.lock:
            cur = self.conn.execute("SELECT enc_salt FROM users WHERE username=?", (u,))
            res = cur.fetchone()
        return res[0] if res else None

    def save_model(self, u, m):
        with self.lock, self.conn: 
            self.conn.execute("UPDATE users SET model_blob=?, is_trained=1 WHERE username=?", (pickle.dumps(m), u))

    def load_model(self, u):
        with self.lock:
            cur = self.conn.execute("SELECT model_blob FROM users WHERE username=?", (u,))
            res = cur.fetchone()
        return pickle.loads(res[0]) if res and res[0] else None

    def is_user_trained(self, u):
        with self.lock:
            cur = self.conn.execute("SELECT is_trained FROM users WHERE username=?", (u,))
            res = cur.fetchone()
        return res[0] if res else False
    
    def add_cred(self, o, s, u, p):
        with self.lock, self.conn: 
            self.conn.execute("INSERT INTO vault_credentials (owner, site_name, site_user, encrypted_pass) VALUES (?,?,?,?)", (o,s,u,p))
    
    def get_creds(self, o):
        with self.lock:
            return self.conn.execute("SELECT id, site_name, site_user, encrypted_pass FROM vault_credentials WHERE owner=?", (o,)).fetchall()
    
    def del_cred(self, cid):
        with self.lock, self.conn: 
            self.conn.execute("DELETE FROM vault_credentials WHERE id=?", (cid,))

# --- BIOMETRIC SENSOR (SMART FILTERING) ---
class BiometricSensor:
    def __init__(self, visual_callback=None):
        self.key_press_times = {}
        self.dwell_times = []
        self.visual_callback = visual_callback 
        self.running = False
        self.listener = None
        self.start_background_listener()

    def start_background_listener(self):
        if self.listener: self.listener.stop()
        self.listener = keyboard.Listener(on_press=self.on_press, on_release=self.on_release)
        self.listener.start()

    def start(self):
        self.key_press_times = {}
        self.dwell_times = []
        self.running = True

    def stop(self):
        self.running = False
        
    def get_key_id(self, key):
        if hasattr(key, 'char') and key.char: return key.char
        return str(key)

    def is_valid_key(self, key):
        """Ignore purely modifier keys to prevent length mismatch bugs"""
        block = [keyboard.Key.shift, keyboard.Key.shift_r, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r,
                 keyboard.Key.alt_l, keyboard.Key.alt_r, keyboard.Key.caps_lock, keyboard.Key.tab]
        return key not in block

    def on_press(self, key):
        if not self.running or not self.is_valid_key(key): return
        if key == keyboard.Key.enter: return 

        key_id = self.get_key_id(key)
        self.key_press_times[key_id] = time.time()
        if self.visual_callback: self.visual_callback(True)
        
        if key == keyboard.Key.backspace:
            self.dwell_times = []
            self.key_press_times = {}

    def on_release(self, key):
        if not self.running or not self.is_valid_key(key): return
        if key == keyboard.Key.enter: return
        
        if self.visual_callback: self.visual_callback(False)
        key_id = self.get_key_id(key)
        press_time = self.key_press_times.get(key_id, 0)
        
        if press_time > 0:
            dwell = time.time() - press_time
            self.dwell_times.append(dwell)
            if key_id in self.key_press_times: del self.key_press_times[key_id] 

    def get_vector(self, expected_len):
        if len(self.dwell_times) == expected_len: return self.dwell_times
        return None

# --- CRYPTO VAULT (ATOMIC) ---
class CryptoVault:
    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def derive_backup_key(self, password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
        return kdf.derive(password.encode())

    def encrypt_data(self, txt, key): return Fernet(key).encrypt(txt.encode())
    def decrypt_data(self, txt, key): return Fernet(key).decrypt(txt).decode()
    
    def encrypt_file(self, path, key):
        temp_path = path + ".tmp"
        try:
            with open(path, 'rb') as f: d = f.read()
            with open(temp_path, 'wb') as f: f.write(Fernet(key).encrypt(d))
            final_path = path + ".locked"
            if os.path.exists(final_path): os.remove(final_path)
            os.rename(temp_path, final_path); os.remove(path)
        except Exception as e:
            if os.path.exists(temp_path): os.remove(temp_path)
            raise e

    def decrypt_file(self, path, key):
        temp_path = path + ".tmp"
        try:
            with open(path, 'rb') as f: d = f.read()
            with open(temp_path, 'wb') as f: f.write(Fernet(key).decrypt(d))
            final_path = path.replace(".locked","")
            if os.path.exists(final_path): os.remove(final_path)
            os.rename(temp_path, final_path); os.remove(path)
        except Exception as e:
            if os.path.exists(temp_path): os.remove(temp_path)
            raise e

# --- UI COMPONENTS ---
class AnimatedProgressBar(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.bg = ctk.CTkFrame(self, height=8, corner_radius=4, fg_color=Theme.BG_CARD)
        self.bg.pack(fill="x", pady=5)
        self.fill = ctk.CTkFrame(self.bg, height=8, corner_radius=4, fg_color=Theme.ACCENT_GREEN)
        self.fill.place(relx=0, rely=0, relheight=1, relwidth=0)
    def set(self, val): self.animate(max(0, min(1, val)))
    def animate(self, target):
        cur = self.fill.winfo_width() / self.bg.winfo_width() if self.bg.winfo_width() > 0 else 0
        if abs(cur - target) < 0.01: self.fill.place(relwidth=target); return
        self.fill.place(relwidth=min(cur + ((target-cur)*0.3), 1))
        self.after(20, lambda: self.animate(target))

class ModernButton(ctk.CTkButton):
    def __init__(self, master, **kwargs):
        dk = {"corner_radius": 8, "border_width": 0, "font": ("Segoe UI", 13, "bold"), "height": 42}
        dk.update(kwargs)
        super().__init__(master, **dk)

# --- MAIN APP ---
class AuthApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.sensor = BiometricSensor(visual_callback=self.pulse_indicator)
        self.vault = CryptoVault()
        self.training_buffer = []
        self.failed_attempts = 0
        self.vault_key = None 
        self.current_username = None
        self.temp_password = None 
        
        self.title(f"Lokey v{APP_VERSION}")
        self.geometry("950x850")
        ctk.set_appearance_mode("Dark")
        self._set_appearance_mode("Dark")
        self.configure(fg_color=Theme.BG_PRIMARY)
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.create_header()
        self.create_main_container()
        self.setup_login_ui()
    
    def create_header(self):
        header = ctk.CTkFrame(self, height=80, corner_radius=0, fg_color=Theme.BG_SECONDARY)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=30, pady=20)
        ctk.CTkLabel(title_frame, text="🔒", font=("Segoe UI Emoji", 32)).pack(side="left", padx=(0, 15))
        
        text_container = ctk.CTkFrame(title_frame, fg_color="transparent")
        text_container.pack(side="left")
        ctk.CTkLabel(text_container, text="LOKEY", font=("Segoe UI", 24, "bold"), text_color=Theme.TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(text_container, text="Biometric Authentication", font=("Segoe UI", 11), text_color=Theme.TEXT_SECONDARY).pack(anchor="w")
        
        version_badge = ctk.CTkFrame(header, fg_color=Theme.ACCENT_PURPLE, corner_radius=12)
        version_badge.pack(side="right", padx=30)
        ctk.CTkLabel(version_badge, text=f"v{APP_VERSION}", font=("Segoe UI", 11, "bold"), text_color=Theme.TEXT_PRIMARY).pack(padx=12, pady=6)

    def create_main_container(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
    
    def on_closing(self):
        if self.sensor.listener: self.sensor.listener.stop()
        self.destroy()

    def setup_login_ui(self):
        self.clear_frame(self.main_frame)
        self.vault_key = None 
        self.current_username = None
        self.temp_password = None
        
        center = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        center.grid(row=0, column=0)
        
        card = ctk.CTkFrame(center, fg_color=Theme.BG_SECONDARY, corner_radius=16, width=480)
        card.pack(padx=20, pady=20, ipadx=10, ipady=10)
        
        self.tab_frame = ctk.CTkFrame(card, fg_color=Theme.BG_CARD, corner_radius=12, height=50)
        self.tab_frame.pack(fill="x", padx=20, pady=(20, 10))
        self.tab_frame.pack_propagate(False)
        
        self.login_tab_btn = ModernButton(self.tab_frame, text="LOGIN", fg_color=Theme.ACCENT_BLUE, hover_color=Theme.ACCENT_PURPLE, command=lambda: self.switch_tab("login"))
        self.login_tab_btn.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        self.register_tab_btn = ModernButton(self.tab_frame, text="REGISTER", fg_color=Theme.BG_CARD, hover_color=Theme.ACCENT_PURPLE, command=lambda: self.switch_tab("register"))
        self.register_tab_btn.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        self.tab_content = ctk.CTkFrame(card, fg_color="transparent")
        self.tab_content.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.current_tab = "login"
        self.show_login_tab()
    
    def switch_tab(self, tab):
        if tab == self.current_tab: return
        self.current_tab = tab
        self.clear_frame(self.tab_content)
        
        if tab == "login":
            self.login_tab_btn.configure(fg_color=Theme.ACCENT_BLUE)
            self.register_tab_btn.configure(fg_color=Theme.BG_CARD)
            self.show_login_tab()
        else:
            self.login_tab_btn.configure(fg_color=Theme.BG_CARD)
            self.register_tab_btn.configure(fg_color=Theme.ACCENT_BLUE)
            self.show_register_tab()
    
    def show_login_tab(self):
        ctk.CTkLabel(self.tab_content, text="Welcome Back", font=("Segoe UI", 22, "bold"), text_color=Theme.TEXT_PRIMARY).pack(pady=(10, 5))
        ctk.CTkLabel(self.tab_content, text="Authenticate with your biometric signature", font=("Segoe UI", 11), text_color=Theme.TEXT_SECONDARY).pack(pady=(0, 20))
        
        self.user_entry = self.create_modern_entry(self.tab_content, "👤 Username", width=400)
        self.pass_entry = self.create_modern_entry(self.tab_content, "🔑 Password", width=400, show="•")
        self.pass_entry.bind("<FocusIn>", lambda e: self.sensor.start())
        
        ind = ctk.CTkFrame(self.tab_content, fg_color="transparent", height=40)
        ind.pack(pady=15)
        ctk.CTkLabel(ind, text="Biometric Sensor:", font=("Segoe UI", 10), text_color=Theme.TEXT_SECONDARY).pack(side="left", padx=(0, 10))
        self.indicator_dot = ctk.CTkFrame(ind, width=12, height=12, corner_radius=6, fg_color=Theme.BG_CARD, border_width=2, border_color=Theme.TEXT_MUTED); self.indicator_dot.pack(side="left")
        
        ModernButton(self.tab_content, text="AUTHENTICATE", fg_color=Theme.ACCENT_GREEN, hover_color=Theme.SUCCESS, width=400, height=50, font=("Segoe UI", 14, "bold"), command=self.perform_login).pack(pady=10)
        ctk.CTkButton(self.tab_content, text="Use Recovery Key", fg_color="transparent", hover_color=Theme.BG_CARD, text_color=Theme.ACCENT_RED, font=("Segoe UI", 10, "bold"), width=120, height=28, command=self.emergency_login_dialog).pack(pady=5)
        self.status_msg = ctk.CTkLabel(self.tab_content, text="", font=("Segoe UI", 11), text_color=Theme.TEXT_SECONDARY); self.status_msg.pack(pady=10)

    # --- WIZARD FLOW (WIZARD REGISTRATION) ---
    def show_register_tab(self):
        # Step 1
        ctk.CTkLabel(self.tab_content, text="Create Account", font=("Segoe UI", 22, "bold"), text_color=Theme.TEXT_PRIMARY).pack(pady=(10, 5))
        ctk.CTkLabel(self.tab_content, text="Step 1: Credentials", font=("Segoe UI", 11, "bold"), text_color=Theme.ACCENT_BLUE).pack(pady=(0, 20))
        
        self.reg_user = self.create_modern_entry(self.tab_content, "Username", width=400)
        self.reg_pass = self.create_modern_entry(self.tab_content, "Password", width=400, show="•")
        
        ModernButton(self.tab_content, text="NEXT ➜", fg_color=Theme.ACCENT_BLUE, hover_color=Theme.ACCENT_PURPLE, width=400, command=self.create_user).pack(pady=20)

    def show_training_step(self):
        # Step 2
        self.clear_frame(self.tab_content)
        ctk.CTkLabel(self.tab_content, text="Biometric Training", font=("Segoe UI", 22, "bold"), text_color=Theme.TEXT_PRIMARY).pack(pady=(10, 5))
        ctk.CTkLabel(self.tab_content, text=f"Type '{self.current_reg_pwd}' 20 times", font=("Segoe UI", 14, "bold"), text_color=Theme.ACCENT_PURPLE).pack(pady=(0, 10))
        
        self.train_lbl = ctk.CTkLabel(self.tab_content, text=f"0 / {MIN_SAMPLES} samples", font=("Segoe UI", 12, "bold"), text_color=Theme.TEXT_PRIMARY); self.train_lbl.pack(pady=5)
        self.train_progress = AnimatedProgressBar(self.tab_content, width=400); self.train_progress.pack(pady=5)
        
        self.train_input = self.create_modern_entry(self.tab_content, "Type password & hit Enter...", width=400, show="•")
        self.train_input.bind("<Return>", self.record_sample)
        self.train_input.bind("<FocusIn>", lambda e: self.sensor.start())
        
        self.after(100, lambda: self.train_input.focus_set() if self.train_input.winfo_exists() else None)
        
        ctk.CTkLabel(self.tab_content, text="Tip: Type naturally. Don't rush.", font=("Segoe UI", 10), text_color=Theme.TEXT_MUTED).pack(pady=20)

    def create_modern_entry(self, parent, placeholder, width=300, show=None):
        e = ctk.CTkEntry(parent, placeholder_text=placeholder, width=width, height=45, corner_radius=8, border_width=2, border_color=Theme.BG_CARD, fg_color=Theme.BG_CARD, text_color=Theme.TEXT_PRIMARY, placeholder_text_color=Theme.TEXT_MUTED, font=("Segoe UI", 12))
        if show: e.configure(show=show)
        e.pack(pady=8)
        return e
    
    def pulse_indicator(self, active):
        try: self.indicator_dot.configure(fg_color=Theme.ACCENT_GREEN if active else Theme.BG_CARD, border_color=Theme.ACCENT_GREEN if active else Theme.TEXT_MUTED)
        except: pass

    # --- LOGIC ---
    def generate_recovery_key(self):
        chars = string.ascii_uppercase + string.digits
        return f"REC-{ ''.join(secrets.choice(chars) for _ in range(4)) }-{ ''.join(secrets.choice(chars) for _ in range(4)) }"

    def create_user(self):
        user, pwd = self.reg_user.get(), self.reg_pass.get()
        if not user or not pwd: 
            messagebox.showerror("Error", "Please fill all fields")
            return
        rec_key = self.generate_recovery_key()
        if self.db.add_user(user, pwd, rec_key):
            self.show_recovery_popup(rec_key)
            self.current_reg_user = user
            self.current_reg_pwd = pwd
            self.training_buffer = []
            self.show_training_step()
        else:
            messagebox.showerror("Error", "Username already taken")

    def show_recovery_popup(self, key):
        popup = ctk.CTkToplevel(self); popup.title("Recovery Key"); popup.geometry("500x400"); popup.configure(fg_color=Theme.BG_PRIMARY)
        popup.transient(self); popup.grab_set()
        header = ctk.CTkFrame(popup, fg_color=Theme.ACCENT_RED, corner_radius=0, height=60); header.pack(fill="x"); header.pack_propagate(False)
        ctk.CTkLabel(header, text="⚠️ CRITICAL: SAVE YOUR KEY", font=("Segoe UI", 16, "bold"), text_color=Theme.TEXT_PRIMARY).pack(expand=True)
        content = ctk.CTkFrame(popup, fg_color="transparent"); content.pack(fill="both", expand=True, padx=30, pady=30)
        ctk.CTkLabel(content, text="This key is your ONLY backup if AI fails.", font=("Segoe UI", 11), text_color=Theme.TEXT_SECONDARY).pack(pady=(0, 20))
        key_entry = ctk.CTkEntry(content, width=400, height=50, font=("Courier New", 18, "bold"), text_color=Theme.ACCENT_GREEN, fg_color=Theme.BG_CARD); key_entry.insert(0, key); key_entry.configure(state="readonly"); key_entry.pack(pady=20)
        ModernButton(content, text="📋 COPY", fg_color=Theme.ACCENT_BLUE, width=400, command=lambda: [pyperclip.copy(key), messagebox.showinfo("Copied", "Copied!")]).pack(pady=10)
        ModernButton(content, text="✓ I HAVE SAVED IT", fg_color=Theme.SUCCESS, width=400, command=popup.destroy).pack(pady=10)

    def record_sample(self, event):
        if not hasattr(self, 'current_reg_user'): return
        target_len = len(self.current_reg_pwd)
        vec = self.sensor.get_vector(target_len)
        self.train_input.delete(0, 'end')
        self.sensor.stop(); time.sleep(0.1); self.sensor.start()
        if vec:
            self.training_buffer.append(vec)
            progress = len(self.training_buffer) / MIN_SAMPLES
            self.train_progress.set(progress)
            self.train_lbl.configure(text=f"{len(self.training_buffer)} / {MIN_SAMPLES} samples")
            if len(self.training_buffer) >= MIN_SAMPLES: self.train_model()
        else:
            self.show_status("⚠️ Length mismatch! Watch typos.", "warning")

    def train_model(self):
        df = pd.DataFrame(self.training_buffer)
        if df.std().mean() < 0.005:
            self.show_status("Typing too mechanical.", "warning"); self.training_buffer = []; self.train_progress.set(0); return
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(df)
        self.db.save_model(self.current_reg_user, model)
        messagebox.showinfo("Success", "Account Created & Trained!")
        self.switch_tab("login")

    def perform_login(self):
        if self.failed_attempts >= LOCKOUT_THRESHOLD: return
        user, pwd = self.user_entry.get(), self.pass_entry.get()
        vec = self.sensor.get_vector(len(pwd))
        self.sensor.stop()
        if not self.db.verify_password(user, pwd): self.fail_login("Invalid Credentials"); return
        
        self.failed_attempts = 0
        self.current_username = user
        self.temp_password = pwd
        user_salt = self.db.get_enc_salt(user)
        
        if self.db.is_user_trained(user):
            if not vec: self.fail_login("Capture failed (Length Mismatch)"); return
            try:
                model = self.db.load_model(user)
                score = model.decision_function(pd.DataFrame([vec]))[0]
                if model.predict(pd.DataFrame([vec]))[0] == 1:
                    self.vault_key = self.vault.generate_key(pwd, user_salt)
                    self.show_dashboard(score, mode="Biometric")
                else: self.fail_login(f"Biometric mismatch ({int((score+0.5)*100)}%)")
            except Exception as e: self.show_status(f"Error: {e}", "error")
        else:
            self.vault_key = self.vault.generate_key(pwd, user_salt)
            self.show_dashboard(0.0, mode="Standard")
    
    def fail_login(self, reason):
        self.failed_attempts += 1
        self.show_status(f"❌ {reason}", "error")
        # FIX: Clear password and reset focus
        self.pass_entry.delete(0, 'end')
        self.pass_entry.focus()
        
        if self.failed_attempts >= LOCKOUT_THRESHOLD:
             self.show_status(f"🔒 Locked for {LOCKOUT_TIME}s", "error")
             threading.Timer(LOCKOUT_TIME, self.reset_lockout).start()

    def reset_lockout(self): self.failed_attempts = 0; self.show_status("", "info")
    def show_status(self, msg, type="info"): 
        c = { "success": Theme.SUCCESS, "error": Theme.ERROR, "warning": Theme.WARNING, "info": Theme.TEXT_SECONDARY }
        try: self.status_msg.configure(text=msg, text_color=c.get(type, Theme.TEXT_SECONDARY))
        except: pass

    def emergency_login_dialog(self):
        d = ctk.CTkToplevel(self); d.title("Recovery"); d.geometry("500x450"); d.configure(fg_color=Theme.BG_PRIMARY)
        ctk.CTkLabel(d, text="EMERGENCY BYPASS", text_color="red", font=("Segoe UI", 16, "bold")).pack(pady=20)
        u = self.create_modern_entry(d, "Username", width=400)
        p = self.create_modern_entry(d, "Password", width=400, show="•")
        r = self.create_modern_entry(d, "Recovery Key", width=400)
        def att():
            if self.db.verify_password(u.get(), p.get()) and self.db.verify_recovery(u.get(), r.get()):
                d.destroy(); self.current_username = u.get(); self.temp_password = p.get()
                self.vault_key = self.vault.generate_key(p.get(), self.db.get_enc_salt(u.get()))
                self.show_dashboard(0.0, mode="EMERGENCY")
            else: 
                messagebox.showerror("Error", "Invalid credentials")
                # FIX: Clear password on failure here too
                p.delete(0, 'end')
                
        ModernButton(d, text="UNLOCK", fg_color="red", width=400, command=att).pack(pady=20)

    # --- DASHBOARD ---
    def show_dashboard(self, confidence, mode="Biometric"):
        self.clear_frame(self.main_frame)
        top = ctk.CTkFrame(self.main_frame, height=60, fg_color="transparent"); top.pack(fill="x", pady=(0, 20))
        
        user_frame = ctk.CTkFrame(top, fg_color=Theme.BG_SECONDARY, corner_radius=12); user_frame.pack(side="left")
        ctk.CTkLabel(user_frame, text=f"👤 {self.current_username}", font=("Segoe UI", 13, "bold")).pack(padx=15, pady=10)
        
        col = Theme.ACCENT_GREEN if mode == "Biometric" else Theme.WARNING
        mode_frame = ctk.CTkFrame(top, fg_color=Theme.BG_SECONDARY, corner_radius=12); mode_frame.pack(side="left", padx=15)
        ctk.CTkLabel(mode_frame, text=f"Conf: {int((confidence+0.5)*100)}%", text_color=col).pack(padx=15, pady=10)
        
        ModernButton(top, text="LOGOUT", width=100, command=self.setup_login_ui).pack(side="right")
        
        tv = ctk.CTkTabview(self.main_frame, fg_color=Theme.BG_SECONDARY); tv.pack(fill="both", expand=True)
        t1=tv.add("File Vault"); t2=tv.add("Passwords"); t3=tv.add("Settings")
        self.setup_file_vault(t1); self.setup_pass_manager(t2); self.setup_settings(t3)

    def setup_file_vault(self, p):
        p.configure(fg_color=Theme.BG_PRIMARY)
        ctk.CTkLabel(p, text="Encryption Vault", font=("Segoe UI", 20, "bold"), text_color=Theme.TEXT_PRIMARY).pack(pady=30)
        btn_frame = ctk.CTkFrame(p, fg_color="transparent"); btn_frame.pack(pady=20)
        ModernButton(btn_frame, text="🔒 Lock File", fg_color=Theme.ACCENT_RED, command=self.encrypt_action).pack(side="left", padx=10)
        ModernButton(btn_frame, text="🔓 Unlock File", fg_color=Theme.ACCENT_GREEN, command=self.decrypt_action).pack(side="left", padx=10)
        self.file_log = ctk.CTkLabel(p, text="Ready", text_color="gray"); self.file_log.pack(pady=20)
    
    def encrypt_action(self):
        p = filedialog.askopenfilename()
        if p: 
            try: self.vault.encrypt_file(p, self.vault_key); self.file_log.configure(text=f"Locked {os.path.basename(p)}")
            except Exception as e: self.file_log.configure(text=str(e))
    def decrypt_action(self):
        p = filedialog.askopenfilename(filetypes=[("Locked","*.locked")])
        if p:
            try: self.vault.decrypt_file(p, self.vault_key); self.file_log.configure(text=f"Unlocked {os.path.basename(p)}")
            except Exception as e: self.file_log.configure(text=str(e))

    def setup_pass_manager(self, p):
        p.configure(fg_color=Theme.BG_PRIMARY)
        self.search_entry = ctk.CTkEntry(p, placeholder_text="Search...", height=45, corner_radius=12); self.search_entry.pack(pady=10, fill="x", padx=30)
        self.search_entry.bind("<KeyRelease>", lambda e: self.refresh_credentials(self.search_entry.get()))
        
        add = ctk.CTkFrame(p, fg_color=Theme.BG_SECONDARY, corner_radius=12); add.pack(fill="x", padx=30, pady=10)
        f = ctk.CTkFrame(add, fg_color="transparent"); f.pack(fill="x", padx=15, pady=10)
        self.site_entry = ctk.CTkEntry(f, placeholder_text="Site", width=150); self.site_entry.pack(side="left", padx=5)
        self.site_user_entry = ctk.CTkEntry(f, placeholder_text="User", width=150); self.site_user_entry.pack(side="left", padx=5)
        self.site_pass_entry = ctk.CTkEntry(f, placeholder_text="Pass", show="•", width=150); self.site_pass_entry.pack(side="left", padx=5)
        ModernButton(f, text="+", width=60, command=self.save_credential).pack(side="left", padx=5)
        
        self.cred_scroll = ctk.CTkScrollableFrame(p, fg_color=Theme.BG_SECONDARY); self.cred_scroll.pack(fill="both", expand=True, padx=30, pady=10)
        self.refresh_credentials()
        
    def save_credential(self):
        s,u,p = self.site_entry.get(), self.site_user_entry.get(), self.site_pass_entry.get()
        if s and p: 
            self.db.add_cred(self.current_username, s, u, self.vault.encrypt_data(p, self.vault_key))
            self.refresh_credentials()
            
    def refresh_credentials(self, filter=""):
        for w in self.cred_scroll.winfo_children(): w.destroy()
        for i, s, u, p in self.db.get_creds(self.current_username):
            if filter.lower() in s.lower():
                r = ctk.CTkFrame(self.cred_scroll, fg_color=Theme.BG_CARD); r.pack(fill="x", pady=2)
                ctk.CTkLabel(r, text=f"{s}", font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)
                ctk.CTkLabel(r, text=f"({u})", font=("Segoe UI", 10), text_color="gray").pack(side="left")
                ctk.CTkButton(r, text="Copy", width=60, fg_color=Theme.ACCENT_BLUE, command=lambda x=p: self.copy_pass(x)).pack(side="right", padx=5)
    
    def copy_pass(self, enc):
        try:
            pyperclip.copy(self.vault.decrypt_data(enc, self.vault_key))
            threading.Timer(30, lambda: pyperclip.copy("")).start()
        except: pass

    def setup_settings(self, p):
        p.configure(fg_color=Theme.BG_PRIMARY)
        ctk.CTkLabel(p, text="Backup & Restore", font=("Segoe UI", 20, "bold")).pack(pady=30)
        ModernButton(p, text="⬇ Export Secure Backup (.nbak)", command=self.act_export).pack(pady=10)
        ModernButton(p, text="⬆ Import Backup", command=self.act_import).pack(pady=10)
        
    def act_export(self):
        try:
            model = self.db.load_model(self.current_username)
            if not model: messagebox.showerror("Err", "No model"); return
            salt = os.urandom(16); key = self.vault.derive_backup_key(self.temp_password, salt)
            aesgcm = AESGCM(key); nonce = os.urandom(12)
            payload = pickle.dumps(model)
            encrypted = aesgcm.encrypt(nonce, payload, None)
            data = {'u': self.current_username, 's': base64.b64encode(salt).decode('utf-8'), 'n': base64.b64encode(nonce).decode('utf-8'), 'd': base64.b64encode(encrypted).decode('utf-8')}
            p = filedialog.asksaveasfilename(defaultextension=".nbak")
            if p: 
                with open(p, 'w') as f: json.dump(data, f)
                messagebox.showinfo("OK", "Exported")
        except Exception as e: messagebox.showerror("Err", str(e))

    def act_import(self):
        try:
            p = filedialog.askopenfilename()
            if not p: return
            pwd = ctk.CTkInputDialog(text="Enter Password to Decrypt:", title="Verify").get_input()
            if not pwd: return
            with open(p, 'r') as f: d = json.load(f)
            if d['u'] != self.current_username:
                 if not messagebox.askyesno("Warn", "Overwrite?"): return
            salt = base64.b64decode(d['s']); nonce = base64.b64decode(d['n']); data = base64.b64decode(d['d'])
            key = self.vault.derive_backup_key(pwd, salt)
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, data, None)
            self.db.save_model(self.current_username, pickle.loads(decrypted))
            messagebox.showinfo("OK", "Restored")
        except: messagebox.showerror("Err", "Decryption Failed")

    def clear_frame(self, f):
        for w in f.winfo_children(): w.destroy()

if __name__ == "__main__":
    app = AuthApp()
    app.mainloop()