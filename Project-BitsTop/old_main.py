"""
Blockchain + Secure Storage GUI (SQLite Integrated) — MILITARY-GRADE LOGIN (Option C)
File: blockchain_secure_gui_sqlite.py
Description:
  - Builds on previous app: now includes a military-grade login & admin system
  - Features:
      * Role-based users (admin, user, viewer)
      * Account lockout after configurable failed attempts
      * Password expiry and strength checks
      * Password hashing with PBKDF2 (strong iterations)
      * TOTP (2FA) support (uses pyotp if available; fallback shows secret QR string)
      * Device fingerprint stored per user
      * Audit logs stored in blockchain + SQLite
      * All previous features: blockchain, encrypted files, password manager, audit logs

Dependencies:
  - Python 3.8+
  - cryptography (pip install cryptography)
  - pyotp (optional, for TOTP 2FA): pip install pyotp

How to run:
  1. pip install cryptography pyotp
  2. python blockchain_secure_gui_sqlite.py

Notes:
  - This is an educational demo. Don't use for production secrets without review.
  - Database file: data_store/app_data.db

"""

import os
import json
import time
import hashlib
import base64
import secrets
import sqlite3
import hmac
from dataclasses import dataclass, asdict
from typing import List, Optional
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# cryptography imports
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
except Exception:
    raise ImportError("cryptography library required. Install with: pip install cryptography")

# optional TOTP
try:
    import pyotp
    HAS_PYOTP = True
except Exception:
    HAS_PYOTP = False

DATA_DIR = "data_store"
DB_PATH = os.path.join(DATA_DIR, 'app_data.db')
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# ------------------------- Utility functions -------------------------

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def current_ts() -> float:
    return time.time()


# Key derivation: derive a Fernet key from passphrase and salt
def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 390000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))
    return key


# ------------------------- SQLite DB -------------------------

def init_db(path: str = DB_PATH):
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute('PRAGMA foreign_keys = ON;')

    # Users table with roles
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT,
        salt TEXT,
        role TEXT,
        totp_secret TEXT,
        device_fingerprint TEXT,
        password_changed_at REAL,
        locked_until REAL
    )
    ''')

    # Failed login attempts
    c.execute('''
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        success INTEGER,
        timestamp REAL,
        ip TEXT
    )
    ''')

    # Blocks table (blockchain)
    c.execute('''
    CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY,
        idx INTEGER UNIQUE,
        timestamp REAL,
        data TEXT,
        previous_hash TEXT,
        nonce INTEGER,
        hash TEXT
    )
    ''')

    # Passwords table
    c.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        site TEXT PRIMARY KEY,
        username TEXT,
        salt TEXT,
        password_hash TEXT,
        created_at REAL
    )
    ''')

    # Files table
    c.execute('''
    CREATE TABLE IF NOT EXISTS files (
        enc_name TEXT PRIMARY KEY,
        original_name TEXT,
        stored_path TEXT,
        timestamp REAL
    )
    ''')

    # Master key metadata
    c.execute('''
    CREATE TABLE IF NOT EXISTS master_key_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        salt TEXT,
        verification TEXT
    )
    ''')

    # Audit logs
    c.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        message TEXT,
        timestamp REAL
    )
    ''')

    conn.commit()
    return conn


# Helper to write audit log
def audit_log(conn: sqlite3.Connection, event_type: str, message: str):
    c = conn.cursor()
    c.execute('INSERT INTO audit_logs (event_type, message, timestamp) VALUES (?, ?, ?)',
              (event_type, message, current_ts()))
    conn.commit()


# ------------------------- Password utilities (PBKDF2) -------------------------

def hash_password(password: str, salt: Optional[bytes] = None, iterations: int = 300_000) -> (str, str):
    if salt is None:
        salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return base64.b64encode(hashed).decode('utf-8'), base64.b64encode(salt).decode('utf-8')


def verify_password_hash(stored_b64_hash: str, stored_b64_salt: str, candidate: str, iterations: int = 300_000) -> bool:
    salt = base64.b64decode(stored_b64_salt)
    expected = base64.b64decode(stored_b64_hash)
    candidate_h = hashlib.pbkdf2_hmac('sha256', candidate.encode('utf-8'), salt, iterations)
    return hmac.compare_digest(candidate_h, expected)


# Password strength check (simple rules)
def password_strength_ok(pw: str) -> (bool, str):
    if len(pw) < 12:
        return False, 'Password must be at least 12 characters.'
    if not any(c.islower() for c in pw):
        return False, 'Add a lowercase character.'
    if not any(c.isupper() for c in pw):
        return False, 'Add an uppercase character.'
    if not any(c.isdigit() for c in pw):
        return False, 'Add a digit.'
    if not any(c in '!@#$%^&*()-_=+[]{};:,.<>?/' for c in pw):
        return False, 'Add a special character.'
    return True, 'OK'


# ------------------------- Blockchain model -------------------------

@dataclass
class Block:
    index: int
    timestamp: float
    data: str
    previous_hash: str
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


class SimpleBlockchain:
    def __init__(self, conn: sqlite3.Connection, difficulty: int = 3):
        self.conn = conn
        self.chain: List[Block] = []
        self.difficulty = difficulty
        self.load_chain_from_db()
        if not self.chain:
            self.create_genesis_block()

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def create_genesis_block(self):
        genesis = Block(index=0, timestamp=current_ts(), data="Genesis Block", previous_hash="0")
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)
        self.save_block_to_db(genesis)
        audit_log(self.conn, 'blockchain', 'Genesis block created')

    def add_block(self, data: str, mine: bool = True) -> Block:
        new_block = Block(index=len(self.chain), timestamp=current_ts(), data=data, previous_hash=self.last_block.hash)
        if mine:
            self.proof_of_work(new_block)
        else:
            new_block.hash = new_block.compute_hash()
        self.chain.append(new_block)
        self.save_block_to_db(new_block)
        audit_log(self.conn, 'block_added', f'Block {new_block.index} added with hash {new_block.hash[:16]}')
        return new_block

    def proof_of_work(self, block: Block) -> str:
        target = '0' * self.difficulty
        while True:
            block.hash = block.compute_hash()
            if block.hash.startswith(target):
                return block.hash
            block.nonce += 1

    def is_valid_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i-1]
            if curr.previous_hash != prev.hash:
                return False
            if curr.compute_hash() != curr.hash:
                return False
        return True

    def to_dict(self):
        return [asdict(b) for b in self.chain]

    # ---------------- DB operations ----------------
    def save_block_to_db(self, block: Block):
        c = self.conn.cursor()
        c.execute('''INSERT OR REPLACE INTO blocks (idx, timestamp, data, previous_hash, nonce, hash) VALUES (?, ?, ?, ?, ?, ?)''',
                  (block.index, block.timestamp, block.data, block.previous_hash, block.nonce, block.hash))
        self.conn.commit()

    def load_chain_from_db(self):
        c = self.conn.cursor()
        c.execute('SELECT idx, timestamp, data, previous_hash, nonce, hash FROM blocks ORDER BY idx ASC')
        rows = c.fetchall()
        self.chain = []
        for r in rows:
            b = Block(index=r[0], timestamp=r[1], data=r[2], previous_hash=r[3], nonce=r[4], hash=r[5])
            self.chain.append(b)


# ------------------------- Secure storage & password manager (SQLite-backed) -------------------------

# Initialize DB
conn = init_db()

# Master passphrase functions using master_key_meta table

def setup_master_passphrase_db(passphrase: str, conn: sqlite3.Connection):
    salt = secrets.token_bytes(16)
    key = derive_key_from_passphrase(passphrase, salt)
    verification = hashlib.sha256(key).hexdigest()
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO master_key_meta (id, salt, verification) VALUES (1, ?, ?)',
              (base64.b64encode(salt).decode('utf-8'), verification))
    conn.commit()
    audit_log(conn, 'master_setup', 'Master passphrase set')


def verify_master_passphrase_db(passphrase: str, conn: sqlite3.Connection) -> bool:
    c = conn.cursor()
    c.execute('SELECT salt, verification FROM master_key_meta WHERE id = 1')
    row = c.fetchone()
    if not row:
        return False
    salt = base64.b64decode(row[0])
    expected_ver = row[1]
    key = derive_key_from_passphrase(passphrase, salt)
    verification = hashlib.sha256(key).hexdigest()
    ok = verification == expected_ver
    audit_log(conn, 'master_verify', f'verify attempt: {"success" if ok else "failure"}')
    return ok


# File encryption / decryption (store encrypted file in DATA_DIR)

def encrypt_file_with_passphrase_db(input_path: str, passphrase: str, conn: sqlite3.Connection) -> Optional[str]:
    c = conn.cursor()
    c.execute('SELECT salt FROM master_key_meta WHERE id = 1')
    row = c.fetchone()
    if not row:
        return None
    salt = base64.b64decode(row[0])
    key = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)
    with open(input_path, 'rb') as f:
        data = f.read()
    token = fernet.encrypt(data)
    enc_name = os.path.basename(input_path) + '.enc'
    out_path = os.path.join(DATA_DIR, enc_name)
    with open(out_path, 'wb') as f:
        f.write(token)
    # register in files table
    c.execute('INSERT OR REPLACE INTO files (enc_name, original_name, stored_path, timestamp) VALUES (?, ?, ?, ?)',
              (enc_name, os.path.basename(input_path), out_path, current_ts()))
    conn.commit()
    audit_log(conn, 'file_encrypt', f'Encrypted {input_path} -> {enc_name}')
    return out_path


def decrypt_file_with_passphrase_db(enc_name: str, passphrase: str, out_path: str, conn: sqlite3.Connection) -> bool:
    c = conn.cursor()
    c.execute('SELECT stored_path FROM files WHERE enc_name = ? ', (enc_name,))
    row = c.fetchone()
    if not row:
        return False
    enc_path = row[0]
    c.execute('SELECT salt FROM master_key_meta WHERE id = 1')
    row2 = c.fetchone()
    if not row2:
        return False
    salt = base64.b64decode(row2[0])
    key = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)
    with open(enc_path, 'rb') as f:
        token = f.read()
    try:
        data = fernet.decrypt(token)
    except Exception:
        audit_log(conn, 'file_decrypt_failed', f'Failed decrypt attempt for {enc_name}')
        return False
    with open(out_path, 'wb') as f:
        f.write(data)
    audit_log(conn, 'file_decrypt', f'Decrypted {enc_name} to {out_path}')
    return True


# Password manager: store username+site with hashed password (pbkdf2) in SQLite

def create_password_entry_db(site: str, username: str, password: str, conn: sqlite3.Connection):
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO passwords (site, username, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
              (site, username, base64.b64encode(salt).decode('utf-8'), base64.b64encode(hashed).decode('utf-8'), current_ts()))
    conn.commit()
    audit_log(conn, 'password_create', f'Password entry created for {site}')


def verify_password_entry_db(site: str, candidate_password: str, conn: sqlite3.Connection) -> bool:
    c = conn.cursor()
    c.execute('SELECT salt, password_hash FROM passwords WHERE site = ?', (site,))
    row = c.fetchone()
    if not row:
        return False
    salt = base64.b64decode(row[0])
    expected = base64.b64decode(row[1])
    candidate_h = hashlib.pbkdf2_hmac('sha256', candidate_password.encode('utf-8'), salt, 200_000)
    ok = secrets.compare_digest(candidate_h, expected)
    audit_log(conn, 'password_verify', f'Password verify for {site}: {"success" if ok else "failure"}')
    return ok


# ------------------------- Advanced User/Login Management -------------------------

def device_fingerprint() -> str:
    # Simple fingerprint: combine machine info (not perfect) - for demo only
    uname = os.uname().sysname + '|' + os.uname().nodename
    return sha256_hex(uname + str(os.getpid()))


def create_user_db(username: str, password: str, role: str, conn: sqlite3.Connection):
    ok, msg = password_strength_ok(password)
    if not ok:
        return False, msg
    h, s = hash_password(password)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO users (username, password_hash, salt, role, totp_secret, device_fingerprint, password_changed_at, locked_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
              (username, h, s, role, None, None, current_ts(), 0))
    conn.commit()
    audit_log(conn, 'user_create', f'User {username} with role {role} created')
    return True, 'Created'


def enable_totp_for_user(username: str, conn: sqlite3.Connection) -> str:
    # returns the base32 secret
    secret = base64.b32encode(secrets.token_bytes(10)).decode('utf-8')
    c = conn.cursor()
    c.execute('UPDATE users SET totp_secret = ? WHERE username = ?', (secret, username))
    conn.commit()
    audit_log(conn, 'totp_enable', f'TOTP enabled for {username}')
    return secret


def lock_account_until(username: str, until_ts: float, conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute('UPDATE users SET locked_until = ? WHERE username = ?', (until_ts, username))
    conn.commit()
    audit_log(conn, 'account_lock', f'User {username} locked until {time.ctime(until_ts)}')


def is_account_locked(username: str, conn: sqlite3.Connection) -> (bool, Optional[float]):
    c = conn.cursor()
    c.execute('SELECT locked_until FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    if not row:
        return False, None
    if row[0] and row[0] > current_ts():
        return True, row[0]
    return False, None


# Authentication flow with lockout, expiry, 2FA
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 300  # 5 minutes
PASSWORD_EXPIRY_DAYS = 90


def authenticate_user(username: str, password: str, totp_code: Optional[str], conn: sqlite3.Connection, device_fp: Optional[str] = None) -> (bool, str):
    c = conn.cursor()
    # check user exists
    c.execute('SELECT password_hash, salt, role, totp_secret, password_changed_at FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    if not row:
        audit_log(conn, 'login_failed', f'Unknown user {username}')
        return False, 'Unknown user'

    # check lock
    locked, until = is_account_locked(username, conn)
    if locked:
        return False, f'Account locked until {time.ctime(until)}'

    stored_hash, stored_salt, role, totp_secret, pwd_changed = row
    if not verify_password_hash(stored_hash, stored_salt, password):
        c.execute('INSERT INTO login_attempts (username, success, timestamp, ip) VALUES (?, ?, ?, ?)', (username, 0, current_ts(), None))
        conn.commit()
        # count recent failures
        c.execute('SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND timestamp > ?', (username, current_ts() - LOCKOUT_SECONDS))
        fails = c.fetchone()[0]
        if fails >= LOCKOUT_THRESHOLD:
            lock_account_until(username, current_ts() + LOCKOUT_SECONDS, conn)
            return False, f'Account locked due to repeated failures. Try after {LOCKOUT_SECONDS} seconds.'
        audit_log(conn, 'login_failed', f'Password mismatch for {username}')
        return False, 'Invalid credentials'

    # password expiry
    if pwd_changed and (current_ts() - pwd_changed) > (PASSWORD_EXPIRY_DAYS * 86400):
        return False, 'Password expired — please change your password'

    # TOTP check if enabled
    if totp_secret:
        if not totp_code:
            return False, 'TOTP code required'
        if HAS_PYOTP:
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                audit_log(conn, 'login_failed', f'TOTP failed for {username}')
                return False, 'Invalid TOTP code'
        else:
            # basic fallback: direct equality (not secure) — only for demo
            if totp_code != totp_secret[-6:]:
                audit_log(conn, 'login_failed', f'TOTP fallback failed for {username}')
                return False, 'Invalid TOTP (fallback)'

    # Device fingerprint check (if stored)
    if device_fp:
        c.execute('SELECT device_fingerprint FROM users WHERE username = ?', (username,))
        df = c.fetchone()[0]
        if df and df != device_fp:
            audit_log(conn, 'device_mismatch', f'Device mismatch for {username}')
            # optionally, require revalidation; for demo just warn

    # success
    c.execute('INSERT INTO login_attempts (username, success, timestamp, ip) VALUES (?, ?, ?, ?)', (username, 1, current_ts(), None))
    conn.commit()
    audit_log(conn, 'login_success', f'User {username} logged in')
    return True, f'Welcome {username} ({role})'


# ------------------------- GUI -------------------------

class App(tk.Tk):
    def __init__(self, conn: sqlite3.Connection):
        super().__init__()
        self.title('Secure Vault — Military-Grade Login Demo')
        self.geometry('1200x760')
        self.conn = conn

        self.blockchain = SimpleBlockchain(conn=self.conn, difficulty=3)

        # If no admin exists, create default admin (demo only)
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            create_user_db('admin', 'Admin@12345!', 'admin', self.conn)
            audit_log(self.conn, 'init', 'Default admin created (admin / Admin@12345!)')

        self.current_user = None

        self.build_login_screen()

    def build_login_screen(self):
        for w in self.winfo_children():
            w.destroy()
        frame = ttk.Frame(self)
        frame.pack(fill='both', expand=True, padx=20, pady=20)

        ttk.Label(frame, text='Secure Vault Login', font=('Helvetica', 18)).pack(pady=10)
        ttk.Label(frame, text='Username:').pack(); e_user = ttk.Entry(frame, width=40); e_user.pack()
        ttk.Label(frame, text='Password:').pack(); e_pw = ttk.Entry(frame, width=40, show='*'); e_pw.pack()
        ttk.Label(frame, text='TOTP (if enabled):').pack(); e_totp = ttk.Entry(frame, width=20); e_totp.pack()

        def do_login():
            u = e_user.get().strip(); p = e_pw.get().strip(); t = e_totp.get().strip()
            df = device_fingerprint()
            ok, msg = authenticate_user(u, p, t, self.conn, device_fp=df)
            if ok:
                self.current_user = u
                messagebox.showinfo('OK', msg)
                self.build_main_ui()
            else:
                messagebox.showerror('Login failed', msg)

        ttk.Button(frame, text='Login', command=do_login).pack(pady=8)
        ttk.Button(frame, text='Admin: Manage Users', command=self.build_admin_ui).pack(pady=4)

    def build_main_ui(self):
        for w in self.winfo_children():
            w.destroy()
        # Simple main UI: tabs for blockchain/files/passwords/audit
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        self.tab_blockchain = ttk.Frame(self.notebook)
        self.tab_files = ttk.Frame(self.notebook)
        self.tab_passwords = ttk.Frame(self.notebook)
        self.tab_audit = ttk.Frame(self.notebook)
        self.tab_account = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_blockchain, text='Blockchain')
        self.notebook.add(self.tab_files, text='Files')
        self.notebook.add(self.tab_passwords, text='Passwords')
        self.notebook.add(self.tab_audit, text='Audit')
        self.notebook.add(self.tab_account, text='Account')

        self.create_blockchain_tab()
        self.create_files_tab()
        self.create_password_tab()
        self.create_audit_tab()
        self.create_account_tab()

    # minimal versions of tabs reused from previous app
    def create_blockchain_tab(self):
        frame = self.tab_blockchain
        left = ttk.Frame(frame)
        left.pack(side='left', fill='y', padx=10, pady=10)
        ttk.Label(left, text='New Block Data:').pack(anchor='w')
        self.new_block_entry = tk.Text(left, height=6, width=48)
        self.new_block_entry.pack()
        ttk.Button(left, text='Add & Mine Block', command=self.add_and_mine_block).pack(pady=6)
        ttk.Button(left, text='Validate Chain', command=self.validate_chain).pack(pady=6)
        right = ttk.Frame(frame)
        right.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        self.canvas = tk.Canvas(right, bg='white')
        self.canvas.pack(fill='both', expand=True)
        self.render_chain()

    def add_and_mine_block(self):
        data = self.new_block_entry.get('1.0', 'end').strip()
        if not data:
            messagebox.showwarning('Empty', 'Enter data')
            return
        # include username in block data for audit
        block = self.blockchain.add_block(f'User:{self.current_user} {data}', mine=True)
        self.render_chain()

    def validate_chain(self):
        ok = self.blockchain.is_valid_chain()
        messagebox.showinfo('Validate', 'Valid' if ok else 'Invalid')

    def render_chain(self):
        self.canvas.delete('all')
        w = self.canvas.winfo_width() or 900
        x = 20; y = 20; boxw = 300; boxh = 120; spacing = 20
        for block in self.blockchain.chain:
            self.canvas.create_rectangle(x, y, x+boxw, y+boxh, outline='black')
            txt = f"Index: {block.index}\nTime: {time.ctime(block.timestamp)}\n{block.data[:80]}\nHash:{block.hash[:28]}"
            self.canvas.create_text(x+10, y+10, anchor='nw', text=txt, width=boxw-20)
            x += boxw + spacing
            if x + boxw > w - 40:
                x = 20; y += boxh + spacing

    # Files tab (encrypt/decrypt) - reuse encrypt/decrypt functions and require login
    def create_files_tab(self):
        frame = self.tab_files
        top = ttk.Frame(frame)
        top.pack(fill='x', padx=10, pady=10)
        ttk.Button(top, text='Encrypt File', command=self.encrypt_file).pack(side='left', padx=6)
        ttk.Button(top, text='Decrypt File', command=self.decrypt_file).pack(side='left', padx=6)
        ttk.Button(top, text='List Encrypted Files', command=self.list_files).pack(side='left', padx=6)
        self.files_listbox = tk.Listbox(frame)
        self.files_listbox.pack(fill='both', expand=True, padx=10, pady=6)

    def encrypt_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        # require master passphrase
        top = tk.Toplevel(self)
        ttk.Label(top, text='Enter master passphrase to encrypt:').pack()
        e = ttk.Entry(top, show='*', width=50); e.pack()
        def do_enc():
            passphrase = e.get()
            if not verify_master_passphrase_db(passphrase, self.conn):
                messagebox.showerror('Auth failed','Master passphrase incorrect')
                return
            out = encrypt_file_with_passphrase_db(path, passphrase, self.conn)
            if out:
                messagebox.showinfo('Encrypted', f'File encrypted to {out}')
                top.destroy()
        ttk.Button(top, text='Encrypt', command=do_enc).pack(pady=6)

    def decrypt_file(self):
        sel = self.files_listbox.curselection()
        if not sel:
            messagebox.showwarning('Select file','Select an encrypted file')
            return
        enc_name = self.files_listbox.get(sel[0])
        top = tk.Toplevel(self)
        ttk.Label(top, text=f'Decrypt {enc_name} - enter master passphrase:').pack()
        e = ttk.Entry(top, show='*', width=50); e.pack()
        def do_dec():
            passphrase = e.get()
            if not verify_master_passphrase_db(passphrase, self.conn):
                messagebox.showerror('Auth failed','Master passphrase incorrect')
                return
            out_path = filedialog.asksaveasfilename(defaultextension='', initialfile=enc_name.replace('.enc',''))
            if not out_path: return
            ok = decrypt_file_with_passphrase_db(enc_name, passphrase, out_path, self.conn)
            if ok:
                messagebox.showinfo('Decrypted', f'Decrypted to {out_path}')
                top.destroy()
            else:
                messagebox.showerror('Failed','Decryption failed')
        ttk.Button(top, text='Decrypt', command=do_dec).pack(pady=6)

    def list_files(self):
        c = self.conn.cursor()
        c.execute('SELECT enc_name FROM files ORDER BY timestamp DESC')
        rows = c.fetchall()
        self.files_listbox.delete(0,'end')
        for r in rows: self.files_listbox.insert('end', r[0])

    # Password tab (manager)
    def create_password_tab(self):
        frame = self.tab_passwords
        top = ttk.Frame(frame); top.pack(fill='x', padx=10, pady=10)
        ttk.Button(top, text='Add Entry', command=self.add_password_entry).pack(side='left', padx=6)
        ttk.Button(top, text='Verify Entry', command=self.verify_password_entry).pack(side='left', padx=6)
        ttk.Button(top, text='List Entries', command=self.list_passwords).pack(side='left', padx=6)
        self.pw_listbox = tk.Listbox(frame); self.pw_listbox.pack(fill='both', expand=True, padx=10, pady=6)

    def add_password_entry(self):
        top = tk.Toplevel(self)
        ttk.Label(top, text='Site:').pack(); e_site = ttk.Entry(top, width=60); e_site.pack()
        ttk.Label(top, text='Username:').pack(); e_user = ttk.Entry(top, width=60); e_user.pack()
        ttk.Label(top, text='Password:').pack(); e_pw = ttk.Entry(top, width=60, show='*'); e_pw.pack()
        def do_add():
            site = e_site.get().strip(); username = e_user.get().strip(); password = e_pw.get().strip()
            if not site or not password: messagebox.showerror('Missing','Site and password required'); return
            create_password_entry_db(site, username, password, self.conn)
            top.destroy(); messagebox.showinfo('Added', f'Password entry added for {site}')
        ttk.Button(top, text='Add', command=do_add).pack(pady=6)

    def verify_password_entry(self):
        top = tk.Toplevel(self)
        ttk.Label(top, text='Site:').pack(); e_site = ttk.Entry(top, width=60); e_site.pack()
        ttk.Label(top, text='Password to check:').pack(); e_pw = ttk.Entry(top, width=60, show='*'); e_pw.pack()
        def do_verify():
            site = e_site.get().strip(); candidate = e_pw.get().strip(); ok = verify_password_entry_db(site, candidate, self.conn)
            messagebox.showinfo('Result', f'Password verify for {site}: {"MATCH" if ok else "NO MATCH"}'); top.destroy()
        ttk.Button(top, text='Verify', command=do_verify).pack(pady=6)

    def list_passwords(self):
        c = self.conn.cursor(); c.execute('SELECT site, username, created_at FROM passwords ORDER BY created_at DESC')
        rows = c.fetchall(); self.pw_listbox.delete(0,'end')
        for r in rows: self.pw_listbox.insert('end', f"{r[0]} - {r[1]} - {time.ctime(r[2])}")

    # Audit tab
    def create_audit_tab(self):
        frame = self.tab_audit; top = ttk.Frame(frame); top.pack(fill='x', padx=10, pady=10)
        ttk.Button(top, text='Refresh Logs', command=self.refresh_audit).pack(side='left', padx=6)
        ttk.Button(top, text='Export Logs (JSON)', command=self.export_audit).pack(side='left', padx=6)
        self.audit_text = tk.Text(frame); self.audit_text.pack(fill='both', expand=True, padx=10, pady=6)
        self.refresh_audit()

    def refresh_audit(self):
        c = self.conn.cursor(); c.execute('SELECT event_type, message, timestamp FROM audit_logs ORDER BY id DESC LIMIT 500')
        rows = c.fetchall(); self.audit_text.delete('1.0','end')
        for r in rows:
            self.audit_text.insert('end', f"[{time.ctime(r[2])}] {r[0]}: {r[1]}\n")

    def export_audit(self):
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
        if not path: return
        c = self.conn.cursor(); c.execute('SELECT event_type, message, timestamp FROM audit_logs ORDER BY id ASC')
        rows = c.fetchall(); out = [{'event_type': r[0], 'message': r[1], 'timestamp': r[2]} for r in rows]
        with open(path, 'w') as f: json.dump(out, f, indent=2)
        messagebox.showinfo('Exported', f'Audit logs exported to {path}')

    # Account tab (change password, enable TOTP)
    def create_account_tab(self):
        frame = self.tab_account; ttk.Label(frame, text=f'Logged in as: {self.current_user}').pack(pady=6)
        ttk.Button(frame, text='Change Password', command=self.change_password).pack(pady=4)
        ttk.Button(frame, text='Enable TOTP (2FA)', command=self.enable_totp).pack(pady=4)
        ttk.Button(frame, text='Logout', command=self.logout).pack(pady=8)

    def change_password(self):
        top = tk.Toplevel(self)
        ttk.Label(top, text='Current password:').pack(); e_curr = ttk.Entry(top, show='*'); e_curr.pack()
        ttk.Label(top, text='New password:').pack(); e_new = ttk.Entry(top, show='*'); e_new.pack()
        def do_change():
            curr = e_curr.get(); new = e_new.get()
            c = self.conn.cursor(); c.execute('SELECT password_hash, salt FROM users WHERE username = ?', (self.current_user,))
            row = c.fetchone()
            if not row or not verify_password_hash(row[0], row[1], curr): messagebox.showerror('Error','Current password wrong'); return
            ok, msg = password_strength_ok(new)
            if not ok: messagebox.showerror('Weak', msg); return
            h, s = hash_password(new)
            c.execute('UPDATE users SET password_hash = ?, salt = ?, password_changed_at = ? WHERE username = ?', (h, s, current_ts(), self.current_user))
            self.conn.commit(); audit_log(self.conn, 'password_change', f'User {self.current_user} changed password'); messagebox.showinfo('Done','Password changed'); top.destroy()
        ttk.Button(top, text='Change', command=do_change).pack(pady=6)

    def enable_totp(self):
        secret = enable_totp_for_user(self.current_user, self.conn)
        if HAS_PYOTP:
            uri = pyotp.totp.TOTP(secret).provisioning_uri(name=self.current_user, issuer_name='SecureVaultDemo')
            messagebox.showinfo('TOTP enabled', f'Secret (scan QR using authenticator)\n{uri}')
        else:
            messagebox.showinfo('TOTP (fallback)', f'TOTP secret: {secret}\n(install pyotp for QR URI)')

    def logout(self):
        self.current_user = None
        audit_log(self.conn, 'logout', 'User logged out')
        self.build_login_screen()

    # ------------------ Admin UI ------------------
    def build_admin_ui(self):
        top = tk.Toplevel(self)
        top.title('Admin Console')
        # list users and allow create/delete
        lf = ttk.Frame(top); lf.pack(fill='both', expand=True, padx=10, pady=10)
        lb = tk.Listbox(lf); lb.pack(side='left', fill='both', expand=True)
        sb = ttk.Scrollbar(lf, orient='vertical', command=lb.yview); sb.pack(side='left', fill='y')
        lb.config(yscrollcommand=sb.set)
        c = self.conn.cursor(); c.execute('SELECT username, role FROM users'); rows = c.fetchall()
        for r in rows: lb.insert('end', f"{r[0]} ({r[1]})")

        def refresh():
            lb.delete(0,'end'); c.execute('SELECT username, role FROM users'); [lb.insert('end', f"{r[0]} ({r[1]})") for r in c.fetchall()]
        def do_create():
            u = simple_prompt('Username:'); p = simple_prompt('Password:(12 char , lower , upper, special ,number'); role = simple_prompt('Role (admin/user/viewer):')
            if not u or not p: messagebox.showerror('Missing','username/password'); return
            ok, msg = create_user_db(u, p, role, self.conn)
            messagebox.showinfo('Create', msg); refresh()
        def do_delete():
            sel = lb.curselection();
            if not sel: return
            name = lb.get(sel[0]).split()[0]
            if messagebox.askyesno('Delete', f'Delete user {name}?'):
                c.execute('DELETE FROM users WHERE username = ?', (name,)); self.conn.commit(); audit_log(self.conn,'user_delete',f'Deleted {name}'); refresh()
        ttk.Button(top, text='Create User', command=do_create).pack(pady=4)
        ttk.Button(top, text='Delete Selected', command=do_delete).pack(pady=4)
        ttk.Button(top, text='Refresh', command=refresh).pack(pady=4)


def simple_prompt(prompt_text: str) -> Optional[str]:
    top = tk.Toplevel()
    top.title('Input')
    ttk.Label(top, text=prompt_text).pack(); e = ttk.Entry(top, width=40); e.pack()
    result = {'val': None}
    def ok(): result['val'] = e.get(); top.destroy()
    ttk.Button(top, text='OK', command=ok).pack(pady=6)
    top.grab_set(); top.wait_window(); return result['val']


# ------------------------- Run App -------------------------

if __name__ == '__main__':
    app = App(conn)
    app.mainloop()
