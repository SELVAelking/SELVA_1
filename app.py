#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
X PANEL OTP PANEL - ENHANCED EDITION v2.0
Single File Application with SMPP + Statistics + Reserve Numbers + General/Legend Roles
Owner Login: Patrickselvaa / Patrickselvaa

Features:
  Reserve Numbers System (Owner/General/Legend only)
  General Role - Can distribute numbers to users
  Legend Role - Can create accounts without approval
  X PANEL - Rate limiting, brute force protection, session management
  Improved UI/UX - Glassmorphism design, animations
"""

import os, json, time, hashlib, secrets, threading, requests, re
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from flask import Flask, render_template_string, request, jsonify, session, redirect, send_file
from flask_socketio import SocketIO, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# TELEGRAM BOT IMPORTS
import asyncio
from telegram import Bot, Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# SMPP IMPORTS
try:
    import smpplib.client
    import smpplib.consts
    import smpplib.gsm
    SMPP_AVAILABLE = True
except ImportError:
    SMPP_AVAILABLE = False
    print("[WARNING] smpplib not installed. SMPP features disabled.")

# ============================================================
# CONFIGURATION & SECURITY
# ============================================================
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute", "50 per second"],
    storage_uri="memory://"
)

# Security Configuration
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 30
SESSION_TIMEOUT_MINUTES = 60

# API Configuration (new panels - old X PANEL / OTP / OTP_MONITOR / RESELLER removed)
# Panel 1: SMTSMS
SMTSMS_API_URL = 'https://smtsms.com/api/v1/sms-logs'
SMTSMS_API_KEY = os.getenv('SMTSMS_API_KEY', '')
SMTSMS_PAGE_SIZE = 100

# Panel 2: UNIXSMS (v2 CDR)
UNIXSMS_API_URL = 'https://agent-api.unixsms.com/v2/cdr'
UNIXSMS_API_KEY = os.getenv('UNIXSMS_API_KEY', '')

# Panel 3: FLY (crapi)
FLY_API_URL = 'http://51.77.216.195/crapi/fly/viewstats'
FLY_API_TOKEN = os.getenv('FLY_API_TOKEN', '')
FLY_WINDOW_HOURS = 12      # how far back to ask for records
FLY_RECORDS = 300          # max records per poll

POLL_INTERVAL = 15

# Data Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'xpanel_data')
import tempfile
DATA_DIR = os.path.join(tempfile.gettempdir(), "xpanel_data")
os.makedirs(DATA_DIR, exist_ok=True)
# File Paths
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
DAILY_LIMITS_FILE = os.path.join(DATA_DIR, 'daily_limits.json')
NUMBERS_FILE = os.path.join(DATA_DIR, 'numbers.json')
TEST_NUMBERS_FILE = os.path.join(DATA_DIR, 'test_numbers.json')
SMS_FILE = os.path.join(DATA_DIR, 'sms.json')
NOTIFICATIONS_FILE = os.path.join(DATA_DIR, 'notifications.json')
PENDING_USERS_FILE = os.path.join(DATA_DIR, 'pending_users.json')
PAYMENTS_FILE = os.path.join(DATA_DIR, 'payments.json')
USER_SMS_COSTS_FILE = os.path.join(DATA_DIR, 'user_sms_costs.json')
SMPP_CONFIG_FILE = os.path.join(DATA_DIR, 'smpp_config.json')
RESERVE_NUMBERS_FILE = os.path.join(DATA_DIR, 'reserve_numbers.json')
SECURITY_LOG_FILE = os.path.join(DATA_DIR, 'security_log.json')
LOGIN_ATTEMPTS_FILE = os.path.join(DATA_DIR, 'login_attempts.json')
FILE_SERVICES_FILE = os.path.join(DATA_DIR, 'file_services.json')   # {file name: service (Whatsapp / Telegram ...)}
RANGE_PRICES_FILE = os.path.join(DATA_DIR, 'range_prices.json')    # {range/file name: price per SMS for that range}
LATEST_FILE = os.path.join(DATA_DIR, 'latest_messages.json')        # feed shown in "Latest messages"

# ============================================================
# DATA MANAGEMENT (Neon PostgreSQL with JSONB; local JSON fallback)
# ============================================================
DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
_DB_POOL = None
_DB_READY = False
_DB_LOCK = threading.Lock()


def _get_db_pool():
    """Create a thread-safe connection pool only when DATABASE_URL is configured."""
    global _DB_POOL
    if not DATABASE_URL:
        return None
    if _DB_POOL is None:
        with _DB_LOCK:
            if _DB_POOL is None:
                try:
                    from psycopg2.pool import ThreadedConnectionPool
                except ImportError as exc:
                    raise RuntimeError('DATABASE_URL is set but psycopg2-binary is missing. Add it to requirements.txt.') from exc
                _DB_POOL = ThreadedConnectionPool(1, 10, DATABASE_URL, sslmode='require')
    return _DB_POOL


def _ensure_db():
    global _DB_READY
    pool = _get_db_pool()
    if pool is None or _DB_READY:
        return
    with _DB_LOCK:
        if _DB_READY:
            return
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS xpanel_json_store (
                        data_key TEXT PRIMARY KEY,
                        data_value JSONB NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
            conn.commit()
            _DB_READY = True
        except Exception:
            conn.rollback()
            raise
        finally:
            pool.putconn(conn)


def _storage_key(filepath):
    return os.path.basename(filepath)


def has_data(filepath):
    """Check for a stored key without treating missing local files as missing DB data."""
    if DATABASE_URL:
        _ensure_db()
        pool = _get_db_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute('SELECT 1 FROM xpanel_json_store WHERE data_key = %s', (_storage_key(filepath),))
                if cur.fetchone():
                    return True
        finally:
            pool.putconn(conn)
    return os.path.exists(filepath)


def load_data(filepath, default=None):
    if default is None:
        default = {}
    if DATABASE_URL:
        from psycopg2.extras import Json
        _ensure_db()
        pool = _get_db_pool()
        key = _storage_key(filepath)
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute('SELECT data_value FROM xpanel_json_store WHERE data_key = %s', (key,))
                row = cur.fetchone()
                if row is not None:
                    return row[0]
                # One-time migration: import an existing local JSON file only if this DB key is absent.
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r', encoding='utf-8') as file:
                            local_data = json.load(file)
                    except (OSError, ValueError):
                        local_data = default
                    cur.execute(
                        'INSERT INTO xpanel_json_store (data_key, data_value) VALUES (%s, %s) ON CONFLICT (data_key) DO NOTHING RETURNING data_value',
                        (key, Json(local_data, dumps=lambda obj: json.dumps(obj, ensure_ascii=False)))
                    )
                    inserted = cur.fetchone()
                    if inserted is not None:
                        conn.commit()
                        return inserted[0]
                    cur.execute('SELECT data_value FROM xpanel_json_store WHERE data_key = %s', (key,))
                    row = cur.fetchone()
                    conn.commit()
                    return row[0] if row else default
                conn.commit()
                return default
        except Exception:
            conn.rollback()
            raise
        finally:
            pool.putconn(conn)
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                return json.load(file)
        except (OSError, ValueError):
            return default
    return default


def save_data(filepath, data):
    if DATABASE_URL:
        from psycopg2.extras import Json
        _ensure_db()
        pool = _get_db_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO xpanel_json_store (data_key, data_value, updated_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (data_key) DO UPDATE
                    SET data_value = EXCLUDED.data_value, updated_at = NOW()
                """, (_storage_key(filepath), Json(data, dumps=lambda obj: json.dumps(obj, ensure_ascii=False))) )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            pool.putconn(conn)
        return
    with open(filepath, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=2)

def init_data():
    if not has_data(USERS_FILE):
        save_data(USERS_FILE, {
            'Patrickselvaa': {
                'password': hashlib.sha256('Patrickselvaa'.encode()).hexdigest(),
                'phone': '',
                'role': 'owner',
                'status': 'active',
                'created_at': datetime.now().isoformat(),
                'limit': 999999,
                'stats': {'numbers_added': 0, 'sms_received': 0, 'files_downloaded': 0}
            }
        })
    for filepath in [NUMBERS_FILE, TEST_NUMBERS_FILE, SMS_FILE, NOTIFICATIONS_FILE, 
                     PENDING_USERS_FILE, PAYMENTS_FILE, USER_SMS_COSTS_FILE, SMPP_CONFIG_FILE,
                     RESERVE_NUMBERS_FILE, LOGIN_ATTEMPTS_FILE, FILE_SERVICES_FILE, RANGE_PRICES_FILE]:
        if not has_data(filepath): save_data(filepath, {})
    if not has_data(SECURITY_LOG_FILE): save_data(SECURITY_LOG_FILE, [])
    # Migrate existing data: ensure all users have created_at
    users = load_data(USERS_FILE)
    changed = False
    for u, d in users.items():
        if 'created_at' not in d:
            users[u]['created_at'] = datetime.now().isoformat()
            changed = True
    if changed:
        save_data(USERS_FILE, users)

init_data()

def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def get_daily_limit_key(username):
    today = datetime.now().strftime('%Y-%m-%d')
    return f"{username}_{today}"

def get_daily_usage(username):
    daily_limits = load_data(DAILY_LIMITS_FILE)
    key = get_daily_limit_key(username)
    return daily_limits.get(key, 0)

def add_daily_usage(username, count):
    daily_limits = load_data(DAILY_LIMITS_FILE)
    key = get_daily_limit_key(username)
    daily_limits[key] = daily_limits.get(key, 0) + count
    save_data(DAILY_LIMITS_FILE, daily_limits)

def get_remaining_daily_limit(username):
    users = load_data(USERS_FILE)
    user = users.get(username, {})
    daily_limit = user.get('daily_limit', 2000)
    used = get_daily_usage(username)
    return max(0, daily_limit - used)

def get_user_sms_cost(username):
    costs = load_data(USER_SMS_COSTS_FILE, {})
    return costs.get(username, 0.01)

def get_range_sms_price(filename, username=None):
    """Price per SMS for a range (file). Falls back to the user's own cost if the range has none."""
    prices = load_data(RANGE_PRICES_FILE, {})
    try:
        if filename in prices and prices[filename] not in ('', None): return float(prices[filename])
    except (TypeError, ValueError): pass
    return get_user_sms_cost(username) if username else 0.01

def set_user_sms_cost(username, cost):
    costs = load_data(USER_SMS_COSTS_FILE, {})
    costs[username] = float(cost)
    save_data(USER_SMS_COSTS_FILE, costs)

# ============================================================
# SECURITY SYSTEM
# ============================================================
class SecurityManager:
    """Advanced security: brute force protection, session validation, audit logging"""

    @staticmethod
    def log_event(event_type, details, username=''):
        """Log security events"""
        logs = load_data(SECURITY_LOG_FILE, [])
        # Fix: handle corrupted files that were saved as dict instead of list
        if isinstance(logs, dict):
            logs = []
        logs.append({
            'type': event_type,
            'details': details,
            'username': username,
            'ip': request.remote_addr if request else 'unknown',
            'time': datetime.now().isoformat()
        })
        # Keep only last 5000 entries
        logs = logs[-5000:]
        save_data(SECURITY_LOG_FILE, logs)

    @staticmethod
    def check_login_attempts(username):
        """Check if account is locked due to failed attempts"""
        attempts = load_data(LOGIN_ATTEMPTS_FILE, {})
        # Fix: handle corrupted files
        if isinstance(attempts, list):
            attempts = {}
        user_attempts = attempts.get(username, [])
        now = datetime.now()
        # Filter attempts within lockout window
        recent = [a for a in user_attempts 
                  if datetime.fromisoformat(a) > now - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)]
        attempts[username] = recent
        save_data(LOGIN_ATTEMPTS_FILE, attempts)
        return len(recent) < MAX_LOGIN_ATTEMPTS

    @staticmethod
    def record_failed_login(username):
        """Record a failed login attempt"""
        attempts = load_data(LOGIN_ATTEMPTS_FILE, {})
        # Fix: handle corrupted files
        if isinstance(attempts, list):
            attempts = {}
        if username not in attempts:
            attempts[username] = []
        attempts[username].append(datetime.now().isoformat())
        save_data(LOGIN_ATTEMPTS_FILE, attempts)
        SecurityManager.log_event('failed_login', f'Failed login attempt {len(attempts[username])}', username)

    @staticmethod
    def clear_login_attempts(username):
        """Clear failed login attempts on successful login"""
        attempts = load_data(LOGIN_ATTEMPTS_FILE, {})
        # Fix: handle corrupted files
        if isinstance(attempts, list):
            attempts = {}
        if username in attempts:
            del attempts[username]
            save_data(LOGIN_ATTEMPTS_FILE, attempts)

    @staticmethod
    def validate_session():
        """Check if session is valid and not expired"""
        if 'username' not in session:
            return False
        if 'login_time' not in session:
            return False
        login_time = datetime.fromisoformat(session['login_time'])
        if datetime.now() - login_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            session.clear()
            return False
        return True

    @staticmethod
    def require_roles(allowed_roles):
        """Decorator factory for role-based access"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not SecurityManager.validate_session():
                    return jsonify({'success': False, 'message': 'Session expired'}), 401
                users = load_data(USERS_FILE)
                user_role = users.get(session.get('username', ''), {}).get('role', '')
                if user_role not in allowed_roles:
                    SecurityManager.log_event('unauthorized_access', 
                        f'Role {user_role} attempted access to {f.__name__}', 
                        session.get('username', ''))
                    return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
                return f(*args, **kwargs)
            return decorated_function
        return decorator

# ============================================================
# DECORATORS
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SecurityManager.validate_session():
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

def owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SecurityManager.validate_session():
            return jsonify({'success': False, 'message': 'Session expired'}), 401
        users = load_data(USERS_FILE)
        role = users.get(session.get('username', ''), {}).get('role', '')
        if role != 'owner':
            return jsonify({'success': False, 'message': 'Owner access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def privileged_required(f):
    """Allow owner, general, and legend roles"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SecurityManager.validate_session():
            return jsonify({'success': False, 'message': 'Session expired'}), 401
        users = load_data(USERS_FILE)
        role = users.get(session.get('username', ''), {}).get('role', '')
        if role not in ['owner', 'general', 'legend']:
            return jsonify({'success': False, 'message': 'Privileged access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def general_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SecurityManager.validate_session():
            return jsonify({'success': False, 'message': 'Session expired'}), 401
        users = load_data(USERS_FILE)
        role = users.get(session.get('username', ''), {}).get('role', '')
        if role not in ['owner', 'general']:
            return jsonify({'success': False, 'message': 'General+ access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def legend_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SecurityManager.validate_session():
            return jsonify({'success': False, 'message': 'Session expired'}), 401
        users = load_data(USERS_FILE)
        role = users.get(session.get('username', ''), {}).get('role', '')
        if role not in ['owner', 'legend']:
            return jsonify({'success': False, 'message': 'Legend+ access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# SMPP CLIENT IMPLEMENTATION
# ============================================================

class SMPPWrapper:
    def __init__(self, host, port, system_id, password, system_type=''):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.system_type = system_type
        self.client = None
        self.connected = False
        self.sms_queue = []
        self.lock = threading.Lock()
        self.running = False
        self.listen_thread = None
        self.keepalive_thread = None

    def _handle_message(self, pdu):
        try:
            source_addr = pdu.source_addr.decode('ascii', errors='ignore') if hasattr(pdu, 'source_addr') else ''
            if hasattr(pdu, 'short_message'):
                try:
                    message_text = pdu.short_message.decode('utf-8')
                except:
                    try:
                        message_text = pdu.short_message.decode('latin-1')
                    except:
                        message_text = pdu.short_message.hex()
            else:
                message_text = ''
            sms_data = {
                'number': source_addr,
                'message': message_text,
                'api': 'SMPP',
                'time': datetime.now().isoformat(),
                'data_coding': getattr(pdu, 'data_coding', 0)
            }
            with self.lock:
                self.sms_queue.append(sms_data)
            print(f"[SMPP] Received SMS from {source_addr}: {message_text[:50]}...")
        except Exception as e:
            print(f"[SMPP] Error handling message: {e}")

    def connect(self):
        if not SMPP_AVAILABLE:
            print("[SMPP] smpplib not available")
            return False
        try:
            self.client = smpplib.client.Client(self.host, self.port, allow_unknown_opt_params=True)
            self.client.set_message_received_handler(self._handle_message)
            self.client.connect()
            self.client.bind_transceiver(system_id=self.system_id, password=self.password, system_type=self.system_type)
            self.connected = True
            self.running = True
            print(f"[SMPP] Connected to {self.host}:{self.port}")
            self.listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.listen_thread.start()
            self.keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
            self.keepalive_thread.start()
            return True
        except Exception as e:
            print(f"[SMPP] Connection failed: {e}")
            self.connected = False
            return False

    def _listen_loop(self):
        while self.running and self.connected:
            try:
                if self.client:
                    self.client.listen(auto_send_enquire_link=True)
            except Exception as e:
                if self.running:
                    print(f"[SMPP] Listen error: {e}")
                    time.sleep(5)

    def _keepalive_loop(self):
        while self.running and self.connected:
            time.sleep(30)
            if self.running and self.connected and self.client:
                try:
                    self.client.enquire_link()
                except Exception as e:
                    print(f"[SMPP] Keepalive failed: {e}")
                    self._reconnect()

    def _reconnect(self):
        print("[SMPP] Attempting to reconnect...")
        try:
            if self.client:
                try: self.client.disconnect()
                except: pass
            time.sleep(5)
            self.connect()
        except Exception as e:
            print(f"[SMPP] Reconnect failed: {e}")

    def disconnect(self):
        self.running = False
        self.connected = False
        if self.client:
            try: self.client.unbind(); self.client.disconnect()
            except: pass
        self.client = None
        print("[SMPP] Disconnected")

    def get_received_sms(self):
        with self.lock:
            messages = self.sms_queue.copy()
            self.sms_queue.clear()
        return messages

smpp_wrapper = None
smpp_config = {}

def init_smpp_client():
    global smpp_wrapper, smpp_config
    if not SMPP_AVAILABLE:
        print("[SMPP] python-smpplib not installed.")
        return None
    config = load_data(SMPP_CONFIG_FILE, {})
    if not config.get('enabled', False):
        print("[SMPP] SMPP is disabled in config")
        return None
    smpp_config = config
    try:
        wrapper = SMPPWrapper(
            host=config.get('host', 'localhost'),
            port=config.get('port', 2775),
            system_id=config.get('system_id', ''),
            password=config.get('password', ''),
            system_type=config.get('system_type', '')
        )
        if wrapper.connect():
            smpp_wrapper = wrapper
            print("[SMPP] Client initialized and connected")
            return wrapper
        else:
            print("[SMPP] Failed to start client")
            return None
    except Exception as e:
        print(f"[SMPP] Initialization error: {e}")
        return None

def get_smpp_sms():
    global smpp_wrapper
    if smpp_wrapper and smpp_wrapper.connected:
        return smpp_wrapper.get_received_sms()
    return []

def restart_smpp_client():
    global smpp_wrapper
    if smpp_wrapper:
        smpp_wrapper.disconnect()
        smpp_wrapper = None
    time.sleep(2)
    return init_smpp_client()

# ============================================================
# SMS API FETCHING
# ============================================================

API_DEBUG = {}   # last status / raw response per panel (used by /api/test_api_connection)

NUM_KEYS  = ('did_number', 'num', 'number', 'did', 'to', 'destination', 'recipient', 'msisdn', 'phone', 'dst', 'called')
MSG_KEYS  = ('message', 'text', 'body', 'sms', 'content', 'msg', 'sms_text', 'message_text')
TIME_KEYS = ('dt', 'time', 'date', 'created_at', 'received_at', 'timestamp', 'datetime', 'start_time')
LIST_KEYS = ('data', 'messages', 'sms', 'items', 'results', 'records', 'rows', 'logs', 'cdr')

def _extract_items(data):
    """Find the list of records inside whatever JSON shape the panel returns."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                inner = _extract_items(value)
                if inner:
                    return inner
        if any(k in data for k in NUM_KEYS):
            return [data]
    return []

def _first(item, keys):
    for k in keys:
        v = item.get(k)
        if v not in (None, ''):
            return str(v).strip()
    return ''

def _normalize_items(items, api_name):
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        number = _first(item, NUM_KEYS)
        message = _first(item, MSG_KEYS)
        if number and message:
            sender = re.sub(r'[<>&"\'`\\]', '', _first(item, ('sender', 'cli', 'from', 'service')))[:40]
            out.append({'number': number, 'message': message, 'api': api_name, 'sender': sender,
                        'time': _first(item, TIME_KEYS) or datetime.now().isoformat()})
    return out

def _debug(name, response=None, error=None):
    API_DEBUG[name] = {
        'status': response.status_code if response is not None else None,
        'raw': response.text[:300] if response is not None else '',
        'error': str(error) if error else '',
        'time': datetime.now().isoformat()
    }

def fetch_sms_from_apis():
    all_sms = []
    all_sms.extend(fetch_smtsms_api())
    all_sms.extend(fetch_unixsms_api())
    all_sms.extend(fetch_fly_api())
    all_sms.extend(fetch_smpp_sms())
    print(f"[SMS Monitor] Total fetched: {len(all_sms)} SMS")
    return all_sms

def fetch_smpp_sms():
    sms_list = []
    try:
        messages = get_smpp_sms()
        for msg in messages:
            sms_list.append({'number': msg.get('number', ''), 'message': msg.get('message', ''), 
                           'api': 'SMPP', 'time': msg.get('time', datetime.now().isoformat())})
        if messages: print(f"[API] SMPP: Fetched {len(messages)} messages")
    except Exception as e: print(f'[API] SMPP Error: {e}')
    return sms_list

def fetch_smtsms_api():
    """https://smtsms.com/api/v1/sms-logs?key=...&start=0&length=N  (optional &did=NUMBER)"""
    try:
        params = {'key': SMTSMS_API_KEY, 'start': 0, 'length': SMTSMS_PAGE_SIZE}
        response = requests.get(SMTSMS_API_URL, params=params, timeout=15)
        _debug('SMTSMS', response)
        print(f"[API] SMTSMS: Status={response.status_code}")
        if response.status_code == 200:
            items = _normalize_items(_extract_items(response.json()), 'SMTSMS')
            print(f"[API] SMTSMS: Found {len(items)} messages")
            return items
    except Exception as e:
        _debug('SMTSMS', error=e)
        print(f'[API] SMTSMS Error: {e}')
    return []

_unixsms_auth_mode = None

def fetch_unixsms_api():
    """https://agent-api.unixsms.com/v2/cdr - auto-detects how the key must be sent."""
    global _unixsms_auth_mode
    attempts = [
        ('bearer',    {'Authorization': f'Bearer {UNIXSMS_API_KEY}'}, {}),
        ('x-api-key', {'X-API-Key': UNIXSMS_API_KEY}, {}),
        ('query',     {}, {'key': UNIXSMS_API_KEY}),
    ]
    if _unixsms_auth_mode:
        attempts.sort(key=lambda a: a[0] != _unixsms_auth_mode)
    try:
        for mode, headers, params in attempts:
            response = requests.get(UNIXSMS_API_URL, headers=headers, params=params, timeout=15)
            _debug('UNIXSMS', response)
            if response.status_code in (401, 403):
                continue
            print(f"[API] UNIXSMS: Status={response.status_code} (auth={mode})")
            if response.status_code == 200:
                _unixsms_auth_mode = mode
                items = _normalize_items(_extract_items(response.json()), 'UNIXSMS')
                print(f"[API] UNIXSMS: Found {len(items)} messages")
                return items
            return []
        print("[API] UNIXSMS: authentication rejected (401/403) with all methods")
    except Exception as e:
        _debug('UNIXSMS', error=e)
        print(f'[API] UNIXSMS Error: {e}')
    return []

def fetch_fly_api():
    """http://51.77.216.195/crapi/fly/viewstats?token=...&dt1=...&dt2=...&records=N"""
    try:
        now = datetime.now()
        fmt = '%Y-%m-%d %H:%M:%S'
        params = {
            'token': FLY_API_TOKEN,
            'dt1': (now - timedelta(hours=FLY_WINDOW_HOURS)).strftime(fmt),
            'dt2': (now + timedelta(hours=FLY_WINDOW_HOURS)).strftime(fmt),  # +window: tolerates server/app timezone gap
            'records': FLY_RECORDS,
        }
        response = requests.get(FLY_API_URL, params=params, timeout=15)
        _debug('FLY', response)
        print(f"[API] FLY: Status={response.status_code}")
        if response.status_code == 200:
            items = _normalize_items(_extract_items(response.json()), 'FLY')
            print(f"[API] FLY: Found {len(items)} messages")
            return items
    except Exception as e:
        _debug('FLY', error=e)
        print(f'[API] FLY Error: {e}')
    return []

def extract_code(message):
    """Pull the verification code out of an SMS (e.g. 605-423 or 123456)."""
    m = re.search(r'(?<!\d)(\d{3}[- ]\d{3}|\d{4,8})(?!\d)', message or '')
    return m.group(1) if m else ''

def mask_number_stars(phone):
    """201500014104 -> 201*******4104"""
    phone = str(phone)
    if len(phone) >= 8: return phone[:3] + '*******' + phone[-4:]
    return phone[:1] + '***'

def _digits(v):
    return re.sub(r'\D', '', str(v))

def _ts(t):
    try: return datetime.fromisoformat(str(t).replace('Z', '').replace(' ', 'T')).timestamp()
    except Exception: return 0

def mask_latest(num):
    """Mask a number but keep it in its own format:
       01553632560 -> 0155*******60 | 201553632560 -> 20155*******60 | +201553632560 -> +20155*******60"""
    num = str(num).strip()
    d = _digits(num)
    if len(d) >= 8:
        if d.startswith('20') and len(d) == 12:           # Egypt with country code: keep it + 3 digits
            return ('+' if num.startswith('+') else '') + '20' + d[2:5] + '*******' + d[-2:]
        if num.startswith('+'): return '+' + d[:4] + '*******' + d[-2:]
        return num[:4] + '*******' + num[-2:]
    return num[:1] + '***'

SERVICE_KEYWORDS = [
    (('whatsapp', 'واتس'), 'WhatsApp'), (('telegram', 'تلغرام', 'تيليجرام'), 'Telegram'),
    (('facebook', 'فيسبوك'), 'Facebook'), (('instagram', 'انستغرام', 'انستجرام'), 'Instagram'),
    (('paypal', 'باي بال'), 'PayPal'), (('google', 'جوجل'), 'Google'),
    (('twitter', 'تويتر', 'x.com'), 'Twitter/X'), (('amazon', 'أمازون'), 'Amazon'),
    (('netflix', 'نتفليكس'), 'Netflix'), (('uber', 'أوبر'), 'Uber'),
]

def detect_service(message):
    low = (message or '').lower()
    for keys, name in SERVICE_KEYWORDS:
        if any(k in low for k in keys): return name
    return ''

def build_number_index(numbers_data, test_numbers):
    """last 9 digits -> [{user, file, num}]  (num = the number exactly as written in the file)"""
    idx = {}
    def add(user, fname, lst):
        if not isinstance(lst, list): return
        for n in lst:
            d = _digits(n)
            if len(d) < 7: continue
            idx.setdefault(d[-9:], []).append({'user': user, 'file': fname, 'num': str(n).strip()})
    for uname, files in (numbers_data or {}).items():
        if not isinstance(files, dict): continue
        if uname == '_available':
            for fname, info in files.items():
                if isinstance(info, dict): add(None, fname, info.get('numbers'))
            continue
        if str(uname).startswith('_'): continue
        for fname, lst in files.items(): add(uname, fname, lst)
    for fname, lst in (test_numbers or {}).items(): add(None, fname, lst)
    return idx

def mask_number(phone):
    if len(phone) >= 10: return phone[:6] + 'XXXXX' + phone[-3:]
    return phone

# ============================================================
# SMS PROCESSING
# ============================================================

def process_new_sms():
    new_sms = fetch_sms_from_apis()
    numbers_data = load_data(NUMBERS_FILE)
    sms_data = load_data(SMS_FILE)
    notifications = load_data(NOTIFICATIONS_FILE)
    test_numbers = load_data(TEST_NUMBERS_FILE)
    payments = load_data(PAYMENTS_FILE)
    all_users = load_data(USERS_FILE)
    file_services = load_data(FILE_SERVICES_FILE, {})
    latest_items = load_data(LATEST_FILE, {}).get('items', [])
    latest_fps = {x.get('fp') for x in latest_items}
    number_index = build_number_index(numbers_data, test_numbers)

    for sms in new_sms:
        phone = sms.get('number', '').strip()
        message = sms.get('message', '').strip()
        api_name = sms.get('api', '')
        time_str = sms.get('time', datetime.now().isoformat())
        if not phone or not message: continue

        # FEATURE 1: Match user's purchased numbers
        for username, user_files in numbers_data.items():
            if username.startswith('_'): continue
            if not isinstance(user_files, dict): continue
            for filename, numbers_list in user_files.items():
                if not isinstance(numbers_list, list): continue
                bare = phone.lstrip('+')
                matched = next((v for v in (phone, bare, '+' + bare) if v in numbers_list), None)
                if matched:
                    phone_key = matched
                    if username not in sms_data: sms_data[username] = {}
                    if phone_key not in sms_data[username]: sms_data[username][phone_key] = []
                    msg_fingerprint = message[:50] + time_str[:16]
                    exists = any((s.get('message', '')[:50] + s.get('time', '')[:16]) == msg_fingerprint for s in sms_data[username][phone_key])
                    if not exists:
                        cost_per_sms = get_range_sms_price(filename, username)
                        sms_entry = {'number': phone_key, 'message': message, 'api': api_name, 'time': time_str,
                                     'sender': sms.get('sender', ''), 'code': extract_code(message),
                                     'range': filename, 'price': cost_per_sms}
                        sms_data[username][phone_key].append(sms_entry)
                        print(f"[NEW SMS] User {username} -> {phone}: {message[:40]}...")
                        if username not in payments: payments[username] = []
                        payments[username].append({'type': 'sms', 'number': phone, 'file': filename, 'cost': cost_per_sms, 'time': datetime.now().isoformat()})
                        if username not in notifications: notifications[username] = []
                        notifications[username].append({'type': 'sms', 'message': f'New SMS for {phone}', 'time': datetime.now().isoformat(), 'read': False})
                        try: socketio.emit('new_sms', {'number': phone, 'message': message, 'api': api_name}, room=username)
                        except Exception as e: print(f"Socket emit error: {e}")

        # FEATURE 2: Show ALL API SMS to ALL users (SMTSMS is excluded: it only goes to "SMS test" masked, see FEATURE 5)
        for username, user_info in ([] if api_name == 'SMTSMS' else all_users.items()):
            if user_info.get('role') in ['user', 'admin', 'general', 'legend']:
                if username not in sms_data: sms_data[username] = {}
                api_key = f"api_{phone}"
                if api_key not in sms_data[username]: sms_data[username][api_key] = []
                msg_fingerprint = message[:50] + time_str[:16]
                exists = any((s.get('message', '')[:50] + s.get('time', '')[:16]) == msg_fingerprint for s in sms_data[username][api_key])
                if not exists:
                    sms_data[username][api_key].append({'number': phone, 'message': message, 'api': api_name, 'time': time_str, 'source': 'api_global'})

        # FEATURE 5: "Latest messages" feed (every API, every user).
        # Non-owners see a masked number; owners (number inside their file) see it in full.
        d = _digits(phone)
        matches = number_index.get(d[-9:], []) if len(d) >= 7 else []
        fp = hashlib.md5((phone + message[:50] + time_str[:16]).encode('utf-8')).hexdigest()
        if fp not in latest_fps:
            service = (sms.get('sender', '') or detect_service(message)
                       or next((file_services[m['file']] for m in matches if file_services.get(m['file'])), ''))
            latest_items.append({'fp': fp, 'api': api_name, 'number': phone, 'message': message,
                                 'service': service, 'time': time_str, 'matches': matches})
            latest_fps.add(fp)

    save_data(LATEST_FILE, {'items': latest_items[-300:]})
    save_data(SMS_FILE, sms_data)
    save_data(NOTIFICATIONS_FILE, notifications)
    save_data(PAYMENTS_FILE, payments)

def start_sms_monitoring():
    def monitor():
        while True:
            try: process_new_sms()
            except Exception as e: print(f'Monitor error: {e}')
            time.sleep(POLL_INTERVAL)
    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()

# ============================================================
# RESERVE NUMBERS SYSTEM
# ============================================================

class ReserveNumbersManager:
    """Manage reserve numbers - only accessible to owner, general, legend"""

    @staticmethod
    def add_reserve_file(filename, numbers, cost_per_number, added_by):
        """Add a new reserve numbers file"""
        reserve_data = load_data(RESERVE_NUMBERS_FILE, {})
        reserve_data[filename] = {
            'numbers': numbers,
            'cost': float(cost_per_number),
            'added_by': added_by,
            'added_at': datetime.now().isoformat(),
            'total_count': len(numbers)
        }
        save_data(RESERVE_NUMBERS_FILE, reserve_data)
        SecurityManager.log_event('reserve_added', f'Added {len(numbers)} reserve numbers in "{filename}"', added_by)
        return True

    @staticmethod
    def get_reserve_files():
        """Get all reserve number files"""
        return load_data(RESERVE_NUMBERS_FILE, {})

    @staticmethod
    def delete_reserve_file(filename):
        """Delete a reserve numbers file"""
        reserve_data = load_data(RESERVE_NUMBERS_FILE, {})
        if filename in reserve_data:
            del reserve_data[filename]
            save_data(RESERVE_NUMBERS_FILE, reserve_data)
            return True
        return False

    @staticmethod
    def get_numbers_from_reserve(filename, count):
        """Extract numbers from a reserve file"""
        reserve_data = load_data(RESERVE_NUMBERS_FILE, {})
        if filename not in reserve_data:
            return None, 0
        numbers = reserve_data[filename]['numbers']
        if count > len(numbers):
            count = len(numbers)
        extracted = numbers[:count]
        remaining = numbers[count:]
        reserve_data[filename]['numbers'] = remaining
        save_data(RESERVE_NUMBERS_FILE, reserve_data)
        return extracted, len(remaining)

    @staticmethod
    def add_numbers_to_user_from_reserve(username, filename, count, added_by):
        """Add numbers from reserve to a user's account"""
        extracted, remaining = ReserveNumbersManager.get_numbers_from_reserve(filename, count)
        if extracted is None:
            return {'success': False, 'message': 'Reserve file not found'}

        numbers_data = load_data(NUMBERS_FILE)
        payments = load_data(PAYMENTS_FILE)

        if username not in numbers_data:
            numbers_data[username] = {}

        # Use the same filename for the user's numbers
        if filename not in numbers_data[username]:
            numbers_data[username][filename] = []

        numbers_data[username][filename].extend(extracted)

        # Record payment
        if username not in payments:
            payments[username] = []
        reserve_files = ReserveNumbersManager.get_reserve_files()
        cost_per_number = reserve_files.get(filename, {}).get('cost', 0)
        payments[username].append({
            'type': 'purchase',
            'file': filename,
            'count': len(extracted),
            'cost': len(extracted) * cost_per_number,
            'time': datetime.now().isoformat(),
            'added_by': added_by,
            'source': 'reserve'
        })

        save_data(NUMBERS_FILE, numbers_data)
        save_data(PAYMENTS_FILE, payments)

        SecurityManager.log_event('reserve_distributed', 
            f'Added {len(extracted)} numbers from reserve "{filename}" to user {username}', added_by)

        return {
            'success': True,
            'assigned': extracted,
            'count': len(extracted),
            'remaining': remaining
        }

    @staticmethod
    def add_numbers_to_user_from_available(username, filename, count, added_by):
        """Add numbers from available (_available) files to a user"""
        numbers_data = load_data(NUMBERS_FILE)
        payments = load_data(PAYMENTS_FILE)

        available = numbers_data.get('_available', {})
        if filename not in available:
            return {'success': False, 'message': 'File not found in available numbers'}

        file_data = available[filename]
        available_numbers = file_data['numbers']
        cost_per_number = file_data.get('cost', 0)

        if count > len(available_numbers):
            return {'success': False, 'message': f'Not enough numbers. Available: {len(available_numbers)}'}

        assigned = available_numbers[:count]
        remaining = available_numbers[count:]

        if username not in numbers_data:
            numbers_data[username] = {}
        if filename not in numbers_data[username]:
            numbers_data[username][filename] = []

        numbers_data[username][filename].extend(assigned)

        if remaining:
            numbers_data['_available'][filename]['numbers'] = remaining
        else:
            del numbers_data['_available'][filename]

        if username not in payments:
            payments[username] = []
        payments[username].append({
            'type': 'purchase',
            'file': filename,
            'count': count,
            'cost': count * cost_per_number,
            'time': datetime.now().isoformat(),
            'added_by': added_by,
            'source': 'available'
        })

        save_data(NUMBERS_FILE, numbers_data)
        save_data(PAYMENTS_FILE, payments)

        SecurityManager.log_event('available_distributed',
            f'Added {count} numbers from available "{filename}" to user {username}', added_by)

        return {
            'success': True,
            'assigned': assigned,
            'count': len(assigned),
            'remaining': len(remaining) if remaining else 0
        }

# ============================================================
# SMPP CONFIG API
# ============================================================

@app.route('/api/owner/smpp_config', methods=['GET'])
@owner_required
def get_smpp_config():
    config = load_data(SMPP_CONFIG_FILE, {})
    safe_config = config.copy()
    if 'password' in safe_config: safe_config['password'] = '********'
    return jsonify({'success': True, 'config': safe_config})

@app.route('/api/owner/smpp_config', methods=['POST'])
@owner_required
def save_smpp_config():
    data = request.get_json()
    config = {
        'enabled': data.get('enabled', False),
        'host': data.get('host', 'localhost'),
        'port': int(data.get('port', 2775)),
        'system_id': data.get('system_id', ''),
        'password': data.get('password', ''),
        'system_type': data.get('system_type', ''),
        'source_addr': data.get('source_addr', ''),
        'source_addr_ton': int(data.get('source_addr_ton', 0)),
        'source_addr_npi': int(data.get('source_addr_npi', 0))
    }
    save_data(SMPP_CONFIG_FILE, config)
    return jsonify({'success': True, 'message': 'SMPP config saved'})

@app.route('/api/owner/smpp_test', methods=['POST'])
@owner_required
def test_smpp_connection():
    try:
        result = restart_smpp_client()
        if result: return jsonify({'success': True, 'message': 'SMPP connected successfully'})
        else: return jsonify({'success': False, 'message': 'Failed to connect SMPP'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)})

@app.route('/api/owner/smpp_status', methods=['GET'])
@owner_required
def get_smpp_status():
    global smpp_wrapper
    config = load_data(SMPP_CONFIG_FILE, {})
    status = {'enabled': config.get('enabled', False), 'connected': False, 'host': config.get('host', ''), 
              'port': config.get('port', 0), 'system_id': config.get('system_id', '')}
    if smpp_wrapper: status['connected'] = smpp_wrapper.connected
    return jsonify({'success': True, 'status': status})

# CORS support for API endpoints
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# ============================================================
# MAIN ROUTES
# ============================================================

@app.route('/')
def index():
    if 'username' in session: return redirect('/dashboard')
    return render_template_string(INDEX_HTML)

@app.route('/set_language', methods=['POST'])
def set_language():
    data = request.get_json()
    session['language'] = data.get('language', 'arabic')
    return jsonify({'success': True})

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    # Security: Check brute force protection
    if not SecurityManager.check_login_attempts(username):
        SecurityManager.log_event('brute_force_blocked', f'Account locked due to failed attempts', username)
        return jsonify({'success': False, 'message': 'Account temporarily locked. Try again in 30 minutes.'}), 429

    users = load_data(USERS_FILE)
    if username in users:
        if users[username]['password'] == hash_password(password):
            if users[username].get('status') == 'banned':
                SecurityManager.log_event('banned_login_attempt', 'Banned user attempted login', username)
                return jsonify({'success': False, 'message': 'Account banned'})
            session['username'] = username
            session['role'] = users[username]['role']
            session['login_time'] = datetime.now().isoformat()
            session['session_id'] = secrets.token_hex(16)
            SecurityManager.clear_login_attempts(username)
            SecurityManager.log_event('login_success', f'Login successful. Role: {users[username]["role"]}', username)
            return jsonify({'success': True, 'role': users[username]['role']})

    SecurityManager.record_failed_login(username)
    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    phone = data.get('phone', '').strip()
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})
    # Security: Validate username format
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return jsonify({'success': False, 'message': 'Username must be 3-30 characters, alphanumeric and underscores only'})
    if len(password) < 4:
        return jsonify({'success': False, 'message': 'Password must be at least 4 characters'})

    users = load_data(USERS_FILE)
    pending = load_data(PENDING_USERS_FILE)
    if username in users or username in pending:
        return jsonify({'success': False, 'message': 'Username already exists'})
    pending[username] = {
        'password': hash_password(password), 'phone': phone, 'role': 'user',
        'status': 'pending', 'created_at': datetime.now().isoformat(), 'limit': 2000
    }
    save_data(PENDING_USERS_FILE, pending)
    notifications = load_data(NOTIFICATIONS_FILE)
    if 'Patrickselvaa' not in notifications: notifications['Patrickselvaa'] = []
    notifications['Patrickselvaa'].append({
        'type': 'registration', 'message': f'New registration request: {username}',
        'username': username, 'time': datetime.now().isoformat(), 'read': False
    })
    save_data(NOTIFICATIONS_FILE, notifications)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running(): asyncio.create_task(send_registration_notification(username, phone))
        else: loop.run_until_complete(send_registration_notification(username, phone))
    except Exception as e: print(f"[Telegram] Registration notification error: {e}")
    return jsonify({'success': True, 'message': 'Registration pending approval'})

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role', 'user')
    if role == 'owner': return render_template_string(OWNER_HTML)
    elif role == 'general': return render_template_string(GENERAL_HTML)
    elif role == 'legend': return render_template_string(LEGEND_HTML)
    elif role == 'admin': return render_template_string(ADMIN_HTML)
    return render_template_string(USER_HTML)

@app.route('/logout')
def logout():
    SecurityManager.log_event('logout', 'User logged out', session.get('username', ''))
    session.clear()
    return redirect('/')

# ============================================================
# OWNER APIs
# ============================================================

@app.route('/api/owner/pending_users')
@owner_required
def get_pending_users():
    pending = load_data(PENDING_USERS_FILE)
    return jsonify({'success': True, 'users': pending})

@app.route('/api/owner/approve_user', methods=['POST'])
@owner_required
def approve_user():
    data = request.get_json()
    username = data.get('username')
    action = data.get('action')
    pending = load_data(PENDING_USERS_FILE)
    users = load_data(USERS_FILE)
    if username not in pending: return jsonify({'success': False, 'message': 'User not found'})
    if action == 'approve':
        users[username] = pending[username]
        users[username]['status'] = 'active'
        save_data(USERS_FILE, users)
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running(): asyncio.create_task(send_user_approval_notification(username))
            else: loop.run_until_complete(send_user_approval_notification(username))
        except Exception as e: print(f"[Telegram] Notification error: {e}")
        notifications = load_data(NOTIFICATIONS_FILE)
        if username not in notifications: notifications[username] = []
        notifications[username].append({'type': 'system', 'message': 'Your account has been approved!', 'time': datetime.now().isoformat(), 'read': False})
        save_data(NOTIFICATIONS_FILE, notifications)
    del pending[username]
    save_data(PENDING_USERS_FILE, pending)
    return jsonify({'success': True})

@app.route('/api/owner/approve_all', methods=['POST'])
@owner_required
def approve_all():
    pending = load_data(PENDING_USERS_FILE)
    users = load_data(USERS_FILE)
    notifications = load_data(NOTIFICATIONS_FILE)
    for username, data in pending.items():
        users[username] = data
        users[username]['status'] = 'active'
        if username not in notifications: notifications[username] = []
        notifications[username].append({'type': 'system', 'message': 'Your account has been approved!', 'time': datetime.now().isoformat(), 'read': False})
    save_data(USERS_FILE, users)
    save_data(NOTIFICATIONS_FILE, notifications)
    save_data(PENDING_USERS_FILE, {})
    return jsonify({'success': True})

@app.route('/api/owner/add_numbers', methods=['POST'])
@owner_required
def add_numbers():
    if 'file' not in request.files: return jsonify({'success': False, 'message': 'No file uploaded'})
    file = request.files['file']
    filename = request.form.get('filename', '').strip()
    cost = request.form.get('cost', '0').strip()
    if not filename: return jsonify({'success': False, 'message': 'Filename required'})
    numbers = []
    try:
        content = file.read().decode('utf-8')
        for line in content.split('\n'):
            num = line.strip()
            if num and re.match(r'^[+\d\s-]+$', num): numbers.append(num)
    except: return jsonify({'success': False, 'message': 'Invalid file'})
    numbers_data = load_data(NUMBERS_FILE)
    if '_available' not in numbers_data: numbers_data['_available'] = {}
    numbers_data['_available'][filename] = {'numbers': numbers, 'cost': float(cost), 'added_at': datetime.now().isoformat()}
    save_data(NUMBERS_FILE, numbers_data)
    sms_price = request.form.get('sms_price', '').strip()
    if sms_price:
        try:
            rp = load_data(RANGE_PRICES_FILE, {})
            rp[filename] = float(sms_price)
            save_data(RANGE_PRICES_FILE, rp)
        except ValueError: return jsonify({'success': False, 'message': 'Invalid SMS price'})
    service = request.form.get('service', '').strip()
    if service:
        fs = load_data(FILE_SERVICES_FILE, {})
        fs[filename] = service
        save_data(FILE_SERVICES_FILE, fs)
    SecurityManager.log_event('numbers_added', f'Added file "{filename}" with {len(numbers)} numbers', session['username'])
    return jsonify({'success': True, 'count': len(numbers)})

@app.route('/api/owner/delete_numbers', methods=['POST'])
@owner_required
def delete_numbers():
    data = request.get_json()
    filename = data.get('filename')
    numbers_data = load_data(NUMBERS_FILE)
    if '_available' in numbers_data and filename in numbers_data['_available']:
        del numbers_data['_available'][filename]
    for username in list(numbers_data.keys()):
        if username != '_available' and filename in numbers_data[username]:
            del numbers_data[username][filename]
    save_data(NUMBERS_FILE, numbers_data)
    fs = load_data(FILE_SERVICES_FILE, {})
    if filename in fs:
        del fs[filename]
        save_data(FILE_SERVICES_FILE, fs)
    rp = load_data(RANGE_PRICES_FILE, {})
    if filename in rp:
        del rp[filename]
        save_data(RANGE_PRICES_FILE, rp)
    return jsonify({'success': True})

@app.route('/api/owner/delete_all_numbers', methods=['POST'])
@owner_required
def delete_all_numbers():
    numbers_data = load_data(NUMBERS_FILE)
    available = numbers_data.get('_available', {})
    numbers_data = {'_available': available}
    save_data(NUMBERS_FILE, numbers_data)
    return jsonify({'success': True})

@app.route('/api/owner/broadcast', methods=['POST'])
@owner_required
def broadcast():
    data = request.get_json()
    message = data.get('message', '')
    users = load_data(USERS_FILE)
    notifications = load_data(NOTIFICATIONS_FILE)
    for username in users:
        if users[username].get('role') in ['user', 'admin', 'general', 'legend']:
            if username not in notifications: notifications[username] = []
            notifications[username].append({'type': 'broadcast', 'message': message, 'from': 'Patrickselvaa', 'time': datetime.now().isoformat(), 'read': False})
    save_data(NOTIFICATIONS_FILE, notifications)
    socketio.emit('broadcast', {'message': message}, broadcast=True)
    SecurityManager.log_event('broadcast', f'Broadcast message sent', session['username'])
    return jsonify({'success': True})

@app.route('/api/owner/increase_limit', methods=['POST'])
@owner_required
def increase_limit():
    data = request.get_json()
    username = data.get('username')
    limit = int(data.get('limit', 0))
    users = load_data(USERS_FILE)
    if username in users:
        users[username]['limit'] = users[username].get('limit', 0) + limit
        save_data(USERS_FILE, users)
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'User not found'})

@app.route('/api/owner/add_numbers_to_user', methods=['POST'])
@owner_required
def add_numbers_to_user():
    data = request.get_json()
    username = data.get('username')
    filename = data.get('filename')
    count = int(data.get('count', 0))
    if not username or not filename or count <= 0:
        return jsonify({'success': False, 'message': 'Username, filename and count required'})
    users = load_data(USERS_FILE)
    if username not in users: return jsonify({'success': False, 'message': 'User not found'})
    numbers_data = load_data(NUMBERS_FILE)
    payments = load_data(PAYMENTS_FILE)
    available = numbers_data.get('_available', {})
    if filename not in available: return jsonify({'success': False, 'message': 'File not found'})
    file_data = available[filename]
    available_numbers = file_data['numbers']
    cost_per_number = file_data.get('cost', 0)
    if count > len(available_numbers): return jsonify({'success': False, 'message': f'Not enough numbers. Available: {len(available_numbers)}'})
    total_cost = count * cost_per_number
    assigned = available_numbers[:count]
    remaining = available_numbers[count:]
    if username not in numbers_data: numbers_data[username] = {}
    if filename not in numbers_data[username]: numbers_data[username][filename] = []
    numbers_data[username][filename].extend(assigned)
    if remaining: numbers_data['_available'][filename]['numbers'] = remaining
    else: del numbers_data['_available'][filename]
    if username not in payments: payments[username] = []
    payments[username].append({'type': 'purchase', 'file': filename, 'count': count, 'cost': total_cost, 'time': datetime.now().isoformat(), 'added_by': 'owner'})
    save_data(NUMBERS_FILE, numbers_data)
    save_data(PAYMENTS_FILE, payments)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        msg = f"تم إضافة {count} رقم للمستخدم {username} من ملف {filename}"
        if loop.is_running(): asyncio.create_task(send_data_change_notification("إضافة أرقام", msg))
        else: loop.run_until_complete(send_data_change_notification("إضافة أرقام", msg))
    except Exception as e: print(f"[Telegram] Notification error: {e}")
    return jsonify({'success': True, 'assigned': assigned, 'count': len(assigned), 'cost': total_cost, 'remaining': len(remaining) if remaining else 0})

@app.route('/api/owner/add_admin', methods=['POST'])
@owner_required
def add_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_data(USERS_FILE)
    if username in users: return jsonify({'success': False, 'message': 'User exists'})
    users[username] = {'password': hash_password(password), 'role': 'admin', 'status': 'active', 'created_at': datetime.now().isoformat(), 'limit': 999999}
    save_data(USERS_FILE, users)
    SecurityManager.log_event('admin_created', f'Created admin: {username}', session['username'])
    return jsonify({'success': True})

@app.route('/api/owner/add_general', methods=['POST'])
@owner_required
def add_general():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_data(USERS_FILE)
    if username in users: return jsonify({'success': False, 'message': 'User exists'})
    users[username] = {'password': hash_password(password), 'phone': '', 'role': 'general', 'status': 'active', 'created_at': datetime.now().isoformat(), 'limit': 999999}
    save_data(USERS_FILE, users)
    SecurityManager.log_event('general_created', f'Created general: {username}', session['username'])
    return jsonify({'success': True, 'message': f'General account {username} created'})

@app.route('/api/owner/add_legend', methods=['POST'])
@owner_required
def add_legend():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_data(USERS_FILE)
    if username in users: return jsonify({'success': False, 'message': 'User exists'})
    users[username] = {'password': hash_password(password), 'phone': '', 'role': 'legend', 'status': 'active', 'created_at': datetime.now().isoformat(), 'limit': 999999}
    save_data(USERS_FILE, users)
    SecurityManager.log_event('legend_created', f'Created legend: {username}', session['username'])
    return jsonify({'success': True, 'message': f'Legend account {username} created'})

@app.route('/api/owner/delete_admin', methods=['POST'])
@owner_required
def delete_admin():
    data = request.get_json()
    username = data.get('username')
    users = load_data(USERS_FILE)
    if username in users and users[username].get('role') == 'admin':
        users[username]['role'] = 'user'
        save_data(USERS_FILE, users)
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Admin not found'})

@app.route('/api/owner/delete_general', methods=['POST'])
@owner_required
def delete_general():
    data = request.get_json()
    username = data.get('username')
    users = load_data(USERS_FILE)
    if username in users and users[username].get('role') == 'general':
        users[username]['role'] = 'user'
        save_data(USERS_FILE, users)
        SecurityManager.log_event('general_deleted', f'Deleted general: {username}', session['username'])
        return jsonify({'success': True, 'message': f'General {username} demoted to user'})
    return jsonify({'success': False, 'message': 'General not found'})

@app.route('/api/owner/delete_legend', methods=['POST'])
@owner_required
def delete_legend():
    data = request.get_json()
    username = data.get('username')
    users = load_data(USERS_FILE)
    if username in users and users[username].get('role') == 'legend':
        users[username]['role'] = 'user'
        save_data(USERS_FILE, users)
        SecurityManager.log_event('legend_deleted', f'Deleted legend: {username}', session['username'])
        return jsonify({'success': True, 'message': f'Legend {username} demoted to user'})
    return jsonify({'success': False, 'message': 'Legend not found'})

@app.route('/api/owner/add_test_numbers', methods=['POST'])
@owner_required
def add_test_numbers():
    if 'file' not in request.files: return jsonify({'success': False, 'message': 'No file uploaded'})
    file = request.files['file']
    filename = request.form.get('filename', '').strip()
    if not filename: return jsonify({'success': False, 'message': 'Filename required'})
    numbers = []
    try:
        content = file.read().decode('utf-8')
        for line in content.split('\n'):
            num = line.strip()
            if num and re.match(r'^[+\d\s-]+$', num): numbers.append(num)
    except: return jsonify({'success': False, 'message': 'Invalid file'})
    test_numbers = load_data(TEST_NUMBERS_FILE)
    test_numbers[filename] = numbers
    save_data(TEST_NUMBERS_FILE, test_numbers)
    return jsonify({'success': True, 'count': len(numbers)})

@app.route('/api/owner/delete_test_numbers', methods=['POST'])
@owner_required
def delete_test_numbers():
    data = request.get_json()
    filename = data.get('filename')
    test_numbers = load_data(TEST_NUMBERS_FILE)
    if filename in test_numbers:
        del test_numbers[filename]
        save_data(TEST_NUMBERS_FILE, test_numbers)
    return jsonify({'success': True})

@app.route('/api/owner/delete_all_test', methods=['POST'])
@owner_required
def delete_all_test():
    save_data(TEST_NUMBERS_FILE, {})
    return jsonify({'success': True})

@app.route('/api/owner/accounts')
@owner_required
def get_accounts():
    users = load_data(USERS_FILE)
    return jsonify({'success': True, 'users': users})

@app.route('/api/owner/toggle_ban', methods=['POST'])
@owner_required
def toggle_ban():
    data = request.get_json()
    username = data.get('username')
    users = load_data(USERS_FILE)
    if username in users and username != 'Patrickselvaa':
        current = users[username].get('status', 'active')
        users[username]['status'] = 'banned' if current == 'active' else 'active'
        save_data(USERS_FILE, users)
        SecurityManager.log_event('toggle_ban', f'Toggled ban for {username} to {users[username]["status"]}', session['username'])
        return jsonify({'success': True, 'status': users[username]['status']})
    return jsonify({'success': False})

@app.route('/api/owner/range_statistics')
@owner_required
def get_range_statistics():
    sms_data = load_data(SMS_FILE)
    numbers_data = load_data(NUMBERS_FILE)
    range_stats = {}
    for username, user_sms in sms_data.items():
        if username.startswith('_') or username == 'Patrickselvaa': continue
        if not isinstance(user_sms, dict): continue
        for phone_key, messages in user_sms.items():
            if not isinstance(messages, list): continue
            if phone_key.startswith('test_') or phone_key.startswith('api_test_'): continue
            user_numbers = numbers_data.get(username, {})
            found_file = None
            for fname, numbers_list in user_numbers.items():
                if not isinstance(numbers_list, list): continue
                if phone_key in numbers_list: found_file = fname; break
                clean_phone = phone_key.replace('api_', '')
                if clean_phone in numbers_list: found_file = fname; break
            if found_file:
                if found_file not in range_stats: range_stats[found_file] = {'file': found_file, 'total_sms': 0, 'unique_numbers': set(), 'users': set(), 'last_sms_time': None}
                range_stats[found_file]['total_sms'] += len(messages)
                range_stats[found_file]['unique_numbers'].add(phone_key.replace('api_', ''))
                range_stats[found_file]['users'].add(username)
                for msg in messages:
                    msg_time = msg.get('time')
                    if msg_time and (range_stats[found_file]['last_sms_time'] is None or msg_time > range_stats[found_file]['last_sms_time']):
                        range_stats[found_file]['last_sms_time'] = msg_time
    result = []
    for file_name, stats in range_stats.items():
        result.append({'file': file_name, 'total_sms': stats['total_sms'], 'unique_numbers': len(stats['unique_numbers']),
                       'active_users': len(stats['users']), 'last_sms_time': stats['last_sms_time'] or '-'})
    result.sort(key=lambda x: x['total_sms'], reverse=True)
    return jsonify({'success': True, 'ranges': result})

@app.route('/api/owner/user_statistics')
@owner_required
def get_user_statistics():
    users = load_data(USERS_FILE)
    numbers_data = load_data(NUMBERS_FILE)
    sms_data = load_data(SMS_FILE)
    payments = load_data(PAYMENTS_FILE)
    stats = []
    for username, user_info in users.items():
        if username == 'Patrickselvaa': continue
        user_numbers = numbers_data.get(username, {})
        total_numbers, files_count = 0, 0
        for fname, nums in user_numbers.items():
            if isinstance(nums, list): total_numbers += len(nums); files_count += 1
        user_sms = sms_data.get(username, {})
        total_sms = 0
        for key, messages in user_sms.items():
            if isinstance(messages, list) and not key.startswith('test_') and not key.startswith('api_test_'): total_sms += len(messages)
        user_payments = payments.get(username, [])
        total_spent = sum(p.get('cost', 0) for p in user_payments)
        stats.append({'username': username, 'role': user_info.get('role', 'user'), 'status': user_info.get('status', 'active'),
                      'limit': user_info.get('limit', 0), 'total_numbers': total_numbers, 'files_count': files_count,
                      'total_sms': total_sms, 'total_spent': round(total_spent, 2), 'created_at': user_info.get('created_at', '')})
    return jsonify({'success': True, 'statistics': stats})

@app.route('/api/owner/user_sms_cost', methods=['GET'])
@owner_required
def get_user_sms_costs():
    costs = load_data(USER_SMS_COSTS_FILE, {})
    users = load_data(USERS_FILE)
    result = []
    for username in users:
        if username != 'Patrickselvaa': result.append({'username': username, 'cost': costs.get(username, 0.01)})
    return jsonify({'success': True, 'costs': result})

@app.route('/api/owner/user_sms_cost', methods=['POST'])
@owner_required
def set_user_sms_cost_api():
    data = request.get_json()
    username = data.get('username')
    cost = float(data.get('cost', 0.01))
    if not username: return jsonify({'success': False, 'message': 'Username required'})
    users = load_data(USERS_FILE)
    if username not in users: return jsonify({'success': False, 'message': 'User not found'})
    set_user_sms_cost(username, cost)
    return jsonify({'success': True, 'message': f'SMS cost for {username} set to ${cost}'})

# ============================================================
# RESERVE NUMBERS APIs (Owner / General / Legend only)
# ============================================================

@app.route('/api/privileged/reserve_numbers', methods=['POST'])
@privileged_required
def add_reserve_numbers():
    """Upload reserve numbers - accessible to owner, general, legend"""
    if 'file' not in request.files: return jsonify({'success': False, 'message': 'No file uploaded'})
    file = request.files['file']
    filename = request.form.get('filename', '').strip()
    cost = request.form.get('cost', '0').strip()
    if not filename: return jsonify({'success': False, 'message': 'Filename required'})
    numbers = []
    try:
        content = file.read().decode('utf-8')
        for line in content.split('\n'):
            num = line.strip()
            if num and re.match(r'^[+\d\s-]+$', num): numbers.append(num)
    except: return jsonify({'success': False, 'message': 'Invalid file'})
    if not numbers: return jsonify({'success': False, 'message': 'No valid numbers found in file'})

    success = ReserveNumbersManager.add_reserve_file(filename, numbers, float(cost), session['username'])
    if success:
        return jsonify({'success': True, 'count': len(numbers), 'filename': filename})
    return jsonify({'success': False, 'message': 'Failed to add reserve numbers'})

@app.route('/api/privileged/reserve_numbers', methods=['GET'])
@privileged_required
def get_reserve_numbers():
    """Get all reserve numbers - accessible to owner, general, legend"""
    reserve_data = ReserveNumbersManager.get_reserve_files()
    # Remove the actual numbers list for security, only return count
    safe_data = {}
    for fname, info in reserve_data.items():
        safe_data[fname] = {
            'filename': fname,
            'cost': info.get('cost', 0),
            'count': len(info.get('numbers', [])),
            'added_by': info.get('added_by', ''),
            'added_at': info.get('added_at', '')
        }
    return jsonify({'success': True, 'files': safe_data})

@app.route('/api/privileged/reserve_numbers/delete', methods=['POST'])
@privileged_required
def delete_reserve_numbers():
    """Delete a reserve numbers file"""
    data = request.get_json()
    filename = data.get('filename')
    if not filename: return jsonify({'success': False, 'message': 'Filename required'})
    success = ReserveNumbersManager.delete_reserve_file(filename)
    if success:
        SecurityManager.log_event('reserve_deleted', f'Deleted reserve file "{filename}"', session['username'])
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'File not found'})

@app.route('/api/privileged/reserve_to_user', methods=['POST'])
@privileged_required
def add_reserve_to_user():
    """Add numbers from reserve or available files to a user"""
    data = request.get_json()
    username = data.get('username')
    filename = data.get('filename')
    count = int(data.get('count', 0))
    source = data.get('source', 'reserve')  # 'reserve' or 'available'

    if not username or not filename or count <= 0:
        return jsonify({'success': False, 'message': 'Username, filename and count required'})

    users = load_data(USERS_FILE)
    if username not in users:
        return jsonify({'success': False, 'message': 'User not found'})

    if source == 'reserve':
        result = ReserveNumbersManager.add_numbers_to_user_from_reserve(username, filename, count, session['username'])
    else:
        result = ReserveNumbersManager.add_numbers_to_user_from_available(username, filename, count, session['username'])

    return jsonify(result)

@app.route('/api/privileged/all_files_for_distribution', methods=['GET'])
@privileged_required
def get_all_files_for_distribution():
    """Get both available and reserve files for distribution"""
    # Available files
    numbers_data = load_data(NUMBERS_FILE)
    available = numbers_data.get('_available', {})
    available_files = {}
    for name, info in available.items():
        available_files[name] = {'type': 'available', 'count': len(info.get('numbers', [])), 'cost': info.get('cost', 0)}

    # Reserve files
    reserve_data = ReserveNumbersManager.get_reserve_files()
    reserve_files = {}
    for name, info in reserve_data.items():
        reserve_files[name] = {'type': 'reserve', 'count': len(info.get('numbers', [])), 'cost': info.get('cost', 0), 'added_by': info.get('added_by', '')}

    return jsonify({
        'success': True,
        'available_files': available_files,
        'reserve_files': reserve_files
    })

# ============================================================
# GENERAL ROLE APIs
# ============================================================

@app.route('/api/general/dashboard_stats')
@general_required
def get_general_dashboard_stats():
    """Get dashboard stats for general role"""
    users = load_data(USERS_FILE)
    reserve_data = ReserveNumbersManager.get_reserve_files()
    numbers_data = load_data(NUMBERS_FILE)

    total_users = len([u for u, d in users.items() if d.get('role') == 'user'])
    total_reserve_numbers = sum(len(info.get('numbers', [])) for info in reserve_data.values())
    total_available = sum(len(info.get('numbers', [])) for info in numbers_data.get('_available', {}).values())
    total_distributed = 0
    for username, files in numbers_data.items():
        if username.startswith('_'): continue
        if isinstance(files, dict):
            for fname, nums in files.items():
                if isinstance(nums, list): total_distributed += len(nums)

    return jsonify({
        'success': True,
        'total_users': total_users,
        'total_reserve_numbers': total_reserve_numbers,
        'total_available_numbers': total_available,
        'total_distributed': total_distributed
    })

@app.route('/api/general/users_list')
@general_required
def get_general_users_list():
    """Get list of regular users for general role"""
    users = load_data(USERS_FILE)
    user_list = []
    for username, info in users.items():
        if info.get('role') == 'user':
            user_list.append({
                'username': username,
                'status': info.get('status', 'active'),
                'limit': info.get('limit', 0),
                'created_at': info.get('created_at', '')
            })
    return jsonify({'success': True, 'users': user_list})

# ============================================================
# LEGEND ROLE APIs
# ============================================================

@app.route('/api/legend/create_user', methods=['POST'])
@legend_required
def legend_create_user():
    """Create a new user account directly without approval - Legend only"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    phone = data.get('phone', '').strip()

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})

    # Validate username
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return jsonify({'success': False, 'message': 'Username must be 3-30 characters, alphanumeric and underscores only'})
    if len(password) < 4:
        return jsonify({'success': False, 'message': 'Password must be at least 4 characters'})

    users = load_data(USERS_FILE)
    pending = load_data(PENDING_USERS_FILE)

    if username in users or username in pending:
        return jsonify({'success': False, 'message': 'Username already exists'})

    # Create user directly (no pending approval needed)
    users[username] = {
        'password': hash_password(password),
        'phone': phone,
        'role': 'user',
        'status': 'active',
        'created_at': datetime.now().isoformat(),
        'limit': 2000,
        'created_by': session.get('username', 'legend')
    }
    save_data(USERS_FILE, users)

    SecurityManager.log_event('user_created_by_legend', 
        f'User {username} created directly by {session.get("username", "")}', session['username'])

    # Notify owner
    notifications = load_data(NOTIFICATIONS_FILE)
    if 'Patrickselvaa' not in notifications: notifications['Patrickselvaa'] = []
    notifications['Patrickselvaa'].append({
        'type': 'legend_create',
        'message': f'Legend created user: {username}',
        'legend': session.get('username', ''),
        'new_user': username,
        'time': datetime.now().isoformat(),
        'read': False
    })
    save_data(NOTIFICATIONS_FILE, notifications)

    return jsonify({
        'success': True, 
        'message': f'User {username} created successfully',
        'user': {
            'username': username,
            'role': 'user',
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }
    })

@app.route('/api/legend/delete_user', methods=['POST'])
@legend_required
def legend_delete_user():
    """Delete a user account - Legend can delete users they created or any regular user"""
    data = request.get_json()
    username = data.get('username')

    if not username: return jsonify({'success': False, 'message': 'Username required'})
    if username == 'Patrickselvaa': return jsonify({'success': False, 'message': 'Cannot delete owner'})

    users = load_data(USERS_FILE)
    if username not in users:
        return jsonify({'success': False, 'message': 'User not found'})

    # Legend can only delete regular users, not other legends, generals, or admins
    target_role = users[username].get('role', 'user')
    if target_role in ['owner', 'legend', 'general', 'admin']:
        return jsonify({'success': False, 'message': 'Cannot delete privileged accounts'})

    del users[username]
    save_data(USERS_FILE, users)

    SecurityManager.log_event('user_deleted_by_legend', 
        f'User {username} deleted by {session.get("username", "")}', session['username'])

    return jsonify({'success': True, 'message': f'User {username} deleted'})

@app.route('/api/legend/users_list')
@legend_required
def get_legend_users_list():
    """Get list of all regular users for legend"""
    users = load_data(USERS_FILE)
    user_list = []
    for username, info in users.items():
        if info.get('role') == 'user':
            user_list.append({
                'username': username,
                'status': info.get('status', 'active'),
                'phone': info.get('phone', ''),
                'limit': info.get('limit', 0),
                'created_at': info.get('created_at', ''),
                'created_by': info.get('created_by', '')
            })
    return jsonify({'success': True, 'users': user_list})

@app.route('/api/legend/toggle_user_status', methods=['POST'])
@legend_required
def legend_toggle_user_status():
    """Ban/unban a regular user"""
    data = request.get_json()
    username = data.get('username')
    users = load_data(USERS_FILE)

    if username not in users or users[username].get('role') != 'user':
        return jsonify({'success': False, 'message': 'User not found or not a regular user'})

    current = users[username].get('status', 'active')
    users[username]['status'] = 'banned' if current == 'active' else 'active'
    save_data(USERS_FILE, users)

    SecurityManager.log_event('user_status_toggled_by_legend',
        f'User {username} status changed to {users[username]["status"]} by {session.get("username", "")}', session['username'])

    return jsonify({'success': True, 'status': users[username]['status']})

@app.route('/api/legend/dashboard_stats')
@legend_required
def get_legend_dashboard_stats():
    """Get dashboard stats for legend role"""
    users = load_data(USERS_FILE)
    reserve_data = ReserveNumbersManager.get_reserve_files()

    total_users = len([u for u, d in users.items() if d.get('role') == 'user'])
    active_users = len([u for u, d in users.items() if d.get('role') == 'user' and d.get('status') == 'active'])
    banned_users = len([u for u, d in users.items() if d.get('role') == 'user' and d.get('status') == 'banned'])
    total_reserve = sum(len(info.get('numbers', [])) for info in reserve_data.values())

    return jsonify({
        'success': True,
        'total_users': total_users,
        'active_users': active_users,
        'banned_users': banned_users,
        'total_reserve_numbers': total_reserve
    })

# ============================================================
# USER APIs
# ============================================================

@app.route('/api/user/available_numbers')
@login_required
def get_available_numbers():
    numbers_data = load_data(NUMBERS_FILE)
    available = numbers_data.get('_available', {})
    u = session['username']
    return jsonify({'success': True, 'files': available, 'sms_prices': {f: get_range_sms_price(f, u) for f in available}})

@app.route('/api/user/request_numbers', methods=['POST'])
@login_required
def request_numbers():
    data = request.get_json()
    filename = data.get('filename')
    count = int(data.get('count', 0))
    username = session['username']
    if count <= 0: return jsonify({'success': False, 'message': 'Invalid count'})
    remaining_daily = get_remaining_daily_limit(username)
    if count > remaining_daily: return jsonify({'success': False, 'message': f'Daily limit exceeded. Remaining: {remaining_daily}'})
    users = load_data(USERS_FILE)
    numbers_data = load_data(NUMBERS_FILE)
    payments = load_data(PAYMENTS_FILE)
    available = numbers_data.get('_available', {})
    if filename not in available: return jsonify({'success': False, 'message': 'File not found'})
    file_data = available[filename]
    available_numbers = file_data['numbers']
    cost_per_number = file_data['cost']
    if count > len(available_numbers): return jsonify({'success': False, 'message': 'Not enough numbers'})
    total_cost = count * cost_per_number
    assigned = available_numbers[:count]
    remaining = available_numbers[count:]
    if username not in numbers_data: numbers_data[username] = {}
    if filename not in numbers_data[username]: numbers_data[username][filename] = []
    numbers_data[username][filename].extend(assigned)
    if remaining: numbers_data['_available'][filename]['numbers'] = remaining
    else: del numbers_data['_available'][filename]
    add_daily_usage(username, count)
    save_data(NUMBERS_FILE, numbers_data)
    new_remaining = get_remaining_daily_limit(username)
    return jsonify({'success': True, 'assigned': assigned, 'cost': total_cost, 'daily_remaining': new_remaining, 'daily_limit': 2000})

@app.route('/api/user/my_numbers')
@login_required
def get_my_numbers():
    username = session['username']
    numbers_data = load_data(NUMBERS_FILE)
    user_numbers = numbers_data.get(username, {})
    payments = load_data(PAYMENTS_FILE)
    user_payments = payments.get(username, [])
    file_costs = {}
    for p in user_payments:
        if p.get('type') == 'purchase' and p.get('file'):
            count = max(p.get('count', 1), 1)
            file_costs[p['file']] = p.get('cost', 0) / count
    return jsonify({'success': True, 'numbers': user_numbers, 'costs': file_costs})

def _parse_count(raw, total):
    if raw in (None, '', 'all', 'All', 'ALL'): return total
    try: return max(0, min(int(raw), total))
    except (TypeError, ValueError): return total

@app.route('/api/user/delete_my_numbers', methods=['POST'])
@login_required
def delete_my_numbers():
    data = request.get_json() or {}
    filename = data.get('filename')
    username = session['username']
    numbers_data = load_data(NUMBERS_FILE)
    mine = numbers_data.get(username, {})
    if filename not in mine: return jsonify({'success': False, 'message': 'Range not found'})
    n = _parse_count(data.get('count'), len(mine[filename]))
    if n >= len(mine[filename]): del mine[filename]
    else: mine[filename] = mine[filename][n:]
    save_data(NUMBERS_FILE, numbers_data)
    return jsonify({'success': True, 'deleted': n})

@app.route('/api/user/daily_limit')
@login_required
def get_daily_limit():
    username = session['username']
    remaining = get_remaining_daily_limit(username)
    used = get_daily_usage(username)
    return jsonify({'success': True, 'daily_limit': 2000, 'daily_used': used, 'daily_remaining': remaining, 'resets_at': '23:59:59'})

@app.route('/api/user/my_range')
@login_required
def get_my_range():
    username = session['username']
    numbers_data = load_data(NUMBERS_FILE)
    user_numbers = numbers_data.get(username, {})
    result = {}
    for filename, numbers in user_numbers.items(): result[filename] = len(numbers)
    return jsonify({'success': True, 'range': result})

@app.route('/api/user/my_sms')
@login_required
def get_my_sms():
    username = session['username']
    sms_data = load_data(SMS_FILE)
    user_sms = sms_data.get(username, {})
    numbers_data = load_data(NUMBERS_FILE)
    phone_to_range = {}
    for fname, nums in (numbers_data.get(username) or {}).items():
        if isinstance(nums, list):
            for n in nums: phone_to_range[_digits(n)] = fname
    out = {}
    for phone, msgs in user_sms.items():
        if phone.startswith('api_') or not isinstance(msgs, list): continue   # global API feed removed
        rows = []
        for m in msgs:
            m = dict(m)
            rng = m.get('range') or phone_to_range.get(_digits(phone), '')
            m['range'] = rng
            if m.get('price') is None:
                m['price'] = get_range_sms_price(rng, username) if rng else 0
            rows.append(m)
        out[phone] = rows
    earned = sum(p.get('cost', 0) for p in load_data(PAYMENTS_FILE).get(username, []) if p.get('type') == 'sms')
    return jsonify({'success': True, 'sms': out, 'earned_total': round(earned, 6)})

@app.route('/api/user/test_numbers')
@login_required
def get_test_numbers():
    test_numbers = load_data(TEST_NUMBERS_FILE)
    return jsonify({'success': True, 'files': test_numbers})

@app.route('/api/user/latest_messages')
@login_required
def get_latest_messages():
    username = session['username']
    items = load_data(LATEST_FILE, {}).get('items', [])
    rows = []
    for it in items:
        ms = it.get('matches') or []
        mine = next((m for m in ms if m.get('user') == username), None)
        if mine:
            number, rng, owned = mine['num'], mine['file'], True
        else:
            first = ms[0] if ms else None
            number = mask_latest(first['num'] if first else it.get('number', ''))
            rng, owned = (first['file'] if first else 'Noun'), False
        rows.append({'service': it.get('service') or '-', 'number': number, 'range': rng or 'Noun',
                     'message': it.get('message', ''), 'time': it.get('time', ''), 'owned': owned,
                     '_ts': _ts(it.get('time'))})
    rows.sort(key=lambda r: r['_ts'], reverse=True)
    rows = rows[:100]
    for r in rows: r.pop('_ts', None)
    return jsonify({'success': True, 'rows': rows})

@app.route('/api/user/search_cli')
@login_required
def search_cli():
    q = request.args.get('service', '').strip().lower()
    fs = load_data(FILE_SERVICES_FILE, {})
    results = [{'range': f, 'service': sv} for f, sv in fs.items() if sv and (not q or q in sv.lower())]
    return jsonify({'success': True, 'results': results})

@app.route('/api/user/notifications')
@login_required
def get_notifications():
    username = session['username']
    notifications = load_data(NOTIFICATIONS_FILE)
    user_notifications = notifications.get(username, [])
    return jsonify({'success': True, 'notifications': user_notifications})

@app.route('/api/user/mark_read', methods=['POST'])
@login_required
def mark_read():
    username = session['username']
    notifications = load_data(NOTIFICATIONS_FILE)
    if username in notifications:
        for notif in notifications[username]: notif['read'] = True
        save_data(NOTIFICATIONS_FILE, notifications)
    return jsonify({'success': True})

@app.route('/api/user/my_account')
@login_required
def get_my_account():
    username = session['username']
    users = load_data(USERS_FILE)
    return jsonify({'success': True, 'user': users.get(username, {})})

@app.route('/api/user/update_account', methods=['POST'])
@login_required
def update_account():
    data = request.get_json()
    username = session['username']
    users = load_data(USERS_FILE)
    if username in users:
        if 'password' in data and data['password']:
            if len(data['password']) < 4:
                return jsonify({'success': False, 'message': 'Password must be at least 4 characters'})
            users[username]['password'] = hash_password(data['password'])
        if 'phone' in data: users[username]['phone'] = data['phone']
        save_data(USERS_FILE, users)
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/api/user/payments')
@login_required
def get_payments():
    username = session['username']
    payments = load_data(PAYMENTS_FILE)
    return jsonify({'success': True, 'payments': payments.get(username, [])})

@app.route('/api/user/download_file', methods=['POST'])
@login_required
def download_file():
    data = request.get_json() or {}
    filename = data.get('filename')
    username = session['username']
    numbers_data = load_data(NUMBERS_FILE)
    user_numbers = numbers_data.get(username, {})
    if filename not in user_numbers: return jsonify({'success': False, 'message': 'File not found'})
    numbers = user_numbers[filename]
    n = _parse_count(data.get('count'), len(numbers))
    safe = re.sub(r'[^A-Za-z0-9_.-]', '_', f'{username}_{filename}')
    file_path = os.path.join(DATA_DIR, f'{safe}.txt')
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write('\n'.join(numbers[:n]))
    return send_file(file_path, as_attachment=True, download_name=f'{filename}_{n}.txt')

# ============================================================
# API TEST + DEBUG ENDPOINTS
# ============================================================

@app.route('/api/test_api_connection')
@owner_required
def test_api_connection():
    results = {}
    for name, fn in [('SMTSMS', fetch_smtsms_api), ('UNIXSMS', fetch_unixsms_api), ('FLY', fetch_fly_api)]:
        try:
            items = fn()
            dbg = API_DEBUG.get(name, {})
            results[name] = {
                'status': 'connected' if dbg.get('status') == 200 else 'error',
                'http_status': dbg.get('status'),
                'parsed_messages': len(items),
                'sample': items[0] if items else {},
                'raw_preview': dbg.get('raw', ''),   # if parsed_messages is 0 look here to see the real format
                'error': dbg.get('error', ''),
            }
        except Exception as e:
            results[name] = {'status': 'failed', 'error': str(e)}
    return jsonify({'success': True, 'apis': results})

@app.route('/api/debug/sms_data')
@login_required
def debug_sms_data():
    username = session['username']
    sms_data = load_data(SMS_FILE)
    numbers_data = load_data(NUMBERS_FILE)
    return jsonify({'success': True, 'username': username, 'user_sms': sms_data.get(username, {}), 'all_sms_keys': list(sms_data.keys()), 'user_numbers': numbers_data.get(username, {}), 'available_numbers': list(numbers_data.get('_available', {}).keys())})

@app.route('/api/debug/check_number/<path:number>')
@login_required
def debug_check_number(number):
    username = session['username']
    numbers_data = load_data(NUMBERS_FILE)
    sms_data = load_data(SMS_FILE)
    user_numbers = numbers_data.get(username, {})
    found_in = []
    for filename, nums in user_numbers.items():
        if number in nums: found_in.append(filename)
    user_sms = sms_data.get(username, {})
    sms_for_number = user_sms.get(number, [])
    return jsonify({'success': True, 'number': number, 'found_in_files': found_in, 'sms_count': len(sms_for_number), 'sms_messages': sms_for_number})

# ============================================================
# DATA EXPORT/IMPORT
# ============================================================


@app.route('/api/import_file', methods=['POST', 'OPTIONS'])
@owner_required
def import_file():
    """Import data from JSON file with validation and backup"""
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = app.make_response('')
        response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    try:
        # DEBUG: Log request details
        print(f"[Import] Request received. Content-Type: {request.content_type}")
        print(f"[Import] Files in request: {list(request.files.keys())}")
        print(f"[Import] Form data: {list(request.form.keys())}")

        if 'file' not in request.files:
            print("[Import] ERROR: 'file' not in request.files")
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400

        file = request.files['file']
        print(f"[Import] File object: {file}")
        print(f"[Import] File name: {file.filename}")

        if not file or file.filename == '':
            return jsonify({'success': False, 'message': 'Empty file'}), 400

        # BULLETPROOF filename extraction
        raw_filename = file.filename

        # Step 1: URL decode
        from urllib.parse import unquote
        raw_filename = unquote(raw_filename)

        # Step 2: Extract just the filename
        import os as os_module
        filename = os_module.path.basename(raw_filename)
        filename = filename.replace(chr(92), "/").split('/')[-1]
        filename = filename.strip()

        print(f"[Import] Processed filename: {filename}")

        # Step 3: Validate filename
        allowed_files = [
            'users.json', 'daily_limits.json', 'numbers.json', 'test_numbers.json',
            'sms.json', 'notifications.json', 'pending_users.json', 'payments.json',
            'user_sms_costs.json', 'smpp_config.json', 'reserve_numbers.json',
            'security_log.json', 'login_attempts.json', 'file_services.json', 'range_prices.json'
        ]

        if filename not in allowed_files:
            return jsonify({
                'success': False, 
                'message': 'Invalid file name: "' + filename + '". Allowed: ' + ', '.join(allowed_files)
            }), 400

        # Step 4: Read file content using stream (more reliable)
        try:
            # Read from the stream directly to avoid consuming the file object
            file_content = file.stream.read()
            if isinstance(file_content, bytes):
                content = file_content.decode('utf-8')
            else:
                content = file_content
            data = json.loads(content)
            print(f"[Import] JSON parsed successfully. Records: {len(data) if isinstance(data, dict) else len(data) if isinstance(data, list) else 0}")
        except json.JSONDecodeError as e:
            print(f"[Import] JSON decode error: {e}")
            return jsonify({'success': False, 'message': 'Invalid JSON format: ' + str(e)}), 400
        except UnicodeDecodeError:
            return jsonify({'success': False, 'message': 'File encoding error. Must be UTF-8.'}), 400
        except Exception as e:
            print(f"[Import] Error reading file: {e}")
            return jsonify({'success': False, 'message': 'Error reading file: ' + str(e)}), 400

        # Validate data structure
        validation_error = validate_import_data(filename, data)
        if validation_error:
            return jsonify({'success': False, 'message': validation_error}), 400

        # Create backup before import
        filepath = os_module.path.join(DATA_DIR, filename)
        if os_module.path.exists(filepath):
            backup_path = os_module.path.join(DATA_DIR, filename + '.backup.' + datetime.now().strftime("%Y%m%d_%H%M%S"))
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    backup_data = f.read()
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(backup_data)
            except Exception as e:
                print("[Import] Backup warning: " + str(e))

        # Save the new data
        save_data(filepath, data)
        print(f"[Import] File saved successfully to {filepath}")

        # Special handling for users.json
        if filename == 'users.json':
            ensure_owner_exists()

        # Send notification
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            msg = "Imported file: " + filename
            if loop.is_running():
                asyncio.create_task(send_data_change_notification("Manual Import", msg))
            else:
                loop.run_until_complete(send_data_change_notification("Manual Import", msg))
        except Exception as e:
            print("[Telegram] Import notification error: " + str(e))

        SecurityManager.log_event('data_imported', 'Imported ' + filename, session.get('username', ''))

        return jsonify({
            'success': True, 
            'message': 'File ' + filename + ' imported successfully',
            'records_count': len(data) if isinstance(data, dict) else len(data) if isinstance(data, list) else 0
        })

    except Exception as e:
        import traceback
        print("[Import Error] " + str(e))
        print(traceback.format_exc())
        return jsonify({'success': False, 'message': 'Import failed: ' + str(e)}), 500

@app.route('/api/export_file')
@owner_required
def export_file():
    """Export a single data file"""
    filename = request.args.get('file', '').strip()

    file_map = {
        'users.json': USERS_FILE,
        'daily_limits.json': DAILY_LIMITS_FILE,
        'numbers.json': NUMBERS_FILE,
        'test_numbers.json': TEST_NUMBERS_FILE,
        'sms.json': SMS_FILE,
        'notifications.json': NOTIFICATIONS_FILE,
        'pending_users.json': PENDING_USERS_FILE,
        'payments.json': PAYMENTS_FILE,
        'user_sms_costs.json': USER_SMS_COSTS_FILE,
        'smpp_config.json': SMPP_CONFIG_FILE,
        'reserve_numbers.json': RESERVE_NUMBERS_FILE,
        'security_log.json': SECURITY_LOG_FILE,
        'login_attempts.json': LOGIN_ATTEMPTS_FILE,
        'file_services.json': FILE_SERVICES_FILE,
        'range_prices.json': RANGE_PRICES_FILE,
    }

    if filename not in file_map:
        return jsonify({'success': False, 'message': f"Invalid file name: {filename}"}), 400

    filepath = file_map[filename]
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'message': 'File not found'}), 404

    return send_file(filepath, as_attachment=True, download_name=filename, mimetype='application/json')

@app.route('/api/force_check_sms')
@login_required
def force_check_sms():
    try:
        print(f"[Force Check] Triggered by user: {session['username']}")
        raw_sms = fetch_sms_from_apis()
        print(f"[Force Check] Fetched {len(raw_sms)} raw SMS from APIs")
        process_new_sms()
        sms_data = load_data(SMS_FILE)
        username = session['username']
        user_sms = sms_data.get(username, {})
        total = sum(len(msgs) for msgs in user_sms.values() if isinstance(msgs, list))
        return jsonify({'success': True, 'message': f'SMS check completed. You have {total} messages.', 'sms_count': total, 'raw_fetched': len(raw_sms), 'user_sms_keys': list(user_sms.keys())})
    except Exception as e:
        import traceback
        print(f"[Force Check Error] {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)})

# ============================================================
# SECURITY LOG API (Owner only)
# ============================================================

@app.route('/api/owner/security_logs')
@owner_required
def get_security_logs():
    """Get security audit logs"""
    logs = load_data(SECURITY_LOG_FILE, [])
    # Return last 200 logs
    return jsonify({'success': True, 'logs': logs[-200:]})

# ============================================================
# WEBSOCKET
# ============================================================

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        join_room(session['username'])

@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    if username: join_room(username)

# ============================================================
# HTML TEMPLATES
# ============================================================

INDEX_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL OTP System v2.0</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#3B82F6;--accent-glow:rgba(59,130,246,0.4);--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.7);--glass-border:rgba(255,255,255,0.08)}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#2563EB;--accent-glow:rgba(37,99,235,0.2);--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#E0E7FF 50%,#C7D2FE 100%)}
[data-theme="light"] .login-card{background:rgba(255,255,255,0.9)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#1E1B4B 50%,#312E81 100%);color:var(--foreground);line-height:1.6;min-height:100vh;overflow-x:hidden}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* Animated background */
.bg-animation{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;overflow:hidden}
.bg-animation .orb{position:absolute;border-radius:50%;filter:blur(80px);opacity:0.4;animation:float 20s infinite ease-in-out}
.bg-animation .orb:nth-child(1){width:400px;height:400px;background:#3B82F6;top:-100px;right:-100px;animation-delay:0s}
.bg-animation .orb:nth-child(2){width:300px;height:300px;background:#8B5CF6;bottom:-50px;left:-50px;animation-delay:-7s}
.bg-animation .orb:nth-child(3){width:250px;height:250px;background:#06B6D4;top:50%;left:50%;animation-delay:-14s}
@keyframes float{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(30px,-30px) scale(1.1)}66%{transform:translate(-20px,20px) scale(0.9)}}

/* Login page */
.login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;position:relative;z-index:1}
.login-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:20px;padding:48px;width:100%;max-width:440px;box-shadow:0 25px 50px rgba(0,0,0,0.4),0 0 100px rgba(59,130,246,0.1)}
.login-logo{text-align:center;margin-bottom:32px}
.login-logo img{width:160px;height:auto;margin-bottom:16px;border-radius:12px;box-shadow:0 8px 32px rgba(59,130,246,0.3)}
.login-logo h1{font-family:'Poppins',sans-serif;font-size:2.2rem;font-weight:700;background:linear-gradient(135deg,#60A5FA,#A78BFA);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.login-logo p{color:var(--muted);font-size:0.9rem}
.lang-selector{display:flex;gap:8px;margin-bottom:24px;justify-content:center;flex-wrap:wrap}
.lang-chip{padding:8px 16px;border-radius:20px;border:1px solid var(--border);background:var(--glass);color:var(--muted);font-size:0.85rem;cursor:pointer;transition:all 0.3s ease;font-family:'Inter',sans-serif}
.lang-chip:hover{border-color:var(--accent);color:var(--accent);box-shadow:0 0 12px rgba(59,130,246,0.2)}
.lang-chip.active{background:linear-gradient(135deg,var(--accent),#8B5CF6);color:#fff;border-color:transparent;box-shadow:0 4px 16px rgba(59,130,246,0.3)}
.input-group{margin-bottom:20px}
.input-group label{display:block;margin-bottom:8px;font-size:0.875rem;font-weight:500;color:var(--muted)}
.input-group input{width:100%;padding:14px 18px;border:1px solid var(--border);border-radius:12px;font-size:0.95rem;font-family:'Inter',sans-serif;transition:all 0.3s ease;color:var(--foreground);background:var(--glass)}
.input-group input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.input-group input::placeholder{color:var(--muted);opacity:0.6}
.btn{width:100%;padding:14px;border:none;border-radius:12px;font-size:0.95rem;font-weight:600;font-family:'Inter',sans-serif;cursor:pointer;transition:all 0.3s ease;display:inline-flex;align-items:center;justify-content:center;gap:10px}
.btn-primary{background:linear-gradient(135deg,var(--accent),#8B5CF6);color:#fff;box-shadow:0 4px 20px rgba(59,130,246,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(59,130,246,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(59,130,246,0.1);border-color:var(--accent);color:var(--accent)}
.divider{display:flex;align-items:center;gap:16px;margin:24px 0;color:var(--muted);font-size:0.85rem}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}
.alert{padding:14px 18px;border-radius:12px;margin-bottom:16px;font-size:0.9rem;display:none;align-items:center;gap:10px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#FCA5A5}
.alert-success{background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);color:#6EE7B7}
.register-section{display:none;margin-top:20px;padding-top:20px;border-top:1px solid var(--border)}
.register-section.show{display:block;animation:slideDown 0.3s ease}
@keyframes slideDown{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.toggle-register{text-align:center;margin-top:16px;font-size:0.9rem;color:var(--muted)}
.toggle-register a{color:#60A5FA;text-decoration:none;font-weight:600;cursor:pointer;transition:all 0.2s}
.toggle-register a:hover{color:#A78BFA;text-decoration:underline}
.loader{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:var(--glass);backdrop-filter:blur(5px);z-index:9999;justify-content:center;align-items:center;flex-direction:column}
.loader-spinner{width:56px;height:56px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 1s linear infinite}
.loader-text{margin-top:20px;color:var(--accent);font-weight:600;font-size:1.1rem}
@keyframes spin{to{transform:rotate(360deg)}}
.version-badge{display:inline-block;padding:4px 12px;background:rgba(59,130,246,0.15);border:1px solid rgba(59,130,246,0.3);border-radius:20px;font-size:0.75rem;color:#60A5FA;font-weight:600;margin-top:8px}
@media(max-width:480px){.login-card{padding:32px 20px}.login-logo h1{font-size:1.8rem}}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>
<div class="bg-animation">
    <div class="orb"></div>
    <div class="orb"></div>
    <div class="orb"></div>
</div>

<div class="loader" id="loader"><div class="loader-spinner"></div><div class="loader-text" id="loaderText">wait please</div></div>

<div style="position:fixed;top:20px;left:20px;z-index:100">
    <button onclick="toggleTheme()" id="themeToggle" style="background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:50%;width:44px;height:44px;cursor:pointer;color:var(--foreground);font-size:18px;transition:all 0.3s ease;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(0,0,0,0.1)">
        <i class="fas fa-sun" id="themeIcon"></i>
    </button>
</div>

<div class="login-page">
    <div class="login-card">
        <div class="login-logo">
            <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL Logo">
            <h1>X PANEL</h1>
            <p id="loginSubtitle">Log in to the X PANEL</p>
            <span class="version-badge">v2.0 X PANEL</span>
        </div>

        <div class="lang-selector">
            <button class="lang-chip active" onclick="selectLanguage('arabic')">العربية</button>
            <button class="lang-chip" onclick="selectLanguage('english')">English</button>
            <button class="lang-chip" onclick="selectLanguage('hindi')">हिंदी</button>
            <button class="lang-chip" onclick="selectLanguage('urdu')">اردو</button>
        </div>

        <div class="alert" id="alert"></div>

        <form id="loginForm">
            <div class="input-group">
                <label id="loginUserLabel">User</label>
                <input type="text" id="loginUsername" placeholder="Enter User" required>
            </div>
            <div class="input-group">
                <label id="loginPassLabel">Password</label>
                <input type="password" id="loginPassword" placeholder="Enter Password" required>
            </div>
            <button type="submit" class="btn btn-primary" id="loginBtn">
                <i class="fas fa-sign-in-alt"></i> <span id="loginBtnText">Login</span>
            </button>
        </form>

        <div class="toggle-register">
            <span id="noAccountText">You do not have an account?</span> 
            <a onclick="toggleRegister()" id="registerLink">Create account</a>
        </div>

        <div class="register-section" id="registerSection">
            <div class="divider"><span id="orText">أو</span></div>
            <form id="regForm">
                <div class="input-group">
                    <label id="regUserLabel">User</label>
                    <input type="text" id="regUsername" placeholder="Choose username" required>
                </div>
                <div class="input-group">
                    <label id="regPassLabel">Password</label>
                    <input type="password" id="regPassword" placeholder="Choose password" required>
                </div>
                <div class="input-group">
                    <label id="regPhoneLabel">phone number</label>
                    <input type="tel" id="regPhone" placeholder="+20xxxxxxxxxx" required>
                </div>
                <button type="submit" class="btn btn-outline" id="regBtn">
                    <i class="fas fa-paper-plane"></i> <span id="regBtnText">Send registration request</span>
                </button>
            </form>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
let currentLang='arabic';
const socket=io();

const translations={
    arabic:{
        loginSubtitle:'Log in to the X PANEL',loginUserLabel:'User',loginPassLabel:'Password',
        loginBtnText:'Login',registerBtnText:'Send registration request',
        regUserLabel:'User',regPassLabel:'Password',regPhoneLabel:'phone number',
        noAccountText:'You do not have an account?',registerLink:'Create account',
        orText:'or',loaderText:'wait please',
        loginPlaceholderUser:'Enter User',loginPlaceholderPass:'Enter Password',
        regPlaceholderUser:'Choose username',regPlaceholderPass:'Choose password',regPlaceholderPhone:'+20xxxxxxxxxx',
        loginError:'Login error',registerSuccess:'Your request has been sent to the owner, awaiting approval',
        registerError:'Registration error',dir:'rtl'
    },
    english:{
        loginSubtitle:'Login to Dashboard',loginUserLabel:'Username',loginPassLabel:'Password',
        loginBtnText:'Login',registerBtnText:'Send Registration Request',
        regUserLabel:'Username',regPassLabel:'Password',regPhoneLabel:'Phone Number',
        noAccountText:"Don't have an account?",registerLink:'Create New Account',
        orText:'OR',loaderText:'Loading...',
        loginPlaceholderUser:'Enter username',loginPlaceholderPass:'Enter password',
        regPlaceholderUser:'Choose username',regPlaceholderPass:'Choose password',regPlaceholderPhone:'+1xxxxxxxxxx',
        loginError:'Invalid credentials',registerSuccess:'Your request has been sent, pending approval',
        registerError:'Registration error',dir:'ltr'
    },
    hindi:{
        loginSubtitle:'डैशबोर्ड में लॉग इन करें',loginUserLabel:'उपयोगकर्ता नाम',loginPassLabel:'पासवर्ड',
        loginBtnText:'लॉग इन',registerBtnText:'पंजीकरण अनुरोध भेजें',
        regUserLabel:'उपयोगकर्ता नाम',regPassLabel:'पासवर्ड',regPhoneLabel:'फोन नंबर',
        noAccountText:'खाता नहीं है?',registerLink:'नया खाता बनाएं',
        orText:'या',loaderText:'लोड हो रहा है...',
        loginPlaceholderUser:'उपयोगकर्ता नाम दर्ज करें',loginPlaceholderPass:'पासवर्ड दर्ज करें',
        regPlaceholderUser:'उपयोगकर्ता नाम चुनें',regPlaceholderPass:'पासवर्ड चुनें',regPlaceholderPhone:'+91xxxxxxxxxx',
        loginError:'अमान्य क्रेडेंशियल्स',registerSuccess:'आपका अनुरोध भेज दिया गया है',
        registerError:'पंजीकरण त्रुटि',dir:'ltr'
    },
    urdu:{
        loginSubtitle:'ڈیش بورڈ میں لاگ ان کریں',loginUserLabel:'صارف نام',loginPassLabel:'پاس ورڈ',
        loginBtnText:'لاگ ان',registerBtnText:'رجسٹریشن کی درخواست بھیجیں',
        regUserLabel:'صارف نام',regPassLabel:'پاس ورڈ',regPhoneLabel:'فون نمبر',
        noAccountText:'اکاؤنٹ نہیں ہے?',registerLink:'نیا اکاؤنٹ بنائیں',
        orText:'یا',loaderText:'لوڈ ہو رہا ہے...',
        loginPlaceholderUser:'صارف نام درج کریں',loginPlaceholderPass:'پاس ورڈ درج کریں',
        regPlaceholderUser:'صارف نام منتخب کریں',regPlaceholderPass:'پاس ورڈ منتخب کریں',regPlaceholderPhone:'+92xxxxxxxxxx',
        loginError:'غلط اسناد',registerSuccess:'آپ کی درخواست بھیج دی گئی ہے',
        registerError:'رجسٹریشن میں خرابی',dir:'rtl'
    }
};

function applyLanguage(lang){
    const t=translations[lang];
    document.getElementById('loginSubtitle').textContent=t.loginSubtitle;
    document.getElementById('loginUserLabel').textContent=t.loginUserLabel;
    document.getElementById('loginPassLabel').textContent=t.loginPassLabel;
    document.getElementById('loginBtnText').textContent=t.loginBtnText;
    document.getElementById('regBtnText').textContent=t.registerBtnText;
    document.getElementById('regUserLabel').textContent=t.regUserLabel;
    document.getElementById('regPassLabel').textContent=t.regPassLabel;
    document.getElementById('regPhoneLabel').textContent=t.regPhoneLabel;
    document.getElementById('noAccountText').textContent=t.noAccountText;
    document.getElementById('registerLink').textContent=t.registerLink;
    document.getElementById('orText').textContent=t.orText;
    document.getElementById('loaderText').textContent=t.loaderText;
    document.getElementById('loginUsername').placeholder=t.loginPlaceholderUser;
    document.getElementById('loginPassword').placeholder=t.loginPlaceholderPass;
    document.getElementById('regUsername').placeholder=t.regPlaceholderUser;
    document.getElementById('regPassword').placeholder=t.regPlaceholderPass;
    document.getElementById('regPhone').placeholder=t.regPlaceholderPhone;
    document.body.dir=t.dir;
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIcon');
    icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
    document.getElementById('themeToggle').style.color='var(--foreground)';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIcon');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function selectLanguage(lang){
    currentLang=lang;
    document.querySelectorAll('.lang-chip').forEach(c=>c.classList.remove('active'));
    event.target.classList.add('active');
    fetch('/set_language',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({language:lang})});
    applyLanguage(lang);
}

function toggleRegister(){
    const section=document.getElementById('registerSection');
    section.classList.toggle('show');
}

function showAlert(message,type){
    const alert=document.getElementById('alert');
    alert.className='alert alert-'+type;
    alert.innerHTML=type==='success'?`<i class="fas fa-check-circle"></i> ${message}`:`<i class="fas fa-exclamation-circle"></i> ${message}`;
    alert.style.display='flex';
    setTimeout(()=>alert.style.display='none',5000);
}

function showLoader(){document.getElementById('loader').style.display='flex';}
function hideLoader(){document.getElementById('loader').style.display='none';}

document.getElementById('loginForm').addEventListener('submit',async(e)=>{
    e.preventDefault();showLoader();
    const response=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('loginUsername').value,password:document.getElementById('loginPassword').value})});
    const data=await response.json();hideLoader();
    if(data.success){window.location.href='/dashboard';}
    else{showAlert(data.message||translations[currentLang].loginError,'error');}
});

document.getElementById('regForm').addEventListener('submit',async(e)=>{
    e.preventDefault();showLoader();
    const response=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('regUsername').value,password:document.getElementById('regPassword').value,phone:document.getElementById('regPhone').value})});
    const data=await response.json();hideLoader();
    if(data.success){showAlert(translations[currentLang].registerSuccess,'success');document.getElementById('registerSection').classList.remove('show');}
    else{showAlert(data.message||translations[currentLang].registerError,'error');}
});

if('Notification' in window&&Notification.permission==='default'){Notification.requestPermission();}
socket.on('broadcast',(data)=>{if(Notification.permission==='granted'){new Notification('X PANEL',{body:data.message});}});
</script>
</body>
</html>
"""

OWNER_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - Owner Panel v2.0</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#3B82F6;--accent-purple:#8B5CF6;--accent-cyan:#06B6D4;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#2563EB;--accent-purple:#7C3AED;--accent-cyan:#0891B2;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#E0E7FF 50%,#C7D2FE 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .file-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .sms-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .notification-panel{background:rgba(255,255,255,0.9)}
[data-theme="light"] .footer{background:rgba(255,255,255,0.9)}
[data-theme="light"] .file-upload{background:rgba(255,255,255,0.5)}
[data-theme="light"] .nav-item:hover{background:rgba(59,130,246,0.1)}
[data-theme="light"] .nav-item.active{background:linear-gradient(135deg,rgba(59,130,246,0.15),rgba(139,92,246,0.15));border:1px solid rgba(59,130,246,0.2);color:#1E40AF}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active i{color:#2563EB}
[data-theme="light"] tbody tr:hover{background:rgba(59,130,246,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select,[data-theme="light"] .form-group textarea{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .form-group input:focus,[data-theme="light"] .form-group select:focus,[data-theme="light"] .form-group textarea:focus{border-color:#2563EB;box-shadow:0 0 0 3px rgba(37,99,235,0.15)}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline:hover{background:rgba(59,130,246,0.1);border-color:#2563EB;color:#2563EB}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .login-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .login-logo h1{background:linear-gradient(135deg,#2563EB,#7C3AED);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#1E1B4B 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* ===== SIDEBAR ===== */
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(59,130,246,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#60A5FA,#A78BFA);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(59,130,246,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(59,130,246,0.2),rgba(139,92,246,0.2));color:#fff;border:1px solid rgba(59,130,246,0.3)}
.nav-item.active i{color:#60A5FA}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}
.role-badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:0.6rem;font-weight:700;margin-right:auto}
.role-owner{background:linear-gradient(135deg,#F59E0B,#EF4444);color:white}

/* ===== MAIN CONTENT ===== */
.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

/* ===== HEADER ===== */
.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--accent);background:rgba(59,130,246,0.1)}
.notification-badge{position:absolute;top:4px;right:4px;width:8px;height:8px;background-color:var(--destructive);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(1.2)}}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent-purple));border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

/* ===== SECTIONS ===== */
.page-section{margin-bottom:20px}
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}
.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ===== CARDS ===== */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(59,130,246,0.3)}
.stat-card .icon{font-size:24px;margin-bottom:8px;display:block}
.stat-card .number{font-family:'Poppins',sans-serif;font-size:1.6rem;font-weight:700;margin-bottom:4px;color:var(--foreground)}
.stat-card .label{color:var(--muted);font-size:12px}

/* ===== BUTTONS ===== */
.action-buttons{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;box-shadow:0 4px 16px rgba(59,130,246,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(59,130,246,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(59,130,246,0.1);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--destructive);color:white}
.btn-danger:hover{background:#DC2626;transform:translateY(-2px);box-shadow:0 4px 16px rgba(239,68,68,0.3)}
.btn-success{background:var(--success);color:white}
.btn-success:hover{background:#059669;transform:translateY(-2px)}
.btn-warning{background:var(--warning);color:white}
.btn-warning:hover{background:#D97706}
.btn-sm{padding:6px 12px;font-size:12px}

/* ===== FORMS ===== */
.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-container:hover{border-color:rgba(59,130,246,0.2)}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group textarea,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group textarea:focus,.form-group select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,0.15)}
.form-group input::placeholder,.form-group textarea::placeholder{color:var(--muted);opacity:0.5}
.file-upload{border:2px dashed var(--border);border-radius:12px;padding:32px;text-align:center;cursor:pointer;transition:all 0.3s ease;margin-bottom:16px;background:var(--glass)}
.file-upload:hover{border-color:var(--accent);background:rgba(59,130,246,0.05)}
.file-upload i{font-size:2.5rem;color:var(--accent);margin-bottom:12px}
.file-upload p{color:var(--muted);font-size:13px}

/* ===== TABLE ===== */
.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.table-controls{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);flex-wrap:wrap;gap:12px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(59,130,246,0.05)}
.checkbox{width:16px;height:16px;cursor:pointer;accent-color:var(--accent)}
.text-primary{color:#60A5FA;font-weight:500}
.text-muted{color:var(--muted)}
.text-mono{font-family:'Courier New',monospace;font-weight:500;font-size:12px}
.text-success{color:var(--success);font-weight:500}
.text-danger{color:var(--destructive);font-weight:500}

/* ===== STATUS BADGES ===== */
.status-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;display:inline-block}
.status-active{background:rgba(16,185,129,0.15);color:#34D399;border:1px solid rgba(16,185,129,0.3)}
.status-pending{background:rgba(245,158,11,0.15);color:#FBBF24;border:1px solid rgba(245,158,11,0.3)}
.status-banned{background:rgba(239,68,68,0.15);color:#FCA5A5;border:1px solid rgba(239,68,68,0.3)}
.status-admin{background:rgba(59,130,246,0.15);color:#60A5FA;border:1px solid rgba(59,130,246,0.3)}
.status-general{background:rgba(6,182,212,0.15);color:#22D3EE;border:1px solid rgba(6,182,212,0.3)}
.status-legend{background:rgba(139,92,246,0.15);color:#A78BFA;border:1px solid rgba(139,92,246,0.3)}

/* ===== FILE CARDS ===== */
.files-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.file-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.file-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(59,130,246,0.3)}
.file-card h4{color:#60A5FA;margin-bottom:12px;font-size:15px;display:flex;align-items:center;gap:8px}
.file-card .info{display:flex;justify-content:space-between;margin-bottom:10px;color:var(--muted);font-size:13px}
.file-card .cost{color:var(--success);font-weight:700;font-size:16px}
.qty-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px}
.qty-btn{padding:10px;background:rgba(59,130,246,0.08);border:1px solid var(--border);border-radius:8px;color:#60A5FA;font-family:'Poppins',sans-serif;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s ease}
.qty-btn:hover,.qty-btn.selected{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;border-color:transparent;transform:scale(1.02)}

/* ===== RESERVE SECTION SPECIAL STYLES ===== */
.reserve-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:20px;color:#A78BFA;font-size:12px;font-weight:600}
.reserve-section-header{display:flex;align-items:center;gap:12px;margin-bottom:16px}

/* ===== SMS CARDS ===== */
.sms-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:16px;margin-bottom:12px;transition:all 0.3s ease}
.sms-card:hover{border-color:rgba(59,130,246,0.3);box-shadow:0 4px 16px rgba(59,130,246,0.1)}
.sms-card .phone{color:#60A5FA;font-weight:600;font-size:14px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.sms-card .message{color:var(--foreground);margin-bottom:10px;line-height:1.6;font-size:13px}
.sms-card .meta{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);align-items:center}
.sms-card .api-badge{background:rgba(59,130,246,0.15);color:#60A5FA;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600}

/* ===== NOTIFICATION PANEL ===== */
.notification-panel{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:16px;margin-bottom:12px;transition:all 0.2s ease}
.notification-panel.unread{border-color:var(--warning);background:rgba(245,158,11,0.05)}
.notification-panel .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.notification-panel .type{background:rgba(59,130,246,0.15);color:#60A5FA;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600}
.notification-panel .time{color:var(--muted);font-size:12px}
.notification-panel p{font-size:13px;color:var(--foreground);line-height:1.5}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
.toast.info{border-right-color:var(--accent)}
.toast.warning{border-right-color:var(--warning)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ===== FOOTER ===== */
.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}

/* ===== RESPONSIVE ===== */

[data-theme="light"] .numbers-table th{background:rgba(241,245,249,0.9);color:#64748B;border-bottom:2px solid #CBD5E1}
[data-theme="light"] .numbers-table td{border-bottom:1px solid #E2E8F0;color:#0F172A}
[data-theme="light"] .numbers-table tbody tr:hover{background:rgba(59,130,246,0.05)}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
    .header{flex-direction:column;align-items:flex-start;gap:10px;padding:12px 20px}
    .header-right{width:100%;justify-content:flex-start}
    .page-content{padding:16px 20px}
    .cards-grid{grid-template-columns:1fr}
    .qty-grid{grid-template-columns:repeat(2,1fr)}
    .files-grid{grid-template-columns:1fr}
    table{font-size:12px}
    th,td{padding:10px 12px}
}
@media(max-width:640px){
    .header-left h2{font-size:18px}
    .section-title{font-size:16px}
    .user-name{display:none}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<!-- SIDEBAR -->
<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>OWNER CONTROL PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)">
            <i class="fas fa-home"></i> Dashboard
        </button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Number management</div>
        <button class="nav-item" onclick="showSection('addNumbers',this)">
            <i class="fas fa-plus-circle"></i> Add numbers
        </button>
        <button class="nav-item" onclick="showSection('deleteNumbers',this)">
            <i class="fas fa-trash"></i> delete numbers
        </button>
        <button class="nav-item" onclick="showSection('deleteAllNumbers',this)">
            <i class="fas fa-trash-alt"></i> Delete all numbers
        </button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Reserve Numbers <span style="color:#A78BFA">(Private)</span></div>
        <button class="nav-item" onclick="showSection('addReserve',this)">
            <i class="fas fa-shield-alt"></i> Add reserve numbers
        </button>
        <button class="nav-item" onclick="showSection('viewReserve',this)">
            <i class="fas fa-eye"></i> View reserve numbers
        </button>
        <button class="nav-item" onclick="showSection('deleteReserve',this)">
            <i class="fas fa-trash"></i> delete reserve numbers
        </button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">tests</div>
        <button class="nav-item" onclick="showSection('addTest',this)">
            <i class="fas fa-vial"></i> Add experimental
        </button>
        <button class="nav-item" onclick="showSection('deleteTest',this)">
            <i class="fas fa-trash"></i> delete experimental
        </button>
        <button class="nav-item" onclick="showSection('deleteAllTest',this)">
            <i class="fas fa-trash-alt"></i> delete all experimental
        </button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">users</div>
        <button class="nav-item" onclick="showSection('pendingUsers',this)">
            <i class="fas fa-user-clock"></i> Registration requests
        </button>
        <button class="nav-item" onclick="showSection('accounts',this)">
            <i class="fas fa-users"></i> Accounts
        </button>
        <button class="nav-item" onclick="showSection('userStatistics',this)">
            <i class="fas fa-chart-bar"></i> User statistics
        </button>
        <button class="nav-item" onclick="showSection('rangeStatistics',this)">
            <i class="fas fa-signal"></i> Most accessed ranges
        </button>
        <button class="nav-item" onclick="showSection('smsCosts',this)">
            <i class="fas fa-dollar-sign"></i> Message pricing
        </button>
        <button class="nav-item" onclick="showSection('increaseLimit',this)">
            <i class="fas fa-user-plus"></i> Add numbers to user
        </button>
        <button class="nav-item" onclick="showSection('addAdmin',this)">
            <i class="fas fa-user-shield"></i> Add admin
        </button>
        <button class="nav-item" onclick="showSection('addGeneral',this)">
            <i class="fas fa-star" style="color:#06B6D4"></i> Add General
        </button>
        <button class="nav-item" onclick="showSection('addLegend',this)">
            <i class="fas fa-bolt" style="color:#8B5CF6"></i> Add Legend
        </button>
        <button class="nav-item" onclick="showSection('deleteAdmin',this)">
            <i class="fas fa-user-times"></i> delete admin
        </button>
        <button class="nav-item" onclick="showSection('deleteGeneral',this)">
            <i class="fas fa-user-times" style="color:#06B6D4"></i> delete General
        </button>
        <button class="nav-item" onclick="showSection('deleteLegend',this)">
            <i class="fas fa-user-times" style="color:#8B5CF6"></i> delete Legend
        </button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">security</div>
        <button class="nav-item" onclick="showSection('securityLogs',this)">
            <i class="fas fa-shield-alt"></i> Security logs
        </button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">data</div>
        <button class="nav-item" onclick="showSection('dataExport',this)">
            <i class="fas fa-database"></i> Export/import
        </button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">communication</div>
        <button class="nav-item" onclick="showSection('broadcast',this)">
            <i class="fas fa-broadcast-tower"></i> Broadcast message
        </button>
        <button class="nav-item" onclick="showSection('notifications',this)">
            <i class="fas fa-bell"></i> notifications
        </button>
        <button class="nav-item" onclick="showSection('apiTest',this)">
            <i class="fas fa-plug"></i> Check APIs
        </button>
        <button class="nav-item" onclick="showSection('smppConfig',this)">
            <i class="fas fa-network-wired"></i> SMPP settings
        </button>
    </div>
</div>

<!-- MAIN CONTENT -->
<div class="main-content">
    <!-- HEADER -->
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-crown" style="color:var(--warning)"></i> Control Panel - Owner</h2>
            <p>System and user management</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <button class="header-icon-btn" onclick="showSection('notifications',this)" title="notifications">
                <i class="fas fa-bell"></i>
                <span class="notification-badge" id="notifBadge" style="display:none"></span>
            </button>
            <button class="header-icon-btn" title="Settings"><i class="fas fa-cog"></i></button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar">M</div>
                <span class="user-name">Patrickselvaa</span>
                <span class="role-badge role-owner">OWNER</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <!-- PAGE CONTENT -->
    <div class="page-content">
        <!-- DASHBOARD -->
        <div class="content-section active" id="dashboard">
            <div class="cards-grid">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128101;</span><div class="number" id="totalUsers">0</div><div class="label">Total users</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128241;</span><div class="number" id="totalNumbers">0</div><div class="label">Total available numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--warning)">&#9203;</span><div class="number" id="pendingCount">0</div><div class="label">Pending requests</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--destructive)">&#128683;</span><div class="number" id="bannedCount">0</div><div class="label">Banned accounts</div></div>
                <div class="stat-card"><span class="icon" style="color:#A78BFA">&#128737;</span><div class="number" id="reserveCount">0</div><div class="label">Reserve numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--accent-cyan)">&#128230;</span><div class="number" id="reserveFilesCount">0</div><div class="label">Reserve files</div></div>
            </div>
        </div>

        <!-- ADD NUMBERS -->
        <div class="content-section" id="addNumbers">
            <h3 class="section-title"><i class="fas fa-plus-circle"></i> Add new numbers</h3>
            <div class="form-container">
                <div class="file-upload" onclick="document.getElementById('numberFile').click()">
                    <i class="fas fa-cloud-upload-alt"></i>
                    <p>Click to upload numbers file (.txt)</p>
                    <p style="color:var(--muted);font-size:12px;margin-top:6px">One number per line</p>
                    <input type="file" id="numberFile" accept=".txt" style="display:none" onchange="handleFileSelect(this)">
                </div>
                <div class="filter-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>File name</label><input type="text" id="fileName" placeholder="Example: Egypt numbers"></div>
                    <div class="form-group"><label>Cost per number ($)</label><input type="number" id="fileCost" placeholder="0.00" step="0.01"></div>
                    <div class="form-group"><label>SMS price for this range ($)</label><input type="number" id="fileSmsPrice" placeholder="0.01" step="0.001"></div>
                    <div class="form-group"><label>Service (Whatsapp / Telegram ...)</label><input type="text" id="fileService" list="serviceOptions" placeholder="Example: Whatsapp"><datalist id="serviceOptions"><option value="Whatsapp"><option value="Telegram"><option value="Facebook"><option value="Instagram"><option value="Google"><option value="PayPal"></datalist></div>
                </div>
                <button class="btn btn-primary" onclick="addNumbers()"><i class="fas fa-save"></i> Save numbers</button>
            </div>
        </div>

        <!-- DELETE NUMBERS -->
        <div class="content-section" id="deleteNumbers">
            <h3 class="section-title"><i class="fas fa-trash"></i> delete numbers</h3>
            <div class="form-container">
                <div class="form-group"><label>Select numbers file</label><select id="deleteFileSelect" class="filter-select" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"><option value="">-- Select file --</option></select></div>
                <button class="btn btn-danger" onclick="deleteNumbers()"><i class="fas fa-trash"></i> delete File</button>
            </div>
        </div>

        <!-- DELETE ALL NUMBERS -->
        <div class="content-section" id="deleteAllNumbers">
            <h3 class="section-title"><i class="fas fa-trash-alt"></i> Delete all numbers</h3>
            <div class="form-container" style="text-align:center">
                <i class="fas fa-exclamation-triangle" style="font-size:4rem;color:var(--destructive);margin-bottom:20px"></i>
                <p style="margin-bottom:30px;font-size:1.1rem">This action will delete all numbers from all users!</p>
                <button class="btn btn-danger" onclick="deleteAllNumbers()"><i class="fas fa-trash-alt"></i> Yes, delete all numbers</button>
            </div>
        </div>

        <!-- ADD RESERVE NUMBERS -->
        <div class="content-section" id="addReserve">
            <div class="reserve-section-header">
                <h3 class="section-title" style="margin:0"><i class="fas fa-shield-alt" style="color:#A78BFA"></i> Add reserve numbers</h3>
                <span class="reserve-badge"><i class="fas fa-lock"></i> Owner/General/Legend only</span>
            </div>
            <div class="form-container" style="border-color:rgba(139,92,246,0.3)">
                <p style="color:var(--muted);margin-bottom:16px;font-size:13px">Reserve numbers are only visible to Owner, General, and Legend accounts. Users cannot see or access these numbers.</p>
                <div class="file-upload" onclick="document.getElementById('reserveFile').click()" style="border-color:rgba(139,92,246,0.3)">
                    <i class="fas fa-cloud-upload-alt" style="color:#A78BFA"></i>
                    <p>Click to upload reserve numbers file (.txt)</p>
                    <p style="color:var(--muted);font-size:12px;margin-top:6px">One number per line - Private file</p>
                    <input type="file" id="reserveFile" accept=".txt" style="display:none" onchange="handleReserveFileSelect(this)">
                </div>
                <div class="filter-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>File name</label><input type="text" id="reserveFileName" placeholder="Example: Reserve USA"></div>
                    <div class="form-group"><label>Cost per number ($)</label><input type="number" id="reserveFileCost" placeholder="0.00" step="0.01"></div>
                </div>
                <button class="btn btn-primary" onclick="addReserveNumbers()" style="background:linear-gradient(135deg,#8B5CF6,#6366F1)"><i class="fas fa-save"></i> Save reserve numbers</button>
            </div>
        </div>

        <!-- VIEW RESERVE NUMBERS -->
        <div class="content-section" id="viewReserve">
            <div class="reserve-section-header">
                <h3 class="section-title" style="margin:0"><i class="fas fa-eye" style="color:#A78BFA"></i> View reserve numbers</h3>
                <span class="reserve-badge"><i class="fas fa-lock"></i> Private</span>
            </div>
            <div id="reserveFilesList"></div>
        </div>

        <!-- DELETE RESERVE NUMBERS -->
        <div class="content-section" id="deleteReserve">
            <h3 class="section-title"><i class="fas fa-trash" style="color:#A78BFA"></i> delete reserve numbers</h3>
            <div class="form-container">
                <div class="form-group"><label>Select reserve file</label><select id="deleteReserveSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"><option value="">-- Select file --</option></select></div>
                <button class="btn btn-danger" onclick="deleteReserveNumbers()"><i class="fas fa-trash"></i> delete reserve File</button>
            </div>
        </div>

        <!-- ADD TEST -->
        <div class="content-section" id="addTest">
            <h3 class="section-title"><i class="fas fa-vial"></i> Add Test numbers</h3>
            <div class="form-container">
                <div class="file-upload" onclick="document.getElementById('testFile').click()">
                    <i class="fas fa-cloud-upload-alt"></i>
                    <p>Click to upload Test numbers file</p>
                    <input type="file" id="testFile" accept=".txt" style="display:none" onchange="handleTestFileSelect(this)">
                </div>
                <div class="form-group"><label>File name</label><input type="text" id="testFileName" placeholder="File name"></div>
                <button class="btn btn-primary" onclick="addTestNumbers()"><i class="fas fa-save"></i> Save</button>
            </div>
        </div>

        <!-- DELETE TEST -->
        <div class="content-section" id="deleteTest">
            <h3 class="section-title"><i class="fas fa-trash"></i> delete Test numbers</h3>
            <div class="form-container">
                <div class="form-group"><label>Select file</label><select id="deleteTestSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"><option value="">-- Select --</option></select></div>
                <button class="btn btn-danger" onclick="deleteTestNumbers()"><i class="fas fa-trash"></i> delete</button>
            </div>
        </div>

        <!-- DELETE ALL TEST -->
        <div class="content-section" id="deleteAllTest">
            <h3 class="section-title"><i class="fas fa-trash-alt"></i> delete all experimental</h3>
            <div class="form-container" style="text-align:center">
                <i class="fas fa-exclamation-triangle" style="font-size:4rem;color:var(--destructive);margin-bottom:20px"></i>
                <p style="margin-bottom:30px">All experimental numbers will be deleted!</p>
                <button class="btn btn-danger" onclick="deleteAllTest()"><i class="fas fa-trash-alt"></i> delete all</button>
            </div>
        </div>

        <!-- PENDING USERS -->
        <div class="content-section" id="pendingUsers">
            <h3 class="section-title"><i class="fas fa-user-clock"></i> Registration requests</h3>
            <div class="form-container">
                <div class="action-buttons">
                    <button class="btn btn-success" onclick="approveAllUsers()"><i class="fas fa-check-double"></i> Approve all</button>
                </div>
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>User</th><th>phone number</th><th>Request date</th><th>Actions</th></tr></thead>
                        <tbody id="pendingUsersTable"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ACCOUNTS -->
        <div class="content-section" id="accounts">
            <h3 class="section-title"><i class="fas fa-users"></i> Account management</h3>
            <div class="table-wrapper">
                <div class="table-controls">
                    <div class="table-show"><span>Show</span><select><option>10</option><option>25</option><option>50</option></select><span>entries</span></div>
                    <div class="table-export">
                        <button class="btn btn-outline btn-sm" onclick="exportTable('csv')"><i class="fas fa-file-csv"></i> CSV</button>
                        <button class="btn btn-outline btn-sm" onclick="exportTable('excel')"><i class="fas fa-file-excel"></i> Excel</button>
                    </div>
                </div>
                <table>
                    <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Limit</th><th>Actions</th></tr></thead>
                    <tbody id="accountsTable"></tbody>
                </table>
            </div>
        </div>

        <!-- SMS COSTS -->
        <div class="content-section" id="smsCosts">
            <h3 class="section-title"><i class="fas fa-dollar-sign"></i> Message pricing (SMS)</h3>
            <div class="form-container">
                <p style="color:var(--muted);margin-bottom:16px;font-size:13px">Set the price per SMS for each user. Default: $0.01</p>
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Price per message ($)</th><th>Actions</th></tr></thead>
                        <tbody id="smsCostsTable"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- RANGE STATISTICS -->
        <div class="content-section" id="rangeStatistics">
            <h3 class="section-title"><i class="fas fa-signal"></i> Most accessed ranges</h3>
            <div class="cards-grid" style="margin-bottom:24px">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128194;</span><div class="number" id="rangeTotalFiles">0</div><div class="label">Total active ranges</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128172;</span><div class="number" id="rangeTotalSMS">0</div><div class="label">Total messages</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--warning)">&#128241;</span><div class="number" id="rangeTotalNumbers">0</div><div class="label">Total active numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--destructive)">&#128101;</span><div class="number" id="rangeTotalUsers">0</div><div class="label">Total active users</div></div>
            </div>
            <div class="table-wrapper">
                <div class="table-controls">
                    <div class="table-show"><span>Show</span><select id="rangeShowCount" onchange="loadRangeStatistics()"><option>10</option><option>25</option><option>50</option><option>100</option></select><span>entries</span></div>
                    <div class="table-export">
                        <button class="btn btn-outline btn-sm" onclick="exportRangeStats('csv')"><i class="fas fa-file-csv"></i> CSV</button>
                        <button class="btn btn-outline btn-sm" onclick="exportRangeStats('excel')"><i class="fas fa-file-excel"></i> Excel</button>
                    </div>
                </div>
                <table>
                    <thead><tr><th>#</th><th>File name (range)</th><th>Message count</th><th>Active numbers</th><th>Active users</th><th>Last message</th><th>Activity</th></tr></thead>
                    <tbody id="rangeStatisticsTable"></tbody>
                </table>
            </div>
        </div>

        <!-- USER STATISTICS -->
        <div class="content-section" id="userStatistics">
            <h3 class="section-title"><i class="fas fa-chart-bar"></i> User statistics</h3>
            <div class="cards-grid" style="margin-bottom:24px">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128101;</span><div class="number" id="statsTotalUsers">0</div><div class="label">Total users</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128241;</span><div class="number" id="statsTotalNumbers">0</div><div class="label">Total numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--warning)">&#128172;</span><div class="number" id="statsTotalSMS">0</div><div class="label">Total messages</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--destructive)">&#128176;</span><div class="number" id="statsTotalSpent">0</div><div class="label">Total expenses ($)</div></div>
            </div>
            <div class="table-wrapper">
                <div class="table-controls">
                    <div class="table-show"><span>Show</span><select id="statsShowCount" onchange="loadUserStatistics()"><option>10</option><option>25</option><option>50</option><option>100</option></select><span>entries</span></div>
                    <div class="table-export">
                        <button class="btn btn-outline btn-sm" onclick="exportStatistics('csv')"><i class="fas fa-file-csv"></i> CSV</button>
                        <button class="btn btn-outline btn-sm" onclick="exportStatistics('excel')"><i class="fas fa-file-excel"></i> Excel</button>
                    </div>
                </div>
                <table>
                    <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Limit</th><th>Numbers</th><th>Files</th><th>Messages</th><th>Expenses ($)</th><th>Registration date</th></tr></thead>
                    <tbody id="statisticsTable"></tbody>
                </table>
            </div>
        </div>

        <!-- SECURITY LOGS -->
        <div class="content-section" id="securityLogs">
            <h3 class="section-title"><i class="fas fa-shield-alt" style="color:var(--destructive)"></i> Security logs</h3>
            <div class="table-wrapper">
                <div class="table-controls">
                    <span style="color:var(--muted);font-size:13px">Last 200 security events</span>
                    <button class="btn btn-outline btn-sm" onclick="loadSecurityLogs()"><i class="fas fa-sync-alt"></i> Refresh</button>
                </div>
                <table>
                    <thead><tr><th>Time</th><th>Type</th><th>User</th><th>Details</th><th>IP</th></tr></thead>
                    <tbody id="securityLogsTable"></tbody>
                </table>
            </div>
        </div>

        <!-- ADD NUMBERS TO USER -->
        <div class="content-section" id="increaseLimit">
            <h3 class="section-title"><i class="fas fa-user-plus"></i> Add numbers to user</h3>
            <div class="form-container">
                <div class="filter-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Username</label><select id="limitUserSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                    <div class="form-group"><label>Select file</label><select id="addNumbersFileSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                    <div class="form-group"><label>Number count</label><input type="number" id="addNumbersCount" placeholder="Example: 1000" min="1"></div>
                </div>
                <button class="btn btn-primary" onclick="addNumbersToUser()"><i class="fas fa-plus"></i> Add numbers</button>
            </div>
        </div>

        <!-- ADD ADMIN -->
        <div class="content-section" id="addAdmin">
            <h3 class="section-title"><i class="fas fa-user-shield"></i> Add admin</h3>
            <div class="form-container">
                <div class="filter-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Username</label><input type="text" id="adminUsername" placeholder="Admin name"></div>
                    <div class="form-group"><label>Password</label><input type="password" id="adminPassword" placeholder="Password"></div>
                </div>
                <button class="btn btn-primary" onclick="addAdmin()"><i class="fas fa-user-plus"></i> Create admin</button>
            </div>
        </div>

        <!-- ADD GENERAL -->
        <div class="content-section" id="addGeneral">
            <h3 class="section-title"><i class="fas fa-star" style="color:#06B6D4"></i> Add General account</h3>
            <div class="form-container" style="border-color:rgba(6,182,212,0.3)">
                <p style="color:var(--muted);margin-bottom:16px;font-size:13px">General accounts can distribute numbers to users and manage reserve numbers.</p>
                <div class="filter-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Username</label><input type="text" id="generalUsername" placeholder="General account name"></div>
                    <div class="form-group"><label>Password</label><input type="password" id="generalPassword" placeholder="Password"></div>
                </div>
                <button class="btn btn-primary" onclick="addGeneral()" style="background:linear-gradient(135deg,#06B6D4,#0891B2)"><i class="fas fa-user-plus"></i> Create General account</button>
            </div>
        </div>

        <!-- ADD LEGEND -->
        <div class="content-section" id="addLegend">
            <h3 class="section-title"><i class="fas fa-bolt" style="color:#8B5CF6"></i> Add Legend account</h3>
            <div class="form-container" style="border-color:rgba(139,92,246,0.3)">
                <p style="color:var(--muted);margin-bottom:16px;font-size:13px">Legend accounts can create users directly without approval and manage reserve numbers.</p>
                <div class="filter-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Username</label><input type="text" id="legendNewUsername" placeholder="Legend account name"></div>
                    <div class="form-group"><label>Password</label><input type="password" id="legendNewPassword" placeholder="Password"></div>
                </div>
                <button class="btn btn-primary" onclick="addLegend()" style="background:linear-gradient(135deg,#8B5CF6,#A855F7)"><i class="fas fa-user-plus"></i> Create Legend account</button>
            </div>
        </div>

        <!-- DELETE ADMIN -->
        <div class="content-section" id="deleteAdmin">
            <h3 class="section-title"><i class="fas fa-user-times"></i> delete admin</h3>
            <div class="form-container">
                <div class="form-group"><label>Admin name</label><select id="adminSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                <button class="btn btn-danger" onclick="deleteAdmin()"><i class="fas fa-user-times"></i> delete admin permissions</button>
            </div>
        </div>

        <!-- DELETE GENERAL -->
        <div class="content-section" id="deleteGeneral">
            <h3 class="section-title"><i class="fas fa-user-times" style="color:#06B6D4"></i> delete General account</h3>
            <div class="form-container" style="border-color:rgba(6,182,212,0.3)">
                <div class="form-group"><label>General account name</label><select id="generalSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                <button class="btn btn-danger" onclick="deleteGeneral()" style="background:linear-gradient(135deg,#EF4444,#DC2626)"><i class="fas fa-user-times"></i> delete General permissions</button>
            </div>
        </div>

        <!-- DELETE LEGEND -->
        <div class="content-section" id="deleteLegend">
            <h3 class="section-title"><i class="fas fa-user-times" style="color:#8B5CF6"></i> delete Legend account</h3>
            <div class="form-container" style="border-color:rgba(139,92,246,0.3)">
                <div class="form-group"><label>Legend account name</label><select id="legendSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                <button class="btn btn-danger" onclick="deleteLegend()" style="background:linear-gradient(135deg,#EF4444,#DC2626)"><i class="fas fa-user-times"></i> delete Legend permissions</button>
            </div>
        </div>

        <!-- BROADCAST -->
        <div class="content-section" id="broadcast">
            <h3 class="section-title"><i class="fas fa-broadcast-tower"></i> Broadcast message</h3>
            <div class="form-container">
                <div class="form-group"><label>Message</label><textarea id="broadcastMessage" rows="5" placeholder="Write your message here..."></textarea></div>
                <button class="btn btn-primary" onclick="sendBroadcast()"><i class="fas fa-paper-plane"></i> Send to all</button>
            </div>
        </div>

        <!-- NOTIFICATIONS -->
        <div class="content-section" id="notifications">
            <h3 class="section-title"><i class="fas fa-bell"></i> notifications</h3>
            <div id="notificationsList"></div>
        </div>

        <!-- EXPORT/IMPORT DATA -->
        <div class="content-section" id="dataExport">
            <h3 class="section-title"><i class="fas fa-database"></i> Export and import data</h3>
            <div class="form-container">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">
                    <div style="text-align:center;padding:30px;border:2px dashed var(--accent);border-radius:12px;background:rgba(59,130,246,0.05)">
                        <i class="fas fa-file-export" style="font-size:3rem;color:var(--accent);margin-bottom:16px"></i>
                        <h4 style="margin-bottom:12px;color:var(--accent)">Export data</h4>
                        <p style="color:var(--muted);margin-bottom:20px;font-size:13px">Export all data files (JSON) for download</p>
                        <button class="btn btn-primary" onclick="exportAllData()" style="width:100%"><i class="fas fa-download"></i> Export all</button>
                    </div>
                    <div style="text-align:center;padding:30px;border:2px dashed var(--success);border-radius:12px;background:rgba(16,185,129,0.05)">
                        <i class="fas fa-file-import" style="font-size:3rem;color:var(--success);margin-bottom:16px"></i>
                        <h4 style="margin-bottom:12px;color:var(--success)">Import data</h4>
                        <p style="color:var(--muted);margin-bottom:20px;font-size:13px">Import JSON file to replace current data</p>
                        <input type="file" id="importFile" accept=".json" style="display:none" onchange="importData(this)">
                        <button class="btn btn-success" onclick="document.getElementById('importFile').click()" style="width:100%"><i class="fas fa-upload"></i> Import file</button>
                    </div>
                </div>
                <div id="exportStatus" style="display:none;margin-top:16px;padding:16px;border-radius:8px;background:var(--secondary)">
                    <h5 style="margin-bottom:12px"><i class="fas fa-info-circle"></i> Export status</h5>
                    <div id="exportFilesList"></div>
                </div>
            </div>
        </div>

        <!-- API TEST -->
        <div class="content-section" id="apiTest">
            <h3 class="section-title"><i class="fas fa-plug"></i> Check API connections</h3>
            <div class="form-container">
                <button class="btn btn-primary" onclick="testAPIs()"><i class="fas fa-sync-alt"></i> Check APIs</button>
                <div id="apiTestResults" style="margin-top:20px"></div>
            </div>
        </div>

        <!-- SMPP CONFIGURATION -->
        <div class="content-section" id="smppConfig">
            <h3 class="section-title"><i class="fas fa-network-wired"></i> SMPP settings</h3>
            <div class="form-container">
                <div style="margin-bottom:20px">
                    <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                        <input type="checkbox" id="smppEnabled" style="width:20px;height:20px">
                        <span style="font-weight:600">Activate SMPP</span>
                    </label>
                    <p style="color:var(--muted);font-size:12px;margin-top:6px">SMPP (Short Message Peer-to-Peer) standard protocol for sending and receiving SMS</p>
                </div>
                <div class="filter-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Host (IP/Domain)</label><input type="text" id="smppHost" placeholder="64.227.66.145" value="64.227.66.145"></div>
                    <div class="form-group"><label>Port</label><input type="number" id="smppPort" placeholder="2775" value="2775"></div>
                    <div class="form-group"><label>System ID</label><input type="text" id="smppSystemId" placeholder="username"></div>
                    <div class="form-group"><label>Password</label><input type="password" id="smppPassword" placeholder="password"></div>
                    <div class="form-group"><label>System Type</label><input type="text" id="smppSystemType" placeholder="optional"></div>
                    <div class="form-group"><label>Source Address</label><input type="text" id="smppSourceAddr" placeholder="sender ID"></div>
                </div>
                <div style="display:flex;gap:10px;margin-bottom:20px">
                    <button class="btn btn-primary" onclick="saveSmppConfig()"><i class="fas fa-save"></i> Save settings</button>
                    <button class="btn btn-success" onclick="testSmppConnection()"><i class="fas fa-plug"></i> Test connection</button>
                </div>
                <div id="smppStatus" style="margin-top:16px;padding:16px;border-radius:8px;background:var(--secondary);display:none">
                    <h5 style="margin-bottom:12px"><i class="fas fa-info-circle"></i> SMPP status</h5>
                    <div id="smppStatusContent"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- FOOTER -->
    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
const socket=io();
let selectedFile=null,selectedTestFile=null,selectedReserveFile=null;
socket.on('connect',()=>{socket.emit('join',{username:'Patrickselvaa'})});
socket.on('broadcast',(data)=>{showToast('Broadcast: '+data.message,'info')});

function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='pendingUsers')loadPendingUsers();
    if(sectionId==='accounts')loadAccounts();
    if(sectionId==='userStatistics')loadUserStatistics();
    if(sectionId==='smsCosts')loadSmsCosts();
    if(sectionId==='deleteNumbers')loadDeleteFiles();
    if(sectionId==='deleteTest')loadDeleteTestFiles();
    if(sectionId==='deleteReserve')loadDeleteReserveFiles();
    if(sectionId==='increaseLimit')loadLimitUsers();
    if(sectionId==='deleteAdmin')loadAdminSelect();
    if(sectionId==='deleteGeneral')loadGeneralSelect();
    if(sectionId==='deleteLegend')loadLegendSelect();
    if(sectionId==='dashboard')loadDashboardStats();
    if(sectionId==='notifications')loadNotifications();
    if(sectionId==='rangeStatistics')loadRangeStatistics();
    if(sectionId==='securityLogs')loadSecurityLogs();
    if(sectionId==='viewReserve')loadReserveFiles();
    if(sectionId==='smppConfig'){loadSmppConfig();loadSmppStatus();}
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':type==='info'?'info':type==='warning'?'warning':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':type==='error'?'exclamation-circle':type==='info'?'info-circle':'exclamation-triangle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function loadDashboardStats(){
    const users=await fetch('/api/owner/accounts').then(r=>r.json());
    const pending=await fetch('/api/owner/pending_users').then(r=>r.json());
    const reserve=await fetch('/api/privileged/reserve_numbers').then(r=>r.json());
    const allUsers=users.users||{};
    document.getElementById('totalUsers').textContent=Object.keys(allUsers).length;
    document.getElementById('pendingCount').textContent=Object.keys(pending.users||{}).length;
    let banned=0;
    for(const u of Object.values(allUsers)){if(u.status==='banned')banned++;}
    document.getElementById('bannedCount').textContent=banned;
    const numbers=await fetch('/api/user/available_numbers').then(r=>r.json());
    let totalNums=0;
    for(const f of Object.values(numbers.files||{})){totalNums+=(f.numbers?.length||0);}
    document.getElementById('totalNumbers').textContent=totalNums;
    // Reserve stats
    let reserveTotal=0,reserveFiles=0;
    for(const f of Object.values(reserve.files||{})){reserveTotal+=f.count;reserveFiles++;}
    document.getElementById('reserveCount').textContent=reserveTotal;
    document.getElementById('reserveFilesCount').textContent=reserveFiles;
}

function handleFileSelect(input){selectedFile=input.files[0];if(selectedFile)showToast('File selected: '+selectedFile.name)}
function handleTestFileSelect(input){selectedTestFile=input.files[0];if(selectedTestFile)showToast('File selected: '+selectedTestFile.name)}
function handleReserveFileSelect(input){selectedReserveFile=input.files[0];if(selectedReserveFile)showToast('Reserve file selected: '+selectedReserveFile.name)}

async function addNumbers(){
    if(!selectedFile){showToast('Select file first','error');return}
    const formData=new FormData();
    formData.append('file',selectedFile);
    formData.append('filename',document.getElementById('fileName').value);
    formData.append('cost',document.getElementById('fileCost').value);
    formData.append('service',document.getElementById('fileService').value);
    formData.append('sms_price',document.getElementById('fileSmsPrice').value);
    const response=await fetch('/api/owner/add_numbers',{method:'POST',body:formData});
    const data=await response.json();
    if(data.success){showToast('Added '+data.count+' numbers');selectedFile=null;document.getElementById('numberFile').value='';document.getElementById('fileName').value='';document.getElementById('fileCost').value='';document.getElementById('fileService').value='';document.getElementById('fileSmsPrice').value='';}
    else{showToast(data.message,'error')}
}

async function addReserveNumbers(){
    if(!selectedReserveFile){showToast('Select reserve file first','error');return}
    const formData=new FormData();
    formData.append('file',selectedReserveFile);
    formData.append('filename',document.getElementById('reserveFileName').value);
    formData.append('cost',document.getElementById('reserveFileCost').value);
    const response=await fetch('/api/privileged/reserve_numbers',{method:'POST',body:formData});
    const data=await response.json();
    if(data.success){showToast('Added '+data.count+' reserve numbers in "'+data.filename+'"','success');selectedReserveFile=null;document.getElementById('reserveFile').value='';document.getElementById('reserveFileName').value='';document.getElementById('reserveFileCost').value='';}
    else{showToast(data.message,'error')}
}

async function loadReserveFiles(){
    const response=await fetch('/api/privileged/reserve_numbers');
    const data=await response.json();
    const container=document.getElementById('reserveFilesList');
    container.innerHTML='';
    if(Object.keys(data.files||{}).length===0){
        container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No reserve numbers yet</p></div>';
        return;
    }
    let html='<div class="files-grid">';
    for(const[name,info] of Object.entries(data.files||{})){
        html+=`<div class="file-card" style="border-color:rgba(139,92,246,0.3)"><h4 style="color:#A78BFA"><i class="fas fa-shield-alt"></i> ${name}</h4><div class="info"><span>Count: ${info.count} numbers</span><span>Added: ${new Date(info.added_at).toLocaleDateString()}</span></div><div class="cost">Cost: $${info.cost} per number</div><div style="margin-top:10px;font-size:12px;color:var(--muted)">Added by: ${info.added_by}</div></div>`;
    }
    html+='</div>';
    container.innerHTML=html;
}

async function loadDeleteReserveFiles(){
    const response=await fetch('/api/privileged/reserve_numbers');
    const data=await response.json();
    const select=document.getElementById('deleteReserveSelect');
    select.innerHTML='<option value="">-- Select file --</option>';
    for(const name of Object.keys(data.files||{})){select.innerHTML+=`<option value="${name}">${name}</option>`}
}

async function deleteReserveNumbers(){
    const filename=document.getElementById('deleteReserveSelect').value;
    if(!filename){showToast('Select file','error');return}
    if(!confirm('Are you sure you want to delete this reserve file?'))return;
    const response=await fetch('/api/privileged/reserve_numbers/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename})});
    const data=await response.json();
    if(data.success){showToast('Reserve file deleted');loadDeleteReserveFiles()}
    else{showToast(data.message,'error')}
}

async function loadSecurityLogs(){
    const response=await fetch('/api/owner/security_logs');
    const data=await response.json();
    const tbody=document.getElementById('securityLogsTable');
    tbody.innerHTML='';
    if(!data.logs||data.logs.length===0){tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted)">No logs</td></tr>';return;}
    for(const log of data.logs.slice().reverse()){
        const typeColor=log.type.includes('failed')||log.type.includes('unauthorized')?'var(--destructive)':log.type.includes('success')?'var(--success)':'var(--accent)';
        tbody.innerHTML+=`<tr><td class="text-muted">${new Date(log.time).toLocaleString()}</td><td style="color:${typeColor};font-weight:600">${log.type}</td><td class="text-primary">${log.username||'-'}</td><td>${log.details}</td><td class="text-muted">${log.ip}</td></tr>`;
    }
}

async function loadDeleteFiles(){
    const response=await fetch('/api/user/available_numbers');
    const data=await response.json();
    const select=document.getElementById('deleteFileSelect');
    select.innerHTML='<option value="">-- Select file --</option>';
    for(const[name,info]of Object.entries(data.files||{})){select.innerHTML+=`<option value="${name}">${name} (${info.numbers?.length||0} number)</option>`}
}

async function deleteNumbers(){
    const filename=document.getElementById('deleteFileSelect').value;
    if(!filename){showToast('Select file','error');return}
    const response=await fetch('/api/owner/delete_numbers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename})});
    const data=await response.json();
    if(data.success){showToast('Deleted successfully');loadDeleteFiles()}
}

async function deleteAllNumbers(){if(!confirm('Are you sure you want to delete all numbers?'))return;const response=await fetch('/api/owner/delete_all_numbers',{method:'POST'});const data=await response.json();if(data.success)showToast('All numbers deleted')}

async function addTestNumbers(){
    if(!selectedTestFile){showToast('Select file','error');return}
    const formData=new FormData();
    formData.append('file',selectedTestFile);
    formData.append('filename',document.getElementById('testFileName').value);
    const response=await fetch('/api/owner/add_test_numbers',{method:'POST',body:formData});
    const data=await response.json();
    if(data.success){showToast('Added '+data.count+' test numbers');selectedTestFile=null;document.getElementById('testFile').value='';document.getElementById('testFileName').value='';}
}

async function loadDeleteTestFiles(){
    const response=await fetch('/api/user/test_numbers');
    const data=await response.json();
    const select=document.getElementById('deleteTestSelect');
    select.innerHTML='<option value="">-- Select --</option>';
    for(const name of Object.keys(data.files||{})){select.innerHTML+=`<option value="${name}">${name}</option>`}
}

async function deleteTestNumbers(){
    const filename=document.getElementById('deleteTestSelect').value;
    if(!filename)return;
    await fetch('/api/owner/delete_test_numbers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename})});
    showToast('Deleted');loadDeleteTestFiles();
}

async function deleteAllTest(){if(!confirm('Are you sure?'))return;await fetch('/api/owner/delete_all_test',{method:'POST'});showToast('All experimental deleted')}

async function loadPendingUsers(){
    const response=await fetch('/api/owner/pending_users');
    const data=await response.json();
    const tbody=document.getElementById('pendingUsersTable');
    tbody.innerHTML='';
    for(const[username,user]of Object.entries(data.users||{})){
        tbody.innerHTML+=`<tr><td class="text-primary">${username}</td><td>${user.phone||'-'}</td><td class="text-muted">${new Date(user.created_at).toLocaleDateString()}</td><td><button class="btn btn-success btn-sm" onclick="approveUser('${username}')"><i class="fas fa-check"></i> Approve</button><button class="btn btn-danger btn-sm" onclick="rejectUser('${username}')" style="margin-right:5px"><i class="fas fa-times"></i> Reject</button></td></tr>`;
    }
}

async function approveUser(username){
    await fetch('/api/owner/approve_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,action:'approve'})});
    showToast('Approved '+username);loadPendingUsers();
}

async function rejectUser(username){
    await fetch('/api/owner/approve_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,action:'reject'})});
    showToast('Rejected '+username);loadPendingUsers();
}

async function approveAllUsers(){
    await fetch('/api/owner/approve_all',{method:'POST'});
    showToast('All users approved');loadPendingUsers();
}

async function loadAccounts(){
    const response=await fetch('/api/owner/accounts');
    const data=await response.json();
    const tbody=document.getElementById('accountsTable');
    tbody.innerHTML='';
    for(const[username,user]of Object.entries(data.users||{})){
        if(username==='Patrickselvaa')continue;
        const statusClass=user.status==='active'?'status-active':user.status==='pending'?'status-pending':'status-banned';
        const roleClass=user.role==='admin'?'status-admin':user.role==='general'?'status-general':user.role==='legend'?'status-legend':user.role==='owner'?'status-owner':'';
        tbody.innerHTML+=`<tr><td class="text-primary">${username}</td><td><span class="status-badge ${roleClass}">${user.role}</span></td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td>${user.limit||0}</td><td><button class="btn ${user.status==='active'?'btn-danger':'btn-success'} btn-sm" onclick="toggleBan('${username}')"><i class="fas fa-ban"></i> ${user.status==='active'?'Ban':'Unban'}</button></td></tr>`;
    }
}

async function toggleBan(username){
    await fetch('/api/owner/toggle_ban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    loadAccounts();
}

async function loadLimitUsers(){
    const response=await fetch('/api/owner/accounts');
    const data=await response.json();
    const select=document.getElementById('limitUserSelect');
    select.innerHTML='';
    for(const username of Object.keys(data.users||{})){if(username!=='Patrickselvaa'){select.innerHTML+=`<option value="${username}">${username}</option>`}}
    const filesResponse=await fetch('/api/user/available_numbers');
    const filesData=await filesResponse.json();
    const fileSelect=document.getElementById('addNumbersFileSelect');
    fileSelect.innerHTML='';
    for(const[name,info]of Object.entries(filesData.files||{})){fileSelect.innerHTML+=`<option value="${name}">${name} (${info.numbers?.length||0} number)</option>`}
}

async function addNumbersToUser(){
    const username=document.getElementById('limitUserSelect').value;
    const filename=document.getElementById('addNumbersFileSelect').value;
    const count=parseInt(document.getElementById('addNumbersCount').value)||0;
    if(!username){showToast('Select user','error');return}
    if(!filename){showToast('Select file','error');return}
    if(count<=0){showToast('Count must be greater than 0','error');return}
    const response=await fetch('/api/owner/add_numbers_to_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,filename,count})});
    const data=await response.json();
    if(data.success){showToast(`Added ${data.assigned?.length||0} numbers to user ${username}`);document.getElementById('addNumbersCount').value='';loadLimitUsers();}
    else{showToast(data.message||'Error','error');}
}

async function addAdmin(){
    const username=document.getElementById('adminUsername').value;
    const password=document.getElementById('adminPassword').value;
    const response=await fetch('/api/owner/add_admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
    const data=await response.json();
    if(data.success){showToast('Admin added');document.getElementById('adminUsername').value='';document.getElementById('adminPassword').value='';loadAdminSelect();}
    else{showToast(data.message,'error')}
}

async function addGeneral(){
    const username=document.getElementById('generalUsername').value.trim();
    const password=document.getElementById('generalPassword').value;
    if(!username||!password){showToast('Username and password required','error');return}
    const response=await fetch('/api/owner/add_general',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
    const data=await response.json();
    if(data.success){showToast('General account created: '+username);document.getElementById('generalUsername').value='';document.getElementById('generalPassword').value='';}
    else{showToast(data.message,'error')}
}

async function addLegend(){
    const username=document.getElementById('legendNewUsername').value.trim();
    const password=document.getElementById('legendNewPassword').value;
    if(!username||!password){showToast('Username and password required','error');return}
    const response=await fetch('/api/owner/add_legend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
    const data=await response.json();
    if(data.success){showToast('Legend account created: '+username);document.getElementById('legendNewUsername').value='';document.getElementById('legendNewPassword').value='';}
    else{showToast(data.message,'error')}
}

async function loadAdminSelect(){
    const response=await fetch('/api/owner/accounts');
    const data=await response.json();
    const select=document.getElementById('adminSelect');
    select.innerHTML='';
    for(const[username,user]of Object.entries(data.users||{})){if(user.role==='admin'){select.innerHTML+=`<option value="${username}">${username}</option>`}}
}

async function deleteAdmin(){
    const username=document.getElementById('adminSelect').value;
    if(!username)return;
    await fetch('/api/owner/delete_admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    showToast('Admin permissions deleted');loadAdminSelect();loadAccounts();
}

async function loadGeneralSelect(){
    const response=await fetch('/api/owner/accounts');
    const data=await response.json();
    const select=document.getElementById('generalSelect');
    select.innerHTML='';
    for(const[username,user]of Object.entries(data.users||{})){if(user.role==='general'){select.innerHTML+=`<option value="${username}">${username}</option>`}}
    if(select.innerHTML===''){select.innerHTML='<option value="">No General accounts</option>';}
}

async function deleteGeneral(){
    const username=document.getElementById('generalSelect').value;
    if(!username||username===''){showToast('Select a General account','error');return;}
    if(!confirm('Are you sure you want to delete General permissions for '+username+'?'))return;
    const response=await fetch('/api/owner/delete_general',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    const data=await response.json();
    if(data.success){showToast('General permissions deleted');loadGeneralSelect();loadAccounts();}
    else{showToast(data.message||'Error','error');}
}

async function loadLegendSelect(){
    const response=await fetch('/api/owner/accounts');
    const data=await response.json();
    const select=document.getElementById('legendSelect');
    select.innerHTML='';
    for(const[username,user]of Object.entries(data.users||{})){if(user.role==='legend'){select.innerHTML+=`<option value="${username}">${username}</option>`}}
    if(select.innerHTML===''){select.innerHTML='<option value="">No Legend accounts</option>';}
}

async function deleteLegend(){
    const username=document.getElementById('legendSelect').value;
    if(!username||username===''){showToast('Select a Legend account','error');return;}
    if(!confirm('Are you sure you want to delete Legend permissions for '+username+'?'))return;
    const response=await fetch('/api/owner/delete_legend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    const data=await response.json();
    if(data.success){showToast('Legend permissions deleted');loadLegendSelect();loadAccounts();}
    else{showToast(data.message||'Error','error');}
}

async function sendBroadcast(){
    const message=document.getElementById('broadcastMessage').value;
    if(!message){showToast('Write a message','error');return}
    await fetch('/api/owner/broadcast',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message})});
    showToast('Broadcast sent');document.getElementById('broadcastMessage').value='';
}

async function loadNotifications(){
    const response=await fetch('/api/user/notifications');
    const data=await response.json();
    const container=document.getElementById('notificationsList');
    container.innerHTML='';
    const notifs=data.notifications||[];
    if(notifs.length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No notifications</p></div>';return;}
    for(const notif of notifs.slice().reverse()){
        container.innerHTML+=`<div class="notification-panel ${notif.read?'':'unread'}"><div class="header"><span class="type">${notif.type}</span><span class="time">${new Date(notif.time).toLocaleString()}</span></div><p>${notif.message}</p></div>`;
    }
}

async function exportAllData(){
    const files = ['users.json','daily_limits.json','numbers.json','test_numbers.json','sms.json','notifications.json','pending_users.json','payments.json','user_sms_costs.json','smpp_config.json','reserve_numbers.json','security_log.json','login_attempts.json','file_services.json','range_prices.json'];
    const statusDiv = document.getElementById('exportStatus');
    const filesList = document.getElementById('exportFilesList');
    statusDiv.style.display = 'block';
    filesList.innerHTML = '<p style="color:var(--muted)">⏳ Exporting...</p>';
    let exported = 0;
    let failed = [];
    for(const file of files){
        try{
            const response = await fetch(`/api/export_file?file=${file}`);
            if(response.ok){
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = file;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                exported++;
            } else {
                failed.push(file);
            }
        }catch(e){
            console.error(e);
            failed.push(file);
        }
    }
    let html = `<p style="color:var(--success)"><i class="fas fa-check-circle"></i> ${exported} files exported successfully!</p>`;
    if(failed.length > 0){
        html += `<p style="color:var(--destructive)"><i class="fas fa-times-circle"></i> Failed: ${failed.join(', ')}</p>`;
    }
    filesList.innerHTML = html;
    showToast(`${exported} files exported${failed.length > 0 ? ', ' + failed.length + ' failed' : ''}`);
}

async function importData(input){
    const file = input.files[0];
    if(!file) return;

    const formData = new FormData();
    formData.append('file', file);
    showToast("Importing data...", "info");
    try{
        const response = await fetch("/api/import_file", {
            method: "POST", 
            body: formData,
            credentials: 'include'
        });
        if(!response.ok){
            const errorText = await response.text();
            showToast("❌ Server error " + response.status + ": " + errorText.substring(0, 100), "error");
            return;
        }
        const data = await response.json();
        if(data.success){
            showToast("✅ " + data.message + " (Records: " + (data.records_count || 0) + ")", "success");
        } else {
            showToast("❌ " + (data.message || "Import error"), "error");
        }
    } catch(e) {
        showToast("❌ Network error: " + e.message, "error");
    }
    input.value = "";
}

async function testAPIs(){
    const btn = event.target;
    btn.querySelector('i').classList.add('fa-spin');
    const response = await fetch('/api/test_api_connection');
    const data = await response.json();
    const container = document.getElementById('apiTestResults');
    let html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px">';
    for(const[name,info] of Object.entries(data.apis||{})){
        const color = info.status==='connected' ? 'var(--success)' : 'var(--destructive)';
        html += `<div style="border:1px solid var(--border);border-radius:8px;padding:16px;background:var(--glass)">
            <h4 style="color:${color};margin-bottom:8px"><i class="fas fa-${info.status==='connected'?'check-circle':'times-circle'}"></i> ${name}</h4>
            <p>Status: ${info.status}</p>
            <p>Messages: ${info.count||0}</p>
            <p style="font-size:11px;color:var(--muted);margin-top:8px">Keys: ${(info.sample_keys||[]).join(', ')}</p>
        </div>`;
    }
    html += '</div>';
    container.innerHTML = html;
    btn.querySelector('i').classList.remove('fa-spin');
    showToast('APIs checked');
}

function exportTable(type){showToast('Exporting...','info');}

async function loadSmppConfig(){
    const response = await fetch('/api/owner/smpp_config');
    const data = await response.json();
    if(data.success && data.config){
        const cfg = data.config;
        document.getElementById('smppEnabled').checked = cfg.enabled || false;
        document.getElementById('smppHost').value = cfg.host || '';
        document.getElementById('smppPort').value = cfg.port || 2775;
        document.getElementById('smppSystemId').value = cfg.system_id || '';
        document.getElementById('smppSystemType').value = cfg.system_type || '';
        document.getElementById('smppSourceAddr').value = cfg.source_addr || '';
    }
}

async function saveSmppConfig(){
    const config = {
        enabled: document.getElementById('smppEnabled').checked,
        host: document.getElementById('smppHost').value,
        port: parseInt(document.getElementById('smppPort').value) || 2775,
        system_id: document.getElementById('smppSystemId').value,
        password: document.getElementById('smppPassword').value,
        system_type: document.getElementById('smppSystemType').value,
        source_addr: document.getElementById('smppSourceAddr').value
    };
    const response = await fetch('/api/owner/smpp_config', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(config)});
    const data = await response.json();
    if(data.success){showToast('SMPP settings saved');document.getElementById('smppPassword').value='';}
    else{showToast(data.message, 'error');}
}

async function testSmppConnection(){
    const btn = event.target;
    btn.querySelector('i').classList.add('fa-spin');
    btn.disabled = true;
    const response = await fetch('/api/owner/smpp_test', {method: 'POST'});
    const data = await response.json();
    const statusDiv = document.getElementById('smppStatus');
    const contentDiv = document.getElementById('smppStatusContent');
    statusDiv.style.display = 'block';
    if(data.success){contentDiv.innerHTML = `<p style="color:var(--success)"><i class="fas fa-check-circle"></i> ${data.message}</p>`;showToast(data.message);}
    else{contentDiv.innerHTML = `<p style="color:var(--destructive)"><i class="fas fa-times-circle"></i> ${data.message}</p>`;showToast(data.message, 'error');}
    btn.querySelector('i').classList.remove('fa-spin');
    btn.disabled = false;
}

async function loadSmppStatus(){
    const response = await fetch('/api/owner/smpp_status');
    const data = await response.json();
    if(data.success && data.status){
        const status = data.status;
        const statusDiv = document.getElementById('smppStatus');
        const contentDiv = document.getElementById('smppStatusContent');
        statusDiv.style.display = 'block';
        let html = `<p><strong>Enabled:</strong> ${status.enabled ? 'Active' : 'Inactive'}</p>`;
        html += `<p><strong>Connection:</strong> ${status.connected ? 'Connected' : 'Not connected'}</p>`;
        html += `<p><strong>Server:</strong> ${status.host}:${status.port}</p>`;
        html += `<p><strong>System ID:</strong> ${status.system_id}</p>`;
        contentDiv.innerHTML = html;
    }
}

async function loadUserStatistics(){
    const response=await fetch('/api/owner/user_statistics');
    const data=await response.json();
    const tbody=document.getElementById('statisticsTable');
    tbody.innerHTML='';
    if(!data.statistics || data.statistics.length===0){
        tbody.innerHTML='<tr><td colspan="9" style="text-align:center;color:var(--muted)">No data</td></tr>';
        return;
    }
    let totalNumbers=0, totalSMS=0, totalSpent=0;
    for(const stat of data.statistics){totalNumbers+=stat.total_numbers||0;totalSMS+=stat.total_sms||0;totalSpent+=stat.total_spent||0;}
    document.getElementById('statsTotalUsers').textContent=data.statistics.length;
    document.getElementById('statsTotalNumbers').textContent=totalNumbers;
    document.getElementById('statsTotalSMS').textContent=totalSMS;
    document.getElementById('statsTotalSpent').textContent=totalSpent.toFixed(2);
    for(const stat of data.statistics){
        const statusClass=stat.status==='active'?'status-active':stat.status==='pending'?'status-pending':'status-banned';
        const roleClass=stat.role==='admin'?'status-admin':stat.role==='general'?'status-general':stat.role==='legend'?'status-legend':'';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${stat.username}</td><td><span class="status-badge ${roleClass}">${stat.role}</span></td><td><span class="status-badge ${statusClass}">${stat.status}</span></td><td>${stat.limit||0}</td><td class="text-success" style="font-weight:600">${stat.total_numbers||0}</td><td>${stat.files_count||0}</td><td class="text-primary" style="font-weight:600">${stat.total_sms||0}</td><td class="text-success" style="font-weight:600">$${(stat.total_spent||0).toFixed(2)}</td><td class="text-muted">${stat.created_at?new Date(stat.created_at).toLocaleDateString():'-'}</td></tr>`;
    }
}

function exportStatistics(type){showToast('Exporting statistics...','info');}

async function loadRangeStatistics(){
    const response=await fetch('/api/owner/range_statistics');
    const data=await response.json();
    const tbody=document.getElementById('rangeStatisticsTable');
    tbody.innerHTML='';
    if(!data.ranges || data.ranges.length===0){
        tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--muted)">No data</td></tr>';
        document.getElementById('rangeTotalFiles').textContent='0';
        document.getElementById('rangeTotalSMS').textContent='0';
        document.getElementById('rangeTotalNumbers').textContent='0';
        document.getElementById('rangeTotalUsers').textContent='0';
        return;
    }
    let totalSMS=0, totalNumbers=0, totalUsers=0;
    for(const r of data.ranges){totalSMS += r.total_sms || 0;totalNumbers += r.unique_numbers || 0;totalUsers += r.active_users || 0;}
    document.getElementById('rangeTotalFiles').textContent=data.ranges.length;
    document.getElementById('rangeTotalSMS').textContent=totalSMS;
    document.getElementById('rangeTotalNumbers').textContent=totalNumbers;
    document.getElementById('rangeTotalUsers').textContent=totalUsers;
    let rank=1;
    for(const range of data.ranges){
        const lastTime = range.last_sms_time && range.last_sms_time !== '-' ? new Date(range.last_sms_time).toLocaleString() : '-';
        const maxSMS = data.ranges[0].total_sms || 1;
        const activityPercent = Math.round((range.total_sms / maxSMS) * 100);
        tbody.innerHTML+=`<tr><td style="font-weight:700;color:var(--accent)">#${rank}</td><td class="text-primary" style="font-weight:600">${range.file}</td><td class="text-success" style="font-weight:700;font-size:1.1rem">${range.total_sms}</td><td>${range.unique_numbers}</td><td>${range.active_users}</td><td class="text-muted">${lastTime}</td><td><div style="display:flex;align-items:center;gap:8px"><div style="flex:1;background:var(--secondary);border-radius:4px;height:8px;overflow:hidden"><div style="width:${activityPercent}%;background:linear-gradient(90deg,var(--accent),var(--success));height:100%;border-radius:4px;transition:width 0.5s ease"></div></div><span style="font-size:11px;font-weight:600;color:var(--accent)">${activityPercent}%</span></div></td></tr>`;
        rank++;
    }
}

function exportRangeStats(type){showToast('Exporting range statistics...','info');}

async function loadSmsCosts(){
    const response=await fetch('/api/owner/user_sms_cost');
    const data=await response.json();
    const tbody=document.getElementById('smsCostsTable');
    tbody.innerHTML='';
    if(!data.costs || data.costs.length===0){tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted)">No data</td></tr>';return;}
    for(const item of data.costs){
        const usersResponse=await fetch('/api/owner/accounts');
        const usersData=await usersResponse.json();
        const user=usersData.users?.[item.username]||{};
        const statusClass=user.status==='active'?'status-active':user.status==='pending'?'status-pending':'status-banned';
        const roleClass=user.role==='admin'?'status-admin':'';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${item.username}</td><td><span class="status-badge ${roleClass}">${user.role||'user'}</span></td><td><span class="status-badge ${statusClass}">${user.status||'active'}</span></td><td><input type="number" id="cost_${item.username}" value="${item.cost}" step="0.001" min="0" style="width:80px;padding:6px;border:1px solid var(--border);border-radius:4px;font-size:13px;background:var(--glass);color:var(--foreground)"></td><td><button class="btn btn-primary btn-sm" onclick="saveSmsCost('${item.username}')"><i class="fas fa-save"></i> Save</button></td></tr>`;
    }
}

async function saveSmsCost(username){
    const costInput=document.getElementById(`cost_${username}`);
    const cost=parseFloat(costInput.value)||0.01;
    const response=await fetch('/api/owner/user_sms_cost',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,cost})});
    const data=await response.json();
    if(data.success){showToast(`Updated SMS price for user ${username} to $${cost}`);}
    else{showToast(data.message||'Error','error');}
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
loadDashboardStats();
</script>
</body>
</html>
"""

GENERAL_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - General Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#06B6D4;--accent-purple:#8B5CF6;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#0891B2;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#ECFEFF 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .file-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#0891B2}
[data-theme="light"] .nav-item:hover{background:rgba(6,182,212,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(6,182,212,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#0C4A6E 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* ===== SIDEBAR ===== */
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(6,182,212,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#22D3EE,#A78BFA);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(6,182,212,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(6,182,212,0.2),rgba(139,92,246,0.2));color:#fff;border:1px solid rgba(6,182,212,0.3)}
.nav-item.active i{color:#22D3EE}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}
.role-badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:0.6rem;font-weight:700;margin-right:auto}
.role-general{background:linear-gradient(135deg,#06B6D4,#0891B2);color:white}

/* ===== MAIN CONTENT ===== */
.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

/* ===== HEADER ===== */
.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--accent);background:rgba(6,182,212,0.1)}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent-purple));border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

/* ===== SECTIONS ===== */
.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ===== CARDS ===== */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(6,182,212,0.3)}
.stat-card .icon{font-size:24px;margin-bottom:8px;display:block}
.stat-card .number{font-family:'Poppins',sans-serif;font-size:1.6rem;font-weight:700;margin-bottom:4px;color:var(--foreground)}
.stat-card .label{color:var(--muted);font-size:12px}

/* ===== BUTTONS ===== */
.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;box-shadow:0 4px 16px rgba(6,182,212,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(6,182,212,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(6,182,212,0.1);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--destructive);color:white}
.btn-danger:hover{background:#DC2626;transform:translateY(-2px);box-shadow:0 4px 16px rgba(239,68,68,0.3)}
.btn-success{background:var(--success);color:white}
.btn-sm{padding:6px 12px;font-size:12px}

/* ===== FORMS ===== */
.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-container:hover{border-color:rgba(6,182,212,0.2)}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,0.15)}
.file-upload{border:2px dashed var(--border);border-radius:12px;padding:32px;text-align:center;cursor:pointer;transition:all 0.3s ease;margin-bottom:16px;background:var(--glass)}
.file-upload:hover{border-color:var(--accent);background:rgba(6,182,212,0.05)}
.file-upload i{font-size:2.5rem;color:var(--accent);margin-bottom:12px}
.file-upload p{color:var(--muted);font-size:13px}

/* ===== TABLE ===== */
.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.table-controls{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);flex-wrap:wrap;gap:12px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(6,182,212,0.05)}
.text-primary{color:#22D3EE;font-weight:500}
.text-muted{color:var(--muted)}
.text-success{color:var(--success);font-weight:500}
.text-danger{color:var(--destructive);font-weight:500}

/* ===== STATUS BADGES ===== */
.status-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;display:inline-block}
.status-active{background:rgba(16,185,129,0.15);color:#34D399;border:1px solid rgba(16,185,129,0.3)}
.status-banned{background:rgba(239,68,68,0.15);color:#FCA5A5;border:1px solid rgba(239,68,68,0.3)}
.status-pending{background:rgba(245,158,11,0.15);color:#FBBF24;border:1px solid rgba(245,158,11,0.3)}

/* ===== FILE CARDS ===== */
.files-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.file-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.file-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(6,182,212,0.3)}
.file-card h4{color:#22D3EE;margin-bottom:12px;font-size:15px;display:flex;align-items:center;gap:8px}
.file-card .info{display:flex;justify-content:space-between;margin-bottom:10px;color:var(--muted);font-size:13px}
.file-card .cost{color:var(--success);font-weight:700;font-size:16px}
.reserve-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:20px;color:#A78BFA;font-size:12px;font-weight:600}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
.toast.info{border-right-color:var(--accent)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ===== FOOTER ===== */
.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}

/* ===== SECTION TITLE ===== */
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
    .header{flex-direction:column;align-items:flex-start;gap:10px;padding:12px 20px}
    .cards-grid{grid-template-columns:1fr}
    .files-grid{grid-template-columns:1fr}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>GENERAL PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Users</div>
        <button class="nav-item" onclick="showSection('usersList',this)"><i class="fas fa-users"></i> User list</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Number distribution</div>
        <button class="nav-item" onclick="showSection('distributeNumbers',this)"><i class="fas fa-share-alt"></i> Distribute numbers</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Reserve Numbers</div>
        <button class="nav-item" onclick="showSection('viewReserve',this)"><i class="fas fa-eye"></i> View reserve numbers</button>
        <button class="nav-item" onclick="showSection('addReserve',this)"><i class="fas fa-plus-circle"></i> Add reserve numbers</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Account</div>
        <button class="nav-item" onclick="showSection('myAccount',this)"><i class="fas fa-user-cog"></i> My account</button>
    </div>
</div>

<div class="main-content">
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-star" style="color:var(--accent)"></i> General Panel</h2>
            <p>Number distribution management</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar">G</div>
                <span class="user-name" id="generalUsername">General</span>
                <span class="role-badge role-general">GENERAL</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <div class="page-content">
        <!-- DASHBOARD -->
        <div class="content-section active" id="dashboard">
            <div class="cards-grid">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128101;</span><div class="number" id="totalUsers">0</div><div class="label">Total users</div></div>
                <div class="stat-card"><span class="icon" style="color:#A78BFA">&#128737;</span><div class="number" id="reserveCount">0</div><div class="label">Reserve numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128241;</span><div class="number" id="availableCount">0</div><div class="label">Available numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--warning)">&#128228;</span><div class="number" id="distributedCount">0</div><div class="label">Distributed numbers</div></div>
            </div>
        </div>

        <!-- USERS LIST -->
        <div class="content-section" id="usersList">
            <h3 class="section-title"><i class="fas fa-users"></i> User list</h3>
            <div class="table-wrapper">
                <div class="table-controls"><span style="color:var(--muted)">All regular users</span></div>
                <table>
                    <thead><tr><th>User</th><th>Status</th><th>Limit</th><th>Registration date</th></tr></thead>
                    <tbody id="usersTable"></tbody>
                </table>
            </div>
        </div>

        <!-- DISTRIBUTE NUMBERS -->
        <div class="content-section" id="distributeNumbers">
            <h3 class="section-title"><i class="fas fa-share-alt"></i> Distribute numbers to users</h3>
            <div class="form-container">
                <p style="color:var(--muted);margin-bottom:16px;font-size:13px">Select numbers from available files or reserve numbers and distribute them to a user.</p>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Select user</label><select id="distUserSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                    <div class="form-group"><label>Number source</label><select id="distSource" onchange="loadFilesForDistribution()" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"><option value="available">Available numbers</option><option value="reserve">Reserve numbers</option></select></div>
                    <div class="form-group"><label>Select file</label><select id="distFileSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                    <div class="form-group"><label>Number count</label><input type="number" id="distCount" placeholder="Example: 100" min="1" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></div>
                </div>
                <button class="btn btn-primary" onclick="distributeNumbers()" style="background:linear-gradient(135deg,#06B6D4,#8B5CF6)"><i class="fas fa-share-alt"></i> Distribute numbers</button>
            </div>
        </div>

        <!-- VIEW RESERVE -->
        <div class="content-section" id="viewReserve">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
                <h3 class="section-title" style="margin:0"><i class="fas fa-eye" style="color:#A78BFA"></i> Reserve numbers</h3>
                <span class="reserve-badge"><i class="fas fa-lock"></i> Private</span>
            </div>
            <div id="reserveFilesList"></div>
        </div>

        <!-- ADD RESERVE -->
        <div class="content-section" id="addReserve">
            <h3 class="section-title"><i class="fas fa-plus-circle" style="color:#A78BFA"></i> Add reserve numbers</h3>
            <div class="form-container" style="border-color:rgba(139,92,246,0.3)">
                <div class="file-upload" onclick="document.getElementById('reserveFile').click()" style="border-color:rgba(139,92,246,0.3)">
                    <i class="fas fa-cloud-upload-alt" style="color:#A78BFA"></i>
                    <p>Click to upload reserve numbers file (.txt)</p>
                    <input type="file" id="reserveFile" accept=".txt" style="display:none" onchange="handleReserveFileSelect(this)">
                </div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>File name</label><input type="text" id="reserveFileName" placeholder="Example: Reserve USA"></div>
                    <div class="form-group"><label>Cost per number ($)</label><input type="number" id="reserveFileCost" placeholder="0.00" step="0.01"></div>
                </div>
                <button class="btn btn-primary" onclick="addReserveNumbers()" style="background:linear-gradient(135deg,#8B5CF6,#6366F1)"><i class="fas fa-save"></i> Save reserve numbers</button>
            </div>
        </div>

        <!-- MY ACCOUNT -->
        <div class="content-section" id="myAccount">
            <h3 class="section-title"><i class="fas fa-user-cog"></i> My account</h3>
            <div class="form-container">
                <div class="form-group"><label>New password</label><input type="password" id="newPassword" placeholder="Leave blank if you don't want to change"></div>
                <div class="form-group"><label>Phone number</label><input type="tel" id="newPhone" placeholder="Phone number"></div>
                <button class="btn btn-primary" onclick="updateAccount()"><i class="fas fa-save"></i> Save</button>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
const socket=io();
let selectedReserveFile=null;

socket.on('connect',()=>{fetch('/api/user/my_account').then(r=>r.json()).then(data=>{if(data.success){document.getElementById('generalUsername').textContent=data.user.username||'General';socket.emit('join',{username:data.user.username})}})});

function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='dashboard')loadDashboardStats();
    if(sectionId==='usersList')loadUsersList();
    if(sectionId==='distributeNumbers'){loadUsersForDistribution();loadFilesForDistribution();}
    if(sectionId==='viewReserve')loadReserveFiles();
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':type==='info'?'info':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':type==='error'?'exclamation-circle':'info-circle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function loadDashboardStats(){
    const response=await fetch('/api/general/dashboard_stats');
    const data=await response.json();
    if(data.success){
        document.getElementById('totalUsers').textContent=data.total_users;
        document.getElementById('reserveCount').textContent=data.total_reserve_numbers;
        document.getElementById('availableCount').textContent=data.total_available_numbers;
        document.getElementById('distributedCount').textContent=data.total_distributed;
    }
}

async function loadUsersList(){
    const response=await fetch('/api/general/users_list');
    const data=await response.json();
    const tbody=document.getElementById('usersTable');
    tbody.innerHTML='';
    if(!data.users||data.users.length===0){tbody.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted)">No users</td></tr>';return;}
    for(const user of data.users){
        const statusClass=user.status==='active'?'status-active':'status-banned';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${user.username}</td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td>${user.limit}</td><td class="text-muted">${user.created_at?new Date(user.created_at).toLocaleDateString():'-'}</td></tr>`;
    }
}

async function loadUsersForDistribution(){
    const response=await fetch('/api/general/users_list');
    const data=await response.json();
    const select=document.getElementById('distUserSelect');
    select.innerHTML='';
    for(const user of data.users||[]){if(user.status==='active'){select.innerHTML+=`<option value="${user.username}">${user.username}</option>`}}
}

async function loadFilesForDistribution(){
    const source=document.getElementById('distSource').value;
    const response=await fetch('/api/privileged/all_files_for_distribution');
    const data=await response.json();
    const select=document.getElementById('distFileSelect');
    select.innerHTML='';
    const files=source==='reserve'?data.reserve_files:data.available_files;
    for(const[name,info]of Object.entries(files||{})){select.innerHTML+=`<option value="${name}">${name} (${info.count} numbers)</option>`}
}

async function distributeNumbers(){
    const username=document.getElementById('distUserSelect').value;
    const filename=document.getElementById('distFileSelect').value;
    const count=parseInt(document.getElementById('distCount').value)||0;
    const source=document.getElementById('distSource').value;
    if(!username){showToast('Select user','error');return}
    if(!filename){showToast('Select file','error');return}
    if(count<=0){showToast('Count must be greater than 0','error');return}
    const response=await fetch('/api/privileged/reserve_to_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,filename,count,source})});
    const data=await response.json();
    if(data.success){showToast(`Distributed ${data.count} numbers to ${username} successfully`);document.getElementById('distCount').value='';loadDashboardStats();}
    else{showToast(data.message||'Error','error');}
}

function handleReserveFileSelect(input){selectedReserveFile=input.files[0];if(selectedReserveFile)showToast('Reserve file selected: '+selectedReserveFile.name)}

async function addReserveNumbers(){
    if(!selectedReserveFile){showToast('Select reserve file first','error');return}
    const formData=new FormData();
    formData.append('file',selectedReserveFile);
    formData.append('filename',document.getElementById('reserveFileName').value);
    formData.append('cost',document.getElementById('reserveFileCost').value);
    const response=await fetch('/api/privileged/reserve_numbers',{method:'POST',body:formData});
    const data=await response.json();
    if(data.success){showToast('Added '+data.count+' reserve numbers in "'+data.filename+'"','success');selectedReserveFile=null;document.getElementById('reserveFile').value='';document.getElementById('reserveFileName').value='';document.getElementById('reserveFileCost').value='';}
    else{showToast(data.message,'error')}
}

async function loadReserveFiles(){
    const response=await fetch('/api/privileged/reserve_numbers');
    const data=await response.json();
    const container=document.getElementById('reserveFilesList');
    container.innerHTML='';
    if(Object.keys(data.files||{}).length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No reserve numbers yet</p></div>';return;}
    let html='<div class="files-grid">';
    for(const[name,info] of Object.entries(data.files||{})){
        html+=`<div class="file-card" style="border-color:rgba(139,92,246,0.3)"><h4 style="color:#A78BFA"><i class="fas fa-shield-alt"></i> ${name}</h4><div class="info"><span>Count: ${info.count} numbers</span><span>Added: ${new Date(info.added_at).toLocaleDateString()}</span></div><div class="cost">Cost: $${info.cost} per number</div><div style="margin-top:10px;font-size:12px;color:var(--muted)">Added by: ${info.added_by}</div></div>`;
    }
    html+='</div>';
    container.innerHTML=html;
}

async function updateAccount(){
    const password=document.getElementById('newPassword').value;
    const phone=document.getElementById('newPhone').value;
    const response=await fetch('/api/user/update_account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,phone})});
    const data=await response.json();
    if(data.success){showToast('Account updated');document.getElementById('newPassword').value='';}
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
loadDashboardStats();
</script>
</body>
</html>
"""

LEGEND_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - Legend Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#8B5CF6;--accent-cyan:#06B6D4;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#7C3AED;--accent-cyan:#0891B2;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#F3E8FF 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#7C3AED}
[data-theme="light"] .nav-item:hover{background:rgba(139,92,246,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(139,92,246,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#2E1065 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* ===== SIDEBAR ===== */
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(139,92,246,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#A78BFA,#C084FC);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(139,92,246,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(139,92,246,0.2),rgba(192,132,252,0.2));color:#fff;border:1px solid rgba(139,92,246,0.3)}
.nav-item.active i{color:#C084FC}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}
.role-badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:0.6rem;font-weight:700;margin-right:auto}
.role-legend{background:linear-gradient(135deg,#8B5CF6,#A855F7);color:white}

/* ===== MAIN CONTENT ===== */
.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

/* ===== HEADER ===== */
.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--accent);background:rgba(139,92,246,0.1)}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),#C084FC);border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

/* ===== SECTIONS ===== */
.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ===== CARDS ===== */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(139,92,246,0.3)}
.stat-card .icon{font-size:24px;margin-bottom:8px;display:block}
.stat-card .number{font-family:'Poppins',sans-serif;font-size:1.6rem;font-weight:700;margin-bottom:4px;color:var(--foreground)}
.stat-card .label{color:var(--muted);font-size:12px}

/* ===== BUTTONS ===== */
.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--accent),#C084FC);color:white;box-shadow:0 4px 16px rgba(139,92,246,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(139,92,246,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(139,92,246,0.1);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--destructive);color:white}
.btn-danger:hover{background:#DC2626;transform:translateY(-2px);box-shadow:0 4px 16px rgba(239,68,68,0.3)}
.btn-success{background:var(--success);color:white}
.btn-sm{padding:6px 12px;font-size:12px}

/* ===== FORMS ===== */
.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-container:hover{border-color:rgba(139,92,246,0.2)}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(139,92,246,0.15)}

/* ===== TABLE ===== */
.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.table-controls{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);flex-wrap:wrap;gap:12px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(139,92,246,0.05)}
.text-primary{color:#C084FC;font-weight:500}
.text-muted{color:var(--muted)}
.text-success{color:var(--success);font-weight:500}
.text-danger{color:var(--destructive);font-weight:500}

/* ===== STATUS BADGES ===== */
.status-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;display:inline-block}
.status-active{background:rgba(16,185,129,0.15);color:#34D399;border:1px solid rgba(16,185,129,0.3)}
.status-banned{background:rgba(239,68,68,0.15);color:#FCA5A5;border:1px solid rgba(239,68,68,0.3)}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
.toast.info{border-right-color:var(--accent)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ===== FOOTER ===== */
.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}

/* ===== SECTION TITLE ===== */
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}

.reserve-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:20px;color:#A78BFA;font-size:12px;font-weight:600}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
    .cards-grid{grid-template-columns:1fr}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>LEGEND PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">User management</div>
        <button class="nav-item" onclick="showSection('createUser',this)"><i class="fas fa-user-plus"></i> Create user</button>
        <button class="nav-item" onclick="showSection('usersList',this)"><i class="fas fa-users"></i> User list</button>
        <button class="nav-item" onclick="showSection('manageUsers',this)"><i class="fas fa-user-shield"></i> Manage users</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Reserve Numbers</div>
        <button class="nav-item" onclick="showSection('viewReserve',this)"><i class="fas fa-eye"></i> View reserve numbers</button>
        <button class="nav-item" onclick="showSection('addReserve',this)"><i class="fas fa-plus-circle"></i> Add reserve numbers</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Account</div>
        <button class="nav-item" onclick="showSection('myAccount',this)"><i class="fas fa-user-cog"></i> My account</button>
    </div>
</div>

<div class="main-content">
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-bolt" style="color:var(--accent)"></i> Legend Panel</h2>
            <p>Direct user creation and management</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar">L</div>
                <span class="user-name" id="legendUsername">Legend</span>
                <span class="role-badge role-legend">LEGEND</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <div class="page-content">
        <!-- DASHBOARD -->
        <div class="content-section active" id="dashboard">
            <div class="cards-grid">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128101;</span><div class="number" id="totalUsers">0</div><div class="label">Total users</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#9989;</span><div class="number" id="activeUsers">0</div><div class="label">Active users</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--destructive)">&#128683;</span><div class="number" id="bannedUsers">0</div><div class="label">Banned users</div></div>
                <div class="stat-card"><span class="icon" style="color:#A78BFA">&#128737;</span><div class="number" id="reserveCount">0</div><div class="label">Reserve numbers</div></div>
            </div>
            <div class="form-container" style="text-align:center;padding:48px">
                <i class="fas fa-bolt" style="font-size:4rem;background:linear-gradient(135deg,#A78BFA,#C084FC);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:20px"></i>
                <h3 style="color:var(--accent);margin-bottom:12px">Welcome to Legend Panel</h3>
                <p style="color:var(--muted)">You can create users directly without owner approval.<br>Manage users and access reserve numbers.</p>
            </div>
        </div>

        <!-- CREATE USER -->
        <div class="content-section" id="createUser">
            <h3 class="section-title"><i class="fas fa-user-plus"></i> Create new user</h3>
            <div class="form-container">
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Username</label><input type="text" id="newUsername" placeholder="Choose username"></div>
                    <div class="form-group"><label>Password</label><input type="password" id="newPassword" placeholder="Choose password"></div>
                    <div class="form-group"><label>Phone number</label><input type="tel" id="newPhone" placeholder="+20xxxxxxxxxx"></div>
                </div>
                <button class="btn btn-primary" onclick="createUser()" style="background:linear-gradient(135deg,#8B5CF6,#C084FC)"><i class="fas fa-plus"></i> Create account immediately</button>
                <p style="color:var(--muted);margin-top:12px;font-size:12px">The account will be created directly without owner approval.</p>
            </div>
        </div>

        <!-- USERS LIST -->
        <div class="content-section" id="usersList">
            <h3 class="section-title"><i class="fas fa-users"></i> User list</h3>
            <div class="table-wrapper">
                <div class="table-controls"><span style="color:var(--muted)">All users you can manage</span></div>
                <table>
                    <thead><tr><th>User</th><th>Status</th><th>Phone</th><th>Limit</th><th>Created by</th><th>Registration date</th></tr></thead>
                    <tbody id="usersTable"></tbody>
                </table>
            </div>
        </div>

        <!-- MANAGE USERS -->
        <div class="content-section" id="manageUsers">
            <h3 class="section-title"><i class="fas fa-user-shield"></i> Manage users</h3>
            <div class="table-wrapper">
                <div class="table-controls"><span style="color:var(--muted)">Ban or activate user accounts</span></div>
                <table>
                    <thead><tr><th>User</th><th>Status</th><th>Registration date</th><th>Actions</th></tr></thead>
                    <tbody id="manageUsersTable"></tbody>
                </table>
            </div>
        </div>

        <!-- VIEW RESERVE -->
        <div class="content-section" id="viewReserve">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
                <h3 class="section-title" style="margin:0"><i class="fas fa-eye" style="color:#A78BFA"></i> Reserve numbers</h3>
                <span class="reserve-badge"><i class="fas fa-lock"></i> Private</span>
            </div>
            <div id="reserveFilesList"></div>
        </div>

        <!-- ADD RESERVE -->
        <div class="content-section" id="addReserve">
            <h3 class="section-title"><i class="fas fa-plus-circle" style="color:#A78BFA"></i> Add reserve numbers</h3>
            <div class="form-container" style="border-color:rgba(139,92,246,0.3)">
                <div class="file-upload" onclick="document.getElementById('reserveFile').click()" style="border-color:rgba(139,92,246,0.3)">
                    <i class="fas fa-cloud-upload-alt" style="color:#A78BFA"></i>
                    <p>Click to upload reserve numbers file (.txt)</p>
                    <input type="file" id="reserveFile" accept=".txt" style="display:none" onchange="handleReserveFileSelect(this)">
                </div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>File name</label><input type="text" id="reserveFileName" placeholder="Example: Reserve USA"></div>
                    <div class="form-group"><label>Cost per number ($)</label><input type="number" id="reserveFileCost" placeholder="0.00" step="0.01"></div>
                </div>
                <button class="btn btn-primary" onclick="addReserveNumbers()" style="background:linear-gradient(135deg,#8B5CF6,#6366F1)"><i class="fas fa-save"></i> Save reserve numbers</button>
            </div>
        </div>

        <!-- MY ACCOUNT -->
        <div class="content-section" id="myAccount">
            <h3 class="section-title"><i class="fas fa-user-cog"></i> My account</h3>
            <div class="form-container">
                <div class="form-group"><label>New password</label><input type="password" id="accNewPassword" placeholder="Leave blank if you don't want to change"></div>
                <div class="form-group"><label>Phone number</label><input type="tel" id="accNewPhone" placeholder="Phone number"></div>
                <button class="btn btn-primary" onclick="updateAccount()"><i class="fas fa-save"></i> Save</button>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
const socket=io();
let selectedReserveFile=null;

socket.on('connect',()=>{fetch('/api/user/my_account').then(r=>r.json()).then(data=>{if(data.success){document.getElementById('legendUsername').textContent=data.user.username||'Legend';socket.emit('join',{username:data.user.username})}})});

function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='dashboard')loadDashboardStats();
    if(sectionId==='usersList')loadUsersList();
    if(sectionId==='manageUsers')loadManageUsers();
    if(sectionId==='viewReserve')loadReserveFiles();
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':type==='info'?'info':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':type==='error'?'exclamation-circle':'info-circle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function loadDashboardStats(){
    const response=await fetch('/api/legend/dashboard_stats');
    const data=await response.json();
    if(data.success){
        document.getElementById('totalUsers').textContent=data.total_users;
        document.getElementById('activeUsers').textContent=data.active_users;
        document.getElementById('bannedUsers').textContent=data.banned_users;
        document.getElementById('reserveCount').textContent=data.total_reserve_numbers;
    }
}

async function createUser(){
    const username=document.getElementById('newUsername').value.trim();
    const password=document.getElementById('newPassword').value;
    const phone=document.getElementById('newPhone').value;
    if(!username||!password){showToast('Username and password required','error');return}
    const response=await fetch('/api/legend/create_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,phone})});
    const data=await response.json();
    if(data.success){
        showToast('User '+username+' created successfully!');
        document.getElementById('newUsername').value='';
        document.getElementById('newPassword').value='';
        document.getElementById('newPhone').value='';
    }else{showToast(data.message,'error');}
}

async function loadUsersList(){
    const response=await fetch('/api/legend/users_list');
    const data=await response.json();
    const tbody=document.getElementById('usersTable');
    tbody.innerHTML='';
    if(!data.users||data.users.length===0){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted)">No users</td></tr>';return;}
    for(const user of data.users){
        const statusClass=user.status==='active'?'status-active':'status-banned';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${user.username}</td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td>${user.phone||'-'}</td><td>${user.limit}</td><td class="text-muted">${user.created_by||'-'}</td><td class="text-muted">${user.created_at?new Date(user.created_at).toLocaleDateString():'-'}</td></tr>`;
    }
}

async function loadManageUsers(){
    const response=await fetch('/api/legend/users_list');
    const data=await response.json();
    const tbody=document.getElementById('manageUsersTable');
    tbody.innerHTML='';
    if(!data.users||data.users.length===0){tbody.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted)">No users</td></tr>';return;}
    for(const user of data.users){
        const statusClass=user.status==='active'?'status-active':'status-banned';
        const btnClass=user.status==='active'?'btn-danger':'btn-success';
        const btnIcon=user.status==='active'?'fa-ban':'fa-check';
        const btnText=user.status==='active'?'Ban':'Activate';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${user.username}</td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td class="text-muted">${user.created_at?new Date(user.created_at).toLocaleDateString():'-'}</td><td><button class="btn ${btnClass} btn-sm" onclick="toggleUserStatus('${user.username}')"><i class="fas ${btnIcon}"></i> ${btnText}</button></td></tr>`;
    }
}

async function toggleUserStatus(username){
    const response=await fetch('/api/legend/toggle_user_status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    const data=await response.json();
    if(data.success){showToast('User '+username+' is now '+data.status);loadManageUsers();loadDashboardStats();}
    else{showToast(data.message,'error');}
}

function handleReserveFileSelect(input){selectedReserveFile=input.files[0];if(selectedReserveFile)showToast('Reserve file selected: '+selectedReserveFile.name)}

async function addReserveNumbers(){
    if(!selectedReserveFile){showToast('Select reserve file first','error');return}
    const formData=new FormData();
    formData.append('file',selectedReserveFile);
    formData.append('filename',document.getElementById('reserveFileName').value);
    formData.append('cost',document.getElementById('reserveFileCost').value);
    const response=await fetch('/api/privileged/reserve_numbers',{method:'POST',body:formData});
    const data=await response.json();
    if(data.success){showToast('Added '+data.count+' reserve numbers in "'+data.filename+'"','success');selectedReserveFile=null;document.getElementById('reserveFile').value='';document.getElementById('reserveFileName').value='';document.getElementById('reserveFileCost').value='';}
    else{showToast(data.message,'error')}
}

async function loadReserveFiles(){
    const response=await fetch('/api/privileged/reserve_numbers');
    const data=await response.json();
    const container=document.getElementById('reserveFilesList');
    container.innerHTML='';
    if(Object.keys(data.files||{}).length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No reserve numbers yet</p></div>';return;}
    let html='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px">';
    for(const[name,info] of Object.entries(data.files||{})){
        html+=`<div class="form-container" style="border-color:rgba(139,92,246,0.3)"><h4 style="color:#A78BFA;margin-bottom:12px"><i class="fas fa-shield-alt"></i> ${name}</h4><div style="display:flex;justify-content:space-between;margin-bottom:10px;color:var(--muted);font-size:13px"><span>Count: ${info.count} numbers</span><span>Added: ${new Date(info.added_at).toLocaleDateString()}</span></div><div style="color:var(--success);font-weight:700;font-size:16px">Cost: $${info.cost} per number</div><div style="margin-top:10px;font-size:12px;color:var(--muted)">Added by: ${info.added_by}</div></div>`;
    }
    html+='</div>';
    container.innerHTML=html;
}

async function updateAccount(){
    const password=document.getElementById('accNewPassword').value;
    const phone=document.getElementById('accNewPhone').value;
    const response=await fetch('/api/user/update_account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,phone})});
    const data=await response.json();
    if(data.success){showToast('Account updated');document.getElementById('accNewPassword').value='';}
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
loadDashboardStats();
</script>
</body>
</html>
"""

USER_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - User Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#3B82F6;--accent-purple:#8B5CF6;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#D97706;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#FEF3C7 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#D97706}
[data-theme="light"] .nav-item:hover{background:rgba(245,158,11,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(245,158,11,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#2563EB;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#E0E7FF 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .file-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .sms-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .notification-panel{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#2563EB}
[data-theme="light"] .nav-item:hover{background:rgba(59,130,246,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(59,130,246,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#1E1B4B 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* ===== SIDEBAR ===== */
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(59,130,246,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#60A5FA,#A78BFA);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(59,130,246,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(59,130,246,0.2),rgba(139,92,246,0.2));color:#fff;border:1px solid rgba(59,130,246,0.3)}
.nav-item.active i{color:#60A5FA}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}

/* ===== MAIN CONTENT ===== */
.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

/* ===== HEADER ===== */
.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--accent);background:rgba(59,130,246,0.1)}
.notification-badge{position:absolute;top:4px;right:4px;width:8px;height:8px;background-color:var(--destructive);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(1.2)}}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent-purple));border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

/* ===== SECTIONS ===== */
.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ===== CARDS ===== */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(59,130,246,0.3)}
.stat-card .icon{font-size:24px;margin-bottom:8px;display:block}
.stat-card .number{font-family:'Poppins',sans-serif;font-size:1.6rem;font-weight:700;margin-bottom:4px;color:var(--foreground)}
.stat-card .label{color:var(--muted);font-size:12px}

/* ===== BUTTONS ===== */
.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;box-shadow:0 4px 16px rgba(59,130,246,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(59,130,246,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(59,130,246,0.1);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--destructive);color:white}
.btn-sm{padding:6px 12px;font-size:12px}

/* ===== FORMS ===== */
.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,0.15)}

/* ===== TABLE ===== */
.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(59,130,246,0.05)}
.text-primary{color:#60A5FA;font-weight:500}
.text-muted{color:var(--muted)}
.text-mono{font-family:'Courier New',monospace;font-weight:500;font-size:12px}
.text-success{color:var(--success);font-weight:500}

/* ===== FILE CARDS ===== */
.files-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.file-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.file-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(59,130,246,0.3)}
.file-card h4{color:#60A5FA;margin-bottom:12px;font-size:15px;display:flex;align-items:center;gap:8px}
.file-card .info{display:flex;justify-content:space-between;margin-bottom:10px;color:var(--muted);font-size:13px}
.file-card .cost{color:var(--success);font-weight:700;font-size:16px}
.qty-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px}
.qty-btn{padding:10px;background:rgba(59,130,246,0.08);border:1px solid var(--border);border-radius:8px;color:#60A5FA;font-family:'Poppins',sans-serif;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s ease}
.qty-btn:hover,.qty-btn.selected{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;border-color:transparent;transform:scale(1.02)}

/* ===== SMS CARDS ===== */
.sms-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:16px;margin-bottom:12px;transition:all 0.3s ease}
.sms-card:hover{border-color:rgba(59,130,246,0.3);box-shadow:0 4px 16px rgba(59,130,246,0.1)}
.sms-card .phone{color:#60A5FA;font-weight:600;font-size:14px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.sms-card .message{color:var(--foreground);margin-bottom:10px;line-height:1.6;font-size:13px}
.sms-card .meta{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);align-items:center}
.sms-card .api-badge{background:rgba(59,130,246,0.15);color:#60A5FA;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600}
.sms-card.api-global{border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.03)}
.sms-card.api-global .phone{color:var(--warning)}

/* ===== NOTIFICATION PANEL ===== */
.notification-panel{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:16px;margin-bottom:12px;transition:all 0.2s ease}
.notification-panel.unread{border-color:var(--warning);background:rgba(245,158,11,0.05)}
.notification-panel .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.notification-panel .type{background:rgba(59,130,246,0.15);color:#60A5FA;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600}
.notification-panel .time{color:var(--muted);font-size:12px}
.notification-panel p{font-size:13px;color:var(--foreground);line-height:1.5}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
.toast.info{border-right-color:var(--accent)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ===== FOOTER ===== */
.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}

/* ===== SECTION TITLE ===== */
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
    .cards-grid{grid-template-columns:1fr}
    .qty-grid{grid-template-columns:repeat(2,1fr)}
    .files-grid{grid-template-columns:1fr}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>USER PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Numbers</div>
        <button class="nav-item" onclick="showSection('requestNumbers',this)"><i class="fas fa-plus-circle"></i> Request numbers</button>
        <button class="nav-item" onclick="showSection('myNumbers',this)"><i class="fas fa-list"></i> My Numbers</button>
        <button class="nav-item" onclick="showSection('myRange',this)"><i class="fas fa-chart-bar"></i> My Range</button>
        <button class="nav-item" onclick="showSection('myFiles',this)"><i class="fas fa-file-download"></i> My Files</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Messages</div>
        <button class="nav-item" onclick="showSection('mySMS',this)"><i class="fas fa-envelope"></i> My Messages</button>
        <button class="nav-item" onclick="showSection('latestMessages',this)"><i class="fas fa-bolt"></i> Latest messages</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Account</div>
        <button class="nav-item" onclick="showSection('notifications',this)"><i class="fas fa-bell"></i> notifications</button>
        <button class="nav-item" onclick="showSection('payments',this)"><i class="fas fa-credit-card"></i> Payments</button>
        <button class="nav-item" onclick="showSection('myAccount',this)"><i class="fas fa-user-cog"></i> My account</button>
    </div>
</div>

<div class="main-content">
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-user" style="color:var(--accent)"></i> AGENT PANEL</h2>
            <p>X PANEL</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <button class="header-icon-btn" onclick="showSection('notifications',this)" title="notifications">
                <i class="fas fa-bell"></i>
                <span class="notification-badge" id="notifBadge" style="display:none"></span>
            </button>
            <button class="header-icon-btn" title="Settings"><i class="fas fa-cog"></i></button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar" id="userAvatar">U</div>
                <span class="user-name" id="userNameDisplay">User</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <div class="page-content">
        <!-- DASHBOARD -->
        <div class="content-section active" id="dashboard">
            <div class="cards-grid">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128241;</span><div class="number" id="totalMyNumbers">0</div><div class="label">Total My Numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128172;</span><div class="number" id="totalMySMS">0</div><div class="label">Messages received</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--warning)">&#128194;</span><div class="number" id="totalMyFiles">0</div><div class="label">Files</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--destructive)">&#128176;</span><div class="number" id="totalSpent">0</div><div class="label">Total expenses ($)</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128202;</span><div class="number" id="dailyLimitRemaining">2000</div><div class="label">Remaining daily limit</div></div>
            </div>
        </div>

        <!-- REQUEST NUMBERS -->
        <div class="content-section" id="requestNumbers">
            <h3 class="section-title"><i class="fas fa-plus-circle"></i> Request new numbers</h3>
            <div id="availableFiles"></div>
        </div>

        <!-- MY NUMBERS -->
        <div class="content-section" id="myNumbers">
            <h3 class="section-title"><i class="fas fa-list"></i> My Numbers</h3>
            <div class="action-buttons">
                <button class="btn btn-danger" onclick="showDeleteMyNumbers()"><i class="fas fa-trash"></i> Delete My Numbers</button>
            </div>
            <div id="myNumbersList"></div>
        </div>

        <!-- MY RANGE -->
        <div class="content-section" id="myRange">
            <h3 class="section-title"><i class="fas fa-chart-bar"></i> My Range</h3>
            <div id="myRangeList"></div>
        </div>

        <!-- MY FILES -->
        <div class="content-section" id="myFiles">
            <h3 class="section-title"><i class="fas fa-file-download"></i> My Files</h3>
            <div id="myFilesList"></div>
        </div>

        <!-- MY SMS -->
        <div class="content-section" id="mySMS">
            <h3 class="section-title"><i class="fas fa-envelope"></i> My Messages</h3>
            <div class="action-buttons">
                <button class="btn btn-primary" id="refreshSMSBtn" onclick="refreshSMS()"><i class="fas fa-sync-alt"></i> Update messages</button>
            </div>
            <div class="form-container" style="padding:16px;margin-bottom:16px">
                <div style="display:flex;gap:10px;align-items:center">
                    <div style="flex:1">
                        <input type="text" id="smsSearchInput" placeholder="Search phone..." style="width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground)" onkeyup="searchSMS()">
                    </div>
                    <button class="btn btn-outline" onclick="clearSMSSearch()" style="white-space:nowrap"><i class="fas fa-times"></i> Clear</button>
                </div>
                <div id="smsSearchStats" style="margin-top:8px;font-size:12px;color:var(--muted)"></div>
            </div>
            <div id="smsDebugInfo" style="margin-bottom:16px;font-size:12px;color:var(--muted);display:none"></div>
            <div id="smsList"></div>
        </div>

        <!-- LATEST MESSAGES -->
        <div class="content-section" id="latestMessages">
            <h3 class="section-title"><i class="fas fa-bolt"></i> Latest messages</h3>
            <div class="form-container" style="padding:16px;margin-bottom:16px">
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <input type="text" id="cliSearchInput" placeholder="Service (e.g. Whatsapp)" style="flex:1;min-width:180px;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground)" onkeydown="if(event.key==='Enter')searchCli()">
                    <button class="btn btn-primary" onclick="searchCli()"><i class="fas fa-search"></i> Search cli</button>
                </div>
                <div id="cliResults" style="margin-top:12px"></div>
            </div>
            <div id="latestMessagesList"></div>
        </div>

        <!-- NOTIFICATIONS -->
        <div class="content-section" id="notifications">
            <h3 class="section-title"><i class="fas fa-bell"></i> notifications</h3>
            <div id="notificationsList"></div>
        </div>

        <!-- PAYMENTS -->
        <div class="content-section" id="payments">
            <h3 class="section-title"><i class="fas fa-credit-card"></i> Payments</h3>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Type</th><th>Details</th><th>Cost</th><th>Date</th></tr></thead>
                    <tbody id="paymentsTable"></tbody>
                </table>
            </div>
        </div>

        <!-- MY ACCOUNT -->
        <div class="content-section" id="myAccount">
            <h3 class="section-title"><i class="fas fa-user-cog"></i> Account settings</h3>
            <div class="form-container">
                <div class="form-group"><label>New password</label><input type="password" id="newPassword" placeholder="Leave blank if you don't want to change"></div>
                <div class="form-group"><label>Phone number</label><input type="tel" id="newPhone" placeholder="Phone number"></div>
                <button class="btn btn-primary" onclick="updateAccount()"><i class="fas fa-save"></i> Save</button>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
const socket=io();
let currentUsername='',allSMSCache=[];

socket.on('connect',()=>{fetch('/api/user/my_account').then(r=>r.json()).then(data=>{if(data.success){currentUsername=data.user.username||'';document.getElementById('userAvatar').textContent=currentUsername.charAt(0).toUpperCase();document.getElementById('userNameDisplay').textContent=currentUsername;socket.emit('join',{username:currentUsername})}})});
socket.on('new_sms',(data)=>{showToast('New message from: '+data.number,'info');if(document.getElementById('mySMS').classList.contains('active')){loadMySMS()}updateNotificationBadge()});
socket.on('broadcast',(data)=>{showToast('Broadcast: '+data.message,'info');if('Notification' in window&&Notification.permission==='granted'){new Notification('X PANEL',{body:data.message})}});

function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='requestNumbers')loadAvailableFiles();
    if(sectionId==='myNumbers')loadMyNumbers();
    if(sectionId==='myRange')loadMyRange();
    if(sectionId==='myFiles')loadMyFiles();
    if(sectionId==='mySMS')loadMySMS();
    if(sectionId==='latestMessages')loadLatestMessages();
    if(sectionId==='notifications')loadNotifications();
    if(sectionId==='payments')loadPayments();
    if(sectionId==='dashboard')loadDashboardStats();
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':type==='info'?'info':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':type==='error'?'exclamation-circle':'info-circle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function loadDashboardStats(){
    const numbers=await fetch('/api/user/my_numbers').then(r=>r.json());
    const sms=await fetch('/api/user/my_sms').then(r=>r.json());
    const payments=await fetch('/api/user/payments').then(r=>r.json());
    const dailyLimit=await fetch('/api/user/daily_limit').then(r=>r.json());
    let totalNumbers=0;for(const nums of Object.values(numbers.numbers||{})){totalNumbers+=nums.length}
    let totalSMS=0;for(const msgs of Object.values(sms.sms||{})){totalSMS+=msgs.length}
    let totalSpent=0;for(const p of payments.payments||[]){if(p.type==='sms'||p.type==='purchase'){totalSpent+=p.cost||0}}
    document.getElementById('totalMyNumbers').textContent=totalNumbers;
    document.getElementById('totalMySMS').textContent=totalSMS;
    document.getElementById('totalMyFiles').textContent=Object.keys(numbers.numbers||{}).length;
    document.getElementById('totalSpent').textContent=totalSpent.toFixed(2);
    const remaining=dailyLimit.daily_remaining||2000;
    const limitEl=document.getElementById('dailyLimitRemaining');
    limitEl.textContent=remaining;
    if(remaining<100)limitEl.style.color='var(--destructive)';
    else if(remaining<500)limitEl.style.color='var(--warning)';
}

async function loadAvailableFiles(){
    const response=await fetch('/api/user/available_numbers');
    const data=await response.json();
    const container=document.getElementById('availableFiles');
    const files=Object.entries(data.files||{});
    if(!files.length){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No files available</p></div>';return}
    const prices=data.sms_prices||{};
    const th='padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap';
    const td='padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)';
    let html=`<div class="table-wrapper"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--glass)"><th style="${th}">Range</th><th style="${th}">Your Profit Per SMS</th><th style="${th}">Actions</th></tr></thead><tbody>`;
    for(const[name,info]of files){
        const avail=(info.numbers||[]).length;
        const take=Math.min(50,avail);
        html+=`<tr><td style="${td};font-weight:600">${lmEsc(name)} <span style="color:var(--muted);font-weight:400;font-size:11px">(${avail})</span></td><td style="${td}">$${prices[name]!=null?prices[name]:0.01}</td><td style="${td}"><button class="btn btn-primary" ${take?'':'disabled'} data-file="${lmEsc(name)}" onclick="requestNumbers(this.dataset.file,${take})"><i class="fas fa-plus-circle"></i> Request number</button></td></tr>`;
    }
    html+='</tbody></table></div>';
    container.innerHTML=html;
}

async function requestNumbers(filename,count){
    const response=await fetch('/api/user/request_numbers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename,count})});
    const data=await response.json();
    if(data.success){showToast(`Added ${data.assigned.length} numbers - Cost: $${data.cost} - Daily remaining: ${data.daily_remaining}`,'success');loadAvailableFiles();loadDashboardStats();}
    else{showToast(data.message,'error')}
}

async function loadMyNumbers(){
    const response=await fetch('/api/user/my_numbers');
    const data=await response.json();
    const container=document.getElementById('myNumbersList');
    container.innerHTML='';
    const costs=data.costs||{};

    if(!data.numbers || Object.keys(data.numbers).length===0){
        container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No numbers yet</p></div>';
        return;
    }

    for(const[filename,numbers]of Object.entries(data.numbers||{})){
        const costPerNumber=costs[filename]||0;
        const totalCost = (costPerNumber * numbers.length).toFixed(2);

        container.innerHTML+=`<div class="form-container" style="padding:0;overflow:hidden">
            <div style="padding:16px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);display:flex;align-items:center;gap:10px">
                <i class="fas fa-file-alt" style="color:var(--accent)"></i>
                <span style="font-weight:600;font-size:15px;color:var(--foreground)">${filename}</span>
                <span style="margin-right:auto;color:var(--muted);font-size:12px">${numbers.length} numbers</span>
            </div>
            <div style="overflow-x:auto">
                <table class="numbers-table" style="width:100%;border-collapse:collapse">
                    <thead>
                        <tr style="background:var(--glass)">
                            <th style="width:40px;padding:12px 16px;text-align:center">
                                <input type="checkbox" class="checkbox" onchange="toggleSelectAll('${filename}',this)" style="width:16px;height:16px;cursor:pointer;accent-color:var(--accent)">
                            </th>
                            <th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border)">Range</th>
                            <th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border)">Number</th>
                            <th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border)">My Payout</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${numbers.map((num,i)=>`<tr style="transition:background-color 0.2s ease" onmouseover="this.style.background='rgba(59,130,246,0.05)'" onmouseout="this.style.background='transparent'">
                            <td style="padding:12px 16px;text-align:center;border-bottom:1px solid var(--glass-border)">
                                <input type="checkbox" class="checkbox row-check-${filename}" value="${num}" style="width:16px;height:16px;cursor:pointer;accent-color:var(--accent)">
                            </td>
                            <td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);font-weight:500">${filename}</td>
                            <td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)" class="text-mono">${num}</td>
                            <td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--success);font-weight:600">$ ${costPerNumber.toFixed(2)}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
            <div style="padding:12px 20px;background:var(--glass);border-top:1px solid var(--glass-border);display:flex;justify-content:space-between;align-items:center">
                <span style="font-size:12px;color:var(--muted)">Total: ${numbers.length} numbers</span>
                <span style="font-size:13px;color:var(--success);font-weight:700">Total: $ ${totalCost}</span>
            </div>
        </div>`;
    }
}

function toggleSelectAll(filename,checkbox){
    const rows=document.querySelectorAll('.row-check-'+filename);
    rows.forEach(row=>row.checked=checkbox.checked);
}

function showDeleteMyNumbers(){
    const filename=prompt('Enter the file name you want to delete:');
    if(filename){fetch('/api/user/delete_my_numbers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename})}).then(()=>{showToast('Deleted');loadMyNumbers()})}
}

async function loadMyRange(){
    const response=await fetch('/api/user/my_range');
    const data=await response.json();
    const container=document.getElementById('myRangeList');
    container.innerHTML='';
    for(const[filename,count]of Object.entries(data.range||{})){container.innerHTML+=`<div class="stat-card" style="margin-bottom:12px"><span class="icon" style="color:var(--accent)">&#128194;</span><div class="number">${count}</div><div class="label">${filename}</div></div>`}
}

async function loadMyFiles(){
    const response=await fetch('/api/user/my_numbers');
    const data=await response.json();
    const container=document.getElementById('myFilesList');
    container.innerHTML='';
    for(const filename of Object.keys(data.numbers||{})){container.innerHTML+=`<div class="file-card"><h4><i class="fas fa-file-alt"></i> ${filename}</h4><button class="btn btn-primary" onclick="downloadFile('${filename}')" style="margin-top:12px"><i class="fas fa-download"></i> Download file</button></div>`}
}

async function downloadFile(filename){
    const response=await fetch('/api/user/download_file',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename})});
    if(response.ok){const blob=await response.blob();const url=window.URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename+'.txt';a.click();showToast('Downloaded')}
}

async function loadMySMS(){
    const response=await fetch('/api/user/my_sms');
    const data=await response.json();
    const container=document.getElementById('smsList');
    container.innerHTML='';
    allSMSCache=[];
    window.smsFileMap = {}; // phone -> filename mapping
    console.log('SMS Data:',data);
    if(!data.sms||Object.keys(data.sms).length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No messages</p></div>';return}

    // Get user's numbers to build phone->file mapping
    const numbersResponse = await fetch('/api/user/my_numbers');
    const numbersData = await numbersResponse.json();
    const phoneToFile = {};
    const phoneToFileNormalized = {};
    for(const[filename, nums] of Object.entries(numbersData.numbers || {})){
        if(Array.isArray(nums)){
            for(const num of nums){ 
                const cleanNum = String(num).trim();
                phoneToFile[cleanNum] = filename;
                // Also store normalized version (digits only) for flexible matching
                const normalized = cleanNum.replace(/\\D/g, '');
                if(normalized) phoneToFileNormalized[normalized] = filename;
            }
        }
    }
    window.smsFileMap = phoneToFile;
    console.log('Phone to File mapping:', phoneToFile);

    const filteredSMS={};
    for(const[phone,messages]of Object.entries(data.sms||{})){if(phone.startsWith('test_')||phone.startsWith('api_test_')){continue}filteredSMS[phone]=messages}

    // Build file filter dropdown options
    const fileSet = new Set();
    for(const[phone,messages]of Object.entries(filteredSMS)){
        const cleanPhone = phone.startsWith('api_') ? phone.replace('api_','').trim() : String(phone).trim();
        let fname = phoneToFile[cleanPhone];
        if(!fname) {
            const normalized = cleanPhone.replace(/\\D/g, '');
            fname = phoneToFileNormalized[normalized];
        }
        if(!fname) fname = phone.startsWith('api_') ? 'API Global' : 'Unknown';
        fileSet.add(fname);
    }
    const fileOptions = Array.from(fileSet).sort();

    let tableHTML = '<div class="table-wrapper" style="margin-bottom:20px"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--glass)"><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Date</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">File Name</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Number</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Service</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Message</th></tr></thead><tbody id="smsTableBody">';

    let rowCount = 0;
    for(const[phone,messages]of Object.entries(filteredSMS)){
        if(!Array.isArray(messages))continue;
        const sortedMessages=[...messages].sort((a,b)=>new Date(b.time)-new Date(a.time));
        const isApiGlobal=phone.startsWith('api_');
        const displayPhone=isApiGlobal?phone.replace('api_','').trim():String(phone).trim();
        let fileName = phoneToFile[displayPhone];
            if(!fileName) {
                const normalizedPhone = displayPhone.replace(/\\D/g, '');
                fileName = phoneToFileNormalized[normalizedPhone];
            }
            if(!fileName) fileName = isApiGlobal ? 'API Global' : 'Unknown';
        for(const sms of sortedMessages){
            const msgText=sms.message||sms.text||sms.body||'No message';
            const apiName=sms.api||'Unknown';
            const timeStr=sms.time?new Date(sms.time).toLocaleString():'-';
            // Detect service from message
            let service = 'Other';
            const msgLower = msgText.toLowerCase();
            if(msgLower.includes('whatsapp') || msgLower.includes('واتس')) service = 'WhatsApp';
            else if(msgLower.includes('paypal') || msgLower.includes('باي بال')) service = 'PayPal';
            else if(msgLower.includes('telegram') || msgLower.includes('تلغرام')) service = 'Telegram';
            else if(msgLower.includes('facebook') || msgLower.includes('فيسبوك')) service = 'Facebook';
            else if(msgLower.includes('instagram') || msgLower.includes('انستغرام')) service = 'Instagram';
            else if(msgLower.includes('google') || msgLower.includes('جوجل')) service = 'Google';
            else if(msgLower.includes('twitter') || msgLower.includes('تويتر') || msgLower.includes('x.com')) service = 'Twitter/X';
            else if(msgLower.includes('amazon') || msgLower.includes('أمازون')) service = 'Amazon';
            else if(msgLower.includes('netflix') || msgLower.includes('نتفليكس')) service = 'Netflix';
            else if(msgLower.includes('uber') || msgLower.includes('أوبر')) service = 'Uber';
            else if(msgLower.includes('otp') || msgLower.includes('code') || msgLower.includes('كود')) service = 'OTP';

            allSMSCache.push({phone:displayPhone,message:msgText,api:apiName,time:sms.time,source:sms.source,isApiGlobal:isApiGlobal,fileName:fileName,service:service});
            const serviceColor = service === 'WhatsApp' ? '#22c55e' : service === 'PayPal' ? '#003087' : service === 'Telegram' ? '#0088cc' : service === 'Google' ? '#ea4335' : service === 'Facebook' ? '#1877f2' : 'var(--accent)';
            tableHTML += `<tr data-filename="${fileName}" style="transition:background-color 0.2s ease" onmouseover="this.style.background='rgba(59,130,246,0.05)'" onmouseout="this.style.background='transparent'"><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:12px;color:var(--muted);white-space:nowrap">${timeStr}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);font-weight:500">${fileName}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)" class="text-mono">${displayPhone}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:12px;font-weight:600" style="color:${serviceColor}">${service}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);max-width:300px;overflow:hidden;text-overflow:ellipsis">${msgText}</td></tr>`;
            rowCount++;
        }
    }
    tableHTML += '</tbody></table></div>';

    // File filter dropdown
    let filterHTML = '<div class="form-container" style="padding:16px;margin-bottom:16px"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><label style="font-size:13px;font-weight:600;color:var(--foreground)"><i class="fas fa-filter"></i> Filter by file:</label><select id="smsFileFilter" onchange="filterSMSByFile()" style="padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);min-width:200px"><option value="ALL">All Files</option>';
    for(const fname of fileOptions){ filterHTML += `<option value="${fname}">${fname}</option>`; }
    filterHTML += '</select><span id="smsFilterCount" style="font-size:12px;color:var(--muted)"></span></div></div>';

    container.innerHTML = filterHTML + tableHTML;
    document.getElementById('smsFilterCount').textContent = `${rowCount} messages`;
    console.log(`SMS Loaded: ${rowCount} total messages, Files: ${fileOptions.length}`);
}

function filterSMSByFile(){
    const selectedFile = document.getElementById('smsFileFilter').value;
    const rows = document.querySelectorAll('#smsTableBody tr');
    let visibleCount = 0;
    rows.forEach(row => {
        const fileName = row.getAttribute('data-filename');
        if(selectedFile === 'ALL' || fileName === selectedFile){
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
        }
    });
    document.getElementById('smsFilterCount').textContent = `${visibleCount} messages`;
}

async function refreshSMS(){
    const btn=document.getElementById('refreshSMSBtn');
    btn.querySelector('i').classList.add('fa-spin');
    btn.disabled=true;
    const response=await fetch('/api/user/my_sms');
    const data=await response.json();
    console.log('Manual refresh - SMS data:',data);
    await loadMySMS();
    const totalMessages=Object.values(data.sms||{}).reduce((acc,arr)=>acc+(Array.isArray(arr)?arr.length:0),0);
    showToast(`Updated messages (${totalMessages} messages)`,totalMessages>0?'success':'info');
    btn.querySelector('i').classList.remove('fa-spin');
    btn.disabled=false;
}

function lmEsc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

async function loadLatestMessages(){
    const container=document.getElementById('latestMessagesList');
    let data;
    try{data=await (await fetch('/api/user/latest_messages')).json()}catch(e){return}
    const rows=data.rows||[];
    if(!rows.length){
        container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No messages yet</p></div>';
        return;
    }
    const th='padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap';
    const td='padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)';
    let html=`<div class="table-wrapper"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--glass)"><th style="${th}">Service</th><th style="${th}">Number</th><th style="${th}">Range</th><th style="${th}">Message</th></tr></thead><tbody>`;
    for(const x of rows){
        const numStyle=x.owned?';color:var(--success);font-weight:700':'';
        html+=`<tr><td style="${td};font-weight:600">${lmEsc(x.service)}</td><td style="${td}${numStyle}" class="text-mono">${lmEsc(x.number)}</td><td style="${td}">${lmEsc(x.range)}</td><td style="${td};max-width:360px;word-break:break-word">${lmEsc(x.message)}</td></tr>`;
    }
    html+='</tbody></table></div>';
    container.innerHTML=html;
}

async function searchCli(){
    const q=document.getElementById('cliSearchInput').value.trim();
    const box=document.getElementById('cliResults');
    let data;
    try{data=await (await fetch('/api/user/search_cli?service='+encodeURIComponent(q))).json()}catch(e){return}
    const res=data.results||[];
    if(!res.length){box.innerHTML='<p style="color:var(--muted);font-size:13px">No ranges found</p>';return}
    box.innerHTML='<div class="table-wrapper"><table style="width:100%;border-collapse:collapse"><thead><tr><th>Range</th><th>Service</th></tr></thead><tbody>'+res.map(x=>`<tr><td>${lmEsc(x.range)}</td><td>${lmEsc(x.service)}</td></tr>`).join('')+'</tbody></table></div>';
}

async function loadNotifications(){
    const response=await fetch('/api/user/notifications');
    const data=await response.json();
    const container=document.getElementById('notificationsList');
    container.innerHTML='';
    const notifs=data.notifications||[];
    if(notifs.length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No notifications</p></div>';return;}
    for(const notif of notifs.slice().reverse()){
        container.innerHTML+=`<div class="notification-panel ${notif.read?'':'unread'}"><div class="header"><span class="type">${notif.type}</span><span class="time">${new Date(notif.time).toLocaleString()}</span></div><p>${notif.message}</p></div>`;
    }
}

async function exportAllData(){
    const files = ['users.json','daily_limits.json','numbers.json','test_numbers.json','sms.json','notifications.json','pending_users.json','payments.json','user_sms_costs.json','smpp_config.json','reserve_numbers.json','security_log.json','login_attempts.json','file_services.json','range_prices.json'];
    const statusDiv = document.getElementById('exportStatus');
    const filesList = document.getElementById('exportFilesList');
    statusDiv.style.display = 'block';
    filesList.innerHTML = '<p style="color:var(--muted)">⏳ Exporting...</p>';
    let exported = 0;
    let failed = [];
    for(const file of files){
        try{
            const response = await fetch(`/api/export_file?file=${file}`);
            if(response.ok){
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = file;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                exported++;
            } else {
                failed.push(file);
            }
        }catch(e){
            console.error(e);
            failed.push(file);
        }
    }
    let html = `<p style="color:var(--success)"><i class="fas fa-check-circle"></i> ${exported} files exported successfully!</p>`;
    if(failed.length > 0){
        html += `<p style="color:var(--destructive)"><i class="fas fa-times-circle"></i> Failed: ${failed.join(', ')}</p>`;
    }
    filesList.innerHTML = html;
    showToast(`${exported} files exported${failed.length > 0 ? ', ' + failed.length + ' failed' : ''}`);
}

async function importData(input){
    const file = input.files[0];
    if(!file) return;

    const formData = new FormData();
    formData.append('file', file);
    showToast("Importing data...", "info");
    try{
        const response = await fetch("/api/import_file", {
            method: "POST", 
            body: formData,
            credentials: 'include'
        });
        if(!response.ok){
            const errorText = await response.text();
            showToast("❌ Server error " + response.status + ": " + errorText.substring(0, 100), "error");
            return;
        }
        const data = await response.json();
        if(data.success){
            showToast("✅ " + data.message + " (Records: " + (data.records_count || 0) + ")", "success");
        } else {
            showToast("❌ " + (data.message || "Import error"), "error");
        }
    } catch(e) {
        showToast("❌ Network error: " + e.message, "error");
    }
    input.value = "";
}

async function testAPIs(){
    const btn = event.target;
    btn.querySelector('i').classList.add('fa-spin');
    const response = await fetch('/api/test_api_connection');
    const data = await response.json();
    const container = document.getElementById('apiTestResults');
    let html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px">';
    for(const[name,info] of Object.entries(data.apis||{})){
        const color = info.status==='connected' ? 'var(--success)' : 'var(--destructive)';
        html += `<div style="border:1px solid var(--border);border-radius:8px;padding:16px;background:var(--glass)">
            <h4 style="color:${color};margin-bottom:8px"><i class="fas fa-${info.status==='connected'?'check-circle':'times-circle'}"></i> ${name}</h4>
            <p>Status: ${info.status}</p>
            <p>Messages: ${info.count||0}</p>
            <p style="font-size:11px;color:var(--muted);margin-top:8px">Keys: ${(info.sample_keys||[]).join(', ')}</p>
        </div>`;
    }
    html += '</div>';
    container.innerHTML = html;
    btn.querySelector('i').classList.remove('fa-spin');
    showToast('APIs checked');
}

function exportTable(type){showToast('Exporting...','info');}

async function loadSmppConfig(){
    const response = await fetch('/api/owner/smpp_config');
    const data = await response.json();
    if(data.success && data.config){
        const cfg = data.config;
        document.getElementById('smppEnabled').checked = cfg.enabled || false;
        document.getElementById('smppHost').value = cfg.host || '';
        document.getElementById('smppPort').value = cfg.port || 2775;
        document.getElementById('smppSystemId').value = cfg.system_id || '';
        document.getElementById('smppSystemType').value = cfg.system_type || '';
        document.getElementById('smppSourceAddr').value = cfg.source_addr || '';
    }
}

async function saveSmppConfig(){
    const config = {
        enabled: document.getElementById('smppEnabled').checked,
        host: document.getElementById('smppHost').value,
        port: parseInt(document.getElementById('smppPort').value) || 2775,
        system_id: document.getElementById('smppSystemId').value,
        password: document.getElementById('smppPassword').value,
        system_type: document.getElementById('smppSystemType').value,
        source_addr: document.getElementById('smppSourceAddr').value
    };
    const response = await fetch('/api/owner/smpp_config', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(config)});
    const data = await response.json();
    if(data.success){showToast('SMPP settings saved');document.getElementById('smppPassword').value='';}
    else{showToast(data.message, 'error');}
}

async function testSmppConnection(){
    const btn = event.target;
    btn.querySelector('i').classList.add('fa-spin');
    btn.disabled = true;
    const response = await fetch('/api/owner/smpp_test', {method: 'POST'});
    const data = await response.json();
    const statusDiv = document.getElementById('smppStatus');
    const contentDiv = document.getElementById('smppStatusContent');
    statusDiv.style.display = 'block';
    if(data.success){contentDiv.innerHTML = `<p style="color:var(--success)"><i class="fas fa-check-circle"></i> ${data.message}</p>`;showToast(data.message);}
    else{contentDiv.innerHTML = `<p style="color:var(--destructive)"><i class="fas fa-times-circle"></i> ${data.message}</p>`;showToast(data.message, 'error');}
    btn.querySelector('i').classList.remove('fa-spin');
    btn.disabled = false;
}

async function loadSmppStatus(){
    const response = await fetch('/api/owner/smpp_status');
    const data = await response.json();
    if(data.success && data.status){
        const status = data.status;
        const statusDiv = document.getElementById('smppStatus');
        const contentDiv = document.getElementById('smppStatusContent');
        statusDiv.style.display = 'block';
        let html = `<p><strong>Enabled:</strong> ${status.enabled ? 'Active' : 'Inactive'}</p>`;
        html += `<p><strong>Connection:</strong> ${status.connected ? 'Connected' : 'Not connected'}</p>`;
        html += `<p><strong>Server:</strong> ${status.host}:${status.port}</p>`;
        html += `<p><strong>System ID:</strong> ${status.system_id}</p>`;
        contentDiv.innerHTML = html;
    }
}

async function loadUserStatistics(){
    const response=await fetch('/api/owner/user_statistics');
    const data=await response.json();
    const tbody=document.getElementById('statisticsTable');
    tbody.innerHTML='';
    if(!data.statistics || data.statistics.length===0){
        tbody.innerHTML='<tr><td colspan="9" style="text-align:center;color:var(--muted)">No data</td></tr>';
        return;
    }
    let totalNumbers=0, totalSMS=0, totalSpent=0;
    for(const stat of data.statistics){totalNumbers+=stat.total_numbers||0;totalSMS+=stat.total_sms||0;totalSpent+=stat.total_spent||0;}
    document.getElementById('statsTotalUsers').textContent=data.statistics.length;
    document.getElementById('statsTotalNumbers').textContent=totalNumbers;
    document.getElementById('statsTotalSMS').textContent=totalSMS;
    document.getElementById('statsTotalSpent').textContent=totalSpent.toFixed(2);
    for(const stat of data.statistics){
        const statusClass=stat.status==='active'?'status-active':stat.status==='pending'?'status-pending':'status-banned';
        const roleClass=stat.role==='admin'?'status-admin':stat.role==='general'?'status-general':stat.role==='legend'?'status-legend':'';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${stat.username}</td><td><span class="status-badge ${roleClass}">${stat.role}</span></td><td><span class="status-badge ${statusClass}">${stat.status}</span></td><td>${stat.limit||0}</td><td class="text-success" style="font-weight:600">${stat.total_numbers||0}</td><td>${stat.files_count||0}</td><td class="text-primary" style="font-weight:600">${stat.total_sms||0}</td><td class="text-success" style="font-weight:600">$${(stat.total_spent||0).toFixed(2)}</td><td class="text-muted">${stat.created_at?new Date(stat.created_at).toLocaleDateString():'-'}</td></tr>`;
    }
}

function exportStatistics(type){showToast('Exporting statistics...','info');}

async function loadRangeStatistics(){
    const response=await fetch('/api/owner/range_statistics');
    const data=await response.json();
    const tbody=document.getElementById('rangeStatisticsTable');
    tbody.innerHTML='';
    if(!data.ranges || data.ranges.length===0){
        tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--muted)">No data</td></tr>';
        document.getElementById('rangeTotalFiles').textContent='0';
        document.getElementById('rangeTotalSMS').textContent='0';
        document.getElementById('rangeTotalNumbers').textContent='0';
        document.getElementById('rangeTotalUsers').textContent='0';
        return;
    }
    let totalSMS=0, totalNumbers=0, totalUsers=0;
    for(const r of data.ranges){totalSMS += r.total_sms || 0;totalNumbers += r.unique_numbers || 0;totalUsers += r.active_users || 0;}
    document.getElementById('rangeTotalFiles').textContent=data.ranges.length;
    document.getElementById('rangeTotalSMS').textContent=totalSMS;
    document.getElementById('rangeTotalNumbers').textContent=totalNumbers;
    document.getElementById('rangeTotalUsers').textContent=totalUsers;
    let rank=1;
    for(const range of data.ranges){
        const lastTime = range.last_sms_time && range.last_sms_time !== '-' ? new Date(range.last_sms_time).toLocaleString() : '-';
        const maxSMS = data.ranges[0].total_sms || 1;
        const activityPercent = Math.round((range.total_sms / maxSMS) * 100);
        tbody.innerHTML+=`<tr><td style="font-weight:700;color:var(--accent)">#${rank}</td><td class="text-primary" style="font-weight:600">${range.file}</td><td class="text-success" style="font-weight:700;font-size:1.1rem">${range.total_sms}</td><td>${range.unique_numbers}</td><td>${range.active_users}</td><td class="text-muted">${lastTime}</td><td><div style="display:flex;align-items:center;gap:8px"><div style="flex:1;background:var(--secondary);border-radius:4px;height:8px;overflow:hidden"><div style="width:${activityPercent}%;background:linear-gradient(90deg,var(--accent),var(--success));height:100%;border-radius:4px;transition:width 0.5s ease"></div></div><span style="font-size:11px;font-weight:600;color:var(--accent)">${activityPercent}%</span></div></td></tr>`;
        rank++;
    }
}

function exportRangeStats(type){showToast('Exporting range statistics...','info');}

async function loadSmsCosts(){
    const response=await fetch('/api/owner/user_sms_cost');
    const data=await response.json();
    const tbody=document.getElementById('smsCostsTable');
    tbody.innerHTML='';
    if(!data.costs || data.costs.length===0){tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted)">No data</td></tr>';return;}
    for(const item of data.costs){
        const usersResponse=await fetch('/api/owner/accounts');
        const usersData=await usersResponse.json();
        const user=usersData.users?.[item.username]||{};
        const statusClass=user.status==='active'?'status-active':user.status==='pending'?'status-pending':'status-banned';
        const roleClass=user.role==='admin'?'status-admin':'';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${item.username}</td><td><span class="status-badge ${roleClass}">${user.role||'user'}</span></td><td><span class="status-badge ${statusClass}">${user.status||'active'}</span></td><td><input type="number" id="cost_${item.username}" value="${item.cost}" step="0.001" min="0" style="width:80px;padding:6px;border:1px solid var(--border);border-radius:4px;font-size:13px;background:var(--glass);color:var(--foreground)"></td><td><button class="btn btn-primary btn-sm" onclick="saveSmsCost('${item.username}')"><i class="fas fa-save"></i> Save</button></td></tr>`;
    }
}

async function saveSmsCost(username){
    const costInput=document.getElementById(`cost_${username}`);
    const cost=parseFloat(costInput.value)||0.01;
    const response=await fetch('/api/owner/user_sms_cost',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,cost})});
    const data=await response.json();
    if(data.success){showToast(`Updated SMS price for user ${username} to $${cost}`);}
    else{showToast(data.message||'Error','error');}
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
loadDashboardStats();
</script>
</body>
</html>
"""

GENERAL_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - General Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#06B6D4;--accent-purple:#8B5CF6;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#0891B2;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#ECFEFF 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .file-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#0891B2}
[data-theme="light"] .nav-item:hover{background:rgba(6,182,212,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(6,182,212,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#0C4A6E 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* ===== SIDEBAR ===== */
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(6,182,212,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#22D3EE,#A78BFA);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(6,182,212,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(6,182,212,0.2),rgba(139,92,246,0.2));color:#fff;border:1px solid rgba(6,182,212,0.3)}
.nav-item.active i{color:#22D3EE}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}
.role-badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:0.6rem;font-weight:700;margin-right:auto}
.role-general{background:linear-gradient(135deg,#06B6D4,#0891B2);color:white}

/* ===== MAIN CONTENT ===== */
.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

/* ===== HEADER ===== */
.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--accent);background:rgba(6,182,212,0.1)}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent-purple));border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

/* ===== SECTIONS ===== */
.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ===== CARDS ===== */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(6,182,212,0.3)}
.stat-card .icon{font-size:24px;margin-bottom:8px;display:block}
.stat-card .number{font-family:'Poppins',sans-serif;font-size:1.6rem;font-weight:700;margin-bottom:4px;color:var(--foreground)}
.stat-card .label{color:var(--muted);font-size:12px}

/* ===== BUTTONS ===== */
.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;box-shadow:0 4px 16px rgba(6,182,212,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(6,182,212,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(6,182,212,0.1);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--destructive);color:white}
.btn-danger:hover{background:#DC2626;transform:translateY(-2px);box-shadow:0 4px 16px rgba(239,68,68,0.3)}
.btn-success{background:var(--success);color:white}
.btn-sm{padding:6px 12px;font-size:12px}

/* ===== FORMS ===== */
.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-container:hover{border-color:rgba(6,182,212,0.2)}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,0.15)}
.file-upload{border:2px dashed var(--border);border-radius:12px;padding:32px;text-align:center;cursor:pointer;transition:all 0.3s ease;margin-bottom:16px;background:var(--glass)}
.file-upload:hover{border-color:var(--accent);background:rgba(6,182,212,0.05)}
.file-upload i{font-size:2.5rem;color:var(--accent);margin-bottom:12px}
.file-upload p{color:var(--muted);font-size:13px}

/* ===== TABLE ===== */
.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.table-controls{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);flex-wrap:wrap;gap:12px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(6,182,212,0.05)}
.text-primary{color:#22D3EE;font-weight:500}
.text-muted{color:var(--muted)}
.text-success{color:var(--success);font-weight:500}
.text-danger{color:var(--destructive);font-weight:500}

/* ===== STATUS BADGES ===== */
.status-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;display:inline-block}
.status-active{background:rgba(16,185,129,0.15);color:#34D399;border:1px solid rgba(16,185,129,0.3)}
.status-banned{background:rgba(239,68,68,0.15);color:#FCA5A5;border:1px solid rgba(239,68,68,0.3)}
.status-pending{background:rgba(245,158,11,0.15);color:#FBBF24;border:1px solid rgba(245,158,11,0.3)}

/* ===== FILE CARDS ===== */
.files-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.file-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.file-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(6,182,212,0.3)}
.file-card h4{color:#22D3EE;margin-bottom:12px;font-size:15px;display:flex;align-items:center;gap:8px}
.file-card .info{display:flex;justify-content:space-between;margin-bottom:10px;color:var(--muted);font-size:13px}
.file-card .cost{color:var(--success);font-weight:700;font-size:16px}
.reserve-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:20px;color:#A78BFA;font-size:12px;font-weight:600}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
.toast.info{border-right-color:var(--accent)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ===== FOOTER ===== */
.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}

/* ===== SECTION TITLE ===== */
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
    .header{flex-direction:column;align-items:flex-start;gap:10px;padding:12px 20px}
    .cards-grid{grid-template-columns:1fr}
    .files-grid{grid-template-columns:1fr}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>GENERAL PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Users</div>
        <button class="nav-item" onclick="showSection('usersList',this)"><i class="fas fa-users"></i> User list</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Number distribution</div>
        <button class="nav-item" onclick="showSection('distributeNumbers',this)"><i class="fas fa-share-alt"></i> Distribute numbers</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Reserve Numbers</div>
        <button class="nav-item" onclick="showSection('viewReserve',this)"><i class="fas fa-eye"></i> View reserve numbers</button>
        <button class="nav-item" onclick="showSection('addReserve',this)"><i class="fas fa-plus-circle"></i> Add reserve numbers</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Account</div>
        <button class="nav-item" onclick="showSection('myAccount',this)"><i class="fas fa-user-cog"></i> My account</button>
    </div>
</div>

<div class="main-content">
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-star" style="color:var(--accent)"></i> General Panel</h2>
            <p>Number distribution management</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar">G</div>
                <span class="user-name" id="generalUsername">General</span>
                <span class="role-badge role-general">GENERAL</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <div class="page-content">
        <!-- DASHBOARD -->
        <div class="content-section active" id="dashboard">
            <div class="cards-grid">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128101;</span><div class="number" id="totalUsers">0</div><div class="label">Total users</div></div>
                <div class="stat-card"><span class="icon" style="color:#A78BFA">&#128737;</span><div class="number" id="reserveCount">0</div><div class="label">Reserve numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128241;</span><div class="number" id="availableCount">0</div><div class="label">Available numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--warning)">&#128228;</span><div class="number" id="distributedCount">0</div><div class="label">Distributed numbers</div></div>
            </div>
        </div>

        <!-- USERS LIST -->
        <div class="content-section" id="usersList">
            <h3 class="section-title"><i class="fas fa-users"></i> User list</h3>
            <div class="table-wrapper">
                <div class="table-controls"><span style="color:var(--muted)">All regular users</span></div>
                <table>
                    <thead><tr><th>User</th><th>Status</th><th>Limit</th><th>Registration date</th></tr></thead>
                    <tbody id="usersTable"></tbody>
                </table>
            </div>
        </div>

        <!-- DISTRIBUTE NUMBERS -->
        <div class="content-section" id="distributeNumbers">
            <h3 class="section-title"><i class="fas fa-share-alt"></i> Distribute numbers to users</h3>
            <div class="form-container">
                <p style="color:var(--muted);margin-bottom:16px;font-size:13px">Select numbers from available files or reserve numbers and distribute them to a user.</p>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Select user</label><select id="distUserSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                    <div class="form-group"><label>Number source</label><select id="distSource" onchange="loadFilesForDistribution()" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"><option value="available">Available numbers</option><option value="reserve">Reserve numbers</option></select></div>
                    <div class="form-group"><label>Select file</label><select id="distFileSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                    <div class="form-group"><label>Number count</label><input type="number" id="distCount" placeholder="Example: 100" min="1" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></div>
                </div>
                <button class="btn btn-primary" onclick="distributeNumbers()" style="background:linear-gradient(135deg,#06B6D4,#8B5CF6)"><i class="fas fa-share-alt"></i> Distribute numbers</button>
            </div>
        </div>

        <!-- VIEW RESERVE -->
        <div class="content-section" id="viewReserve">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
                <h3 class="section-title" style="margin:0"><i class="fas fa-eye" style="color:#A78BFA"></i> Reserve numbers</h3>
                <span class="reserve-badge"><i class="fas fa-lock"></i> Private</span>
            </div>
            <div id="reserveFilesList"></div>
        </div>

        <!-- ADD RESERVE -->
        <div class="content-section" id="addReserve">
            <h3 class="section-title"><i class="fas fa-plus-circle" style="color:#A78BFA"></i> Add reserve numbers</h3>
            <div class="form-container" style="border-color:rgba(139,92,246,0.3)">
                <div class="file-upload" onclick="document.getElementById('reserveFile').click()" style="border-color:rgba(139,92,246,0.3)">
                    <i class="fas fa-cloud-upload-alt" style="color:#A78BFA"></i>
                    <p>Click to upload reserve numbers file (.txt)</p>
                    <input type="file" id="reserveFile" accept=".txt" style="display:none" onchange="handleReserveFileSelect(this)">
                </div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>File name</label><input type="text" id="reserveFileName" placeholder="Example: Reserve USA"></div>
                    <div class="form-group"><label>Cost per number ($)</label><input type="number" id="reserveFileCost" placeholder="0.00" step="0.01"></div>
                </div>
                <button class="btn btn-primary" onclick="addReserveNumbers()" style="background:linear-gradient(135deg,#8B5CF6,#6366F1)"><i class="fas fa-save"></i> Save reserve numbers</button>
            </div>
        </div>

        <!-- MY ACCOUNT -->
        <div class="content-section" id="myAccount">
            <h3 class="section-title"><i class="fas fa-user-cog"></i> My account</h3>
            <div class="form-container">
                <div class="form-group"><label>New password</label><input type="password" id="newPassword" placeholder="Leave blank if you don't want to change"></div>
                <div class="form-group"><label>Phone number</label><input type="tel" id="newPhone" placeholder="Phone number"></div>
                <button class="btn btn-primary" onclick="updateAccount()"><i class="fas fa-save"></i> Save</button>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
const socket=io();
let selectedReserveFile=null;

socket.on('connect',()=>{fetch('/api/user/my_account').then(r=>r.json()).then(data=>{if(data.success){document.getElementById('generalUsername').textContent=data.user.username||'General';socket.emit('join',{username:data.user.username})}})});

function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='dashboard')loadDashboardStats();
    if(sectionId==='usersList')loadUsersList();
    if(sectionId==='distributeNumbers'){loadUsersForDistribution();loadFilesForDistribution();}
    if(sectionId==='viewReserve')loadReserveFiles();
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':type==='info'?'info':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':type==='error'?'exclamation-circle':'info-circle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function loadDashboardStats(){
    const response=await fetch('/api/general/dashboard_stats');
    const data=await response.json();
    if(data.success){
        document.getElementById('totalUsers').textContent=data.total_users;
        document.getElementById('reserveCount').textContent=data.total_reserve_numbers;
        document.getElementById('availableCount').textContent=data.total_available_numbers;
        document.getElementById('distributedCount').textContent=data.total_distributed;
    }
}

async function loadUsersList(){
    const response=await fetch('/api/general/users_list');
    const data=await response.json();
    const tbody=document.getElementById('usersTable');
    tbody.innerHTML='';
    if(!data.users||data.users.length===0){tbody.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted)">No users</td></tr>';return;}
    for(const user of data.users){
        const statusClass=user.status==='active'?'status-active':'status-banned';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${user.username}</td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td>${user.limit}</td><td class="text-muted">${user.created_at?new Date(user.created_at).toLocaleDateString():'-'}</td></tr>`;
    }
}

async function loadUsersForDistribution(){
    const response=await fetch('/api/general/users_list');
    const data=await response.json();
    const select=document.getElementById('distUserSelect');
    select.innerHTML='';
    for(const user of data.users||[]){if(user.status==='active'){select.innerHTML+=`<option value="${user.username}">${user.username}</option>`}}
}

async function loadFilesForDistribution(){
    const source=document.getElementById('distSource').value;
    const response=await fetch('/api/privileged/all_files_for_distribution');
    const data=await response.json();
    const select=document.getElementById('distFileSelect');
    select.innerHTML='';
    const files=source==='reserve'?data.reserve_files:data.available_files;
    for(const[name,info]of Object.entries(files||{})){select.innerHTML+=`<option value="${name}">${name} (${info.count} numbers)</option>`}
}

async function distributeNumbers(){
    const username=document.getElementById('distUserSelect').value;
    const filename=document.getElementById('distFileSelect').value;
    const count=parseInt(document.getElementById('distCount').value)||0;
    const source=document.getElementById('distSource').value;
    if(!username){showToast('Select user','error');return}
    if(!filename){showToast('Select file','error');return}
    if(count<=0){showToast('Count must be greater than 0','error');return}
    const response=await fetch('/api/privileged/reserve_to_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,filename,count,source})});
    const data=await response.json();
    if(data.success){showToast(`Distributed ${data.count} numbers to ${username} successfully`);document.getElementById('distCount').value='';loadDashboardStats();}
    else{showToast(data.message||'Error','error');}
}

function handleReserveFileSelect(input){selectedReserveFile=input.files[0];if(selectedReserveFile)showToast('Reserve file selected: '+selectedReserveFile.name)}

async function addReserveNumbers(){
    if(!selectedReserveFile){showToast('Select reserve file first','error');return}
    const formData=new FormData();
    formData.append('file',selectedReserveFile);
    formData.append('filename',document.getElementById('reserveFileName').value);
    formData.append('cost',document.getElementById('reserveFileCost').value);
    const response=await fetch('/api/privileged/reserve_numbers',{method:'POST',body:formData});
    const data=await response.json();
    if(data.success){showToast('Added '+data.count+' reserve numbers in "'+data.filename+'"','success');selectedReserveFile=null;document.getElementById('reserveFile').value='';document.getElementById('reserveFileName').value='';document.getElementById('reserveFileCost').value='';}
    else{showToast(data.message,'error')}
}

async function loadReserveFiles(){
    const response=await fetch('/api/privileged/reserve_numbers');
    const data=await response.json();
    const container=document.getElementById('reserveFilesList');
    container.innerHTML='';
    if(Object.keys(data.files||{}).length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No reserve numbers yet</p></div>';return;}
    let html='<div class="files-grid">';
    for(const[name,info] of Object.entries(data.files||{})){
        html+=`<div class="file-card" style="border-color:rgba(139,92,246,0.3)"><h4 style="color:#A78BFA"><i class="fas fa-shield-alt"></i> ${name}</h4><div class="info"><span>Count: ${info.count} numbers</span><span>Added: ${new Date(info.added_at).toLocaleDateString()}</span></div><div class="cost">Cost: $${info.cost} per number</div><div style="margin-top:10px;font-size:12px;color:var(--muted)">Added by: ${info.added_by}</div></div>`;
    }
    html+='</div>';
    container.innerHTML=html;
}

async function updateAccount(){
    const password=document.getElementById('newPassword').value;
    const phone=document.getElementById('newPhone').value;
    const response=await fetch('/api/user/update_account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,phone})});
    const data=await response.json();
    if(data.success){showToast('Account updated');document.getElementById('newPassword').value='';}
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
loadDashboardStats();
</script>
</body>
</html>
"""

LEGEND_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - Legend Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#8B5CF6;--accent-cyan:#06B6D4;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#7C3AED;--accent-cyan:#0891B2;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#F3E8FF 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#7C3AED}
[data-theme="light"] .nav-item:hover{background:rgba(139,92,246,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(139,92,246,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#2E1065 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* ===== SIDEBAR ===== */
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(139,92,246,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#A78BFA,#C084FC);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(139,92,246,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(139,92,246,0.2),rgba(192,132,252,0.2));color:#fff;border:1px solid rgba(139,92,246,0.3)}
.nav-item.active i{color:#C084FC}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}
.role-badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:0.6rem;font-weight:700;margin-right:auto}
.role-legend{background:linear-gradient(135deg,#8B5CF6,#A855F7);color:white}

/* ===== MAIN CONTENT ===== */
.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

/* ===== HEADER ===== */
.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--accent);background:rgba(139,92,246,0.1)}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),#C084FC);border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

/* ===== SECTIONS ===== */
.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ===== CARDS ===== */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(139,92,246,0.3)}
.stat-card .icon{font-size:24px;margin-bottom:8px;display:block}
.stat-card .number{font-family:'Poppins',sans-serif;font-size:1.6rem;font-weight:700;margin-bottom:4px;color:var(--foreground)}
.stat-card .label{color:var(--muted);font-size:12px}

/* ===== BUTTONS ===== */
.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--accent),#C084FC);color:white;box-shadow:0 4px 16px rgba(139,92,246,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(139,92,246,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(139,92,246,0.1);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--destructive);color:white}
.btn-danger:hover{background:#DC2626;transform:translateY(-2px);box-shadow:0 4px 16px rgba(239,68,68,0.3)}
.btn-success{background:var(--success);color:white}
.btn-sm{padding:6px 12px;font-size:12px}

/* ===== FORMS ===== */
.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-container:hover{border-color:rgba(139,92,246,0.2)}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(139,92,246,0.15)}

/* ===== TABLE ===== */
.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.table-controls{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);flex-wrap:wrap;gap:12px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(139,92,246,0.05)}
.text-primary{color:#C084FC;font-weight:500}
.text-muted{color:var(--muted)}
.text-success{color:var(--success);font-weight:500}
.text-danger{color:var(--destructive);font-weight:500}

/* ===== STATUS BADGES ===== */
.status-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;display:inline-block}
.status-active{background:rgba(16,185,129,0.15);color:#34D399;border:1px solid rgba(16,185,129,0.3)}
.status-banned{background:rgba(239,68,68,0.15);color:#FCA5A5;border:1px solid rgba(239,68,68,0.3)}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
.toast.info{border-right-color:var(--accent)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ===== FOOTER ===== */
.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}

/* ===== SECTION TITLE ===== */
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}

.reserve-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);border-radius:20px;color:#A78BFA;font-size:12px;font-weight:600}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
    .cards-grid{grid-template-columns:1fr}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>LEGEND PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">User management</div>
        <button class="nav-item" onclick="showSection('createUser',this)"><i class="fas fa-user-plus"></i> Create user</button>
        <button class="nav-item" onclick="showSection('usersList',this)"><i class="fas fa-users"></i> User list</button>
        <button class="nav-item" onclick="showSection('manageUsers',this)"><i class="fas fa-user-shield"></i> Manage users</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Reserve Numbers</div>
        <button class="nav-item" onclick="showSection('viewReserve',this)"><i class="fas fa-eye"></i> View reserve numbers</button>
        <button class="nav-item" onclick="showSection('addReserve',this)"><i class="fas fa-plus-circle"></i> Add reserve numbers</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Account</div>
        <button class="nav-item" onclick="showSection('myAccount',this)"><i class="fas fa-user-cog"></i> My account</button>
    </div>
</div>

<div class="main-content">
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-bolt" style="color:var(--accent)"></i> Legend Panel</h2>
            <p>Direct user creation and management</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar">L</div>
                <span class="user-name" id="legendUsername">Legend</span>
                <span class="role-badge role-legend">LEGEND</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <div class="page-content">
        <!-- DASHBOARD -->
        <div class="content-section active" id="dashboard">
            <div class="cards-grid">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128101;</span><div class="number" id="totalUsers">0</div><div class="label">Total users</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#9989;</span><div class="number" id="activeUsers">0</div><div class="label">Active users</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--destructive)">&#128683;</span><div class="number" id="bannedUsers">0</div><div class="label">Banned users</div></div>
                <div class="stat-card"><span class="icon" style="color:#A78BFA">&#128737;</span><div class="number" id="reserveCount">0</div><div class="label">Reserve numbers</div></div>
            </div>
            <div class="form-container" style="text-align:center;padding:48px">
                <i class="fas fa-bolt" style="font-size:4rem;background:linear-gradient(135deg,#A78BFA,#C084FC);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:20px"></i>
                <h3 style="color:var(--accent);margin-bottom:12px">Welcome to Legend Panel</h3>
                <p style="color:var(--muted)">You can create users directly without owner approval.<br>Manage users and access reserve numbers.</p>
            </div>
        </div>

        <!-- CREATE USER -->
        <div class="content-section" id="createUser">
            <h3 class="section-title"><i class="fas fa-user-plus"></i> Create new user</h3>
            <div class="form-container">
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>Username</label><input type="text" id="newUsername" placeholder="Choose username"></div>
                    <div class="form-group"><label>Password</label><input type="password" id="newPassword" placeholder="Choose password"></div>
                    <div class="form-group"><label>Phone number</label><input type="tel" id="newPhone" placeholder="+20xxxxxxxxxx"></div>
                </div>
                <button class="btn btn-primary" onclick="createUser()" style="background:linear-gradient(135deg,#8B5CF6,#C084FC)"><i class="fas fa-plus"></i> Create account immediately</button>
                <p style="color:var(--muted);margin-top:12px;font-size:12px">The account will be created directly without owner approval.</p>
            </div>
        </div>

        <!-- USERS LIST -->
        <div class="content-section" id="usersList">
            <h3 class="section-title"><i class="fas fa-users"></i> User list</h3>
            <div class="table-wrapper">
                <div class="table-controls"><span style="color:var(--muted)">All users you can manage</span></div>
                <table>
                    <thead><tr><th>User</th><th>Status</th><th>Phone</th><th>Limit</th><th>Created by</th><th>Registration date</th></tr></thead>
                    <tbody id="usersTable"></tbody>
                </table>
            </div>
        </div>

        <!-- MANAGE USERS -->
        <div class="content-section" id="manageUsers">
            <h3 class="section-title"><i class="fas fa-user-shield"></i> Manage users</h3>
            <div class="table-wrapper">
                <div class="table-controls"><span style="color:var(--muted)">Ban or activate user accounts</span></div>
                <table>
                    <thead><tr><th>User</th><th>Status</th><th>Registration date</th><th>Actions</th></tr></thead>
                    <tbody id="manageUsersTable"></tbody>
                </table>
            </div>
        </div>

        <!-- VIEW RESERVE -->
        <div class="content-section" id="viewReserve">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
                <h3 class="section-title" style="margin:0"><i class="fas fa-eye" style="color:#A78BFA"></i> Reserve numbers</h3>
                <span class="reserve-badge"><i class="fas fa-lock"></i> Private</span>
            </div>
            <div id="reserveFilesList"></div>
        </div>

        <!-- ADD RESERVE -->
        <div class="content-section" id="addReserve">
            <h3 class="section-title"><i class="fas fa-plus-circle" style="color:#A78BFA"></i> Add reserve numbers</h3>
            <div class="form-container" style="border-color:rgba(139,92,246,0.3)">
                <div class="file-upload" onclick="document.getElementById('reserveFile').click()" style="border-color:rgba(139,92,246,0.3)">
                    <i class="fas fa-cloud-upload-alt" style="color:#A78BFA"></i>
                    <p>Click to upload reserve numbers file (.txt)</p>
                    <input type="file" id="reserveFile" accept=".txt" style="display:none" onchange="handleReserveFileSelect(this)">
                </div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:16px">
                    <div class="form-group"><label>File name</label><input type="text" id="reserveFileName" placeholder="Example: Reserve USA"></div>
                    <div class="form-group"><label>Cost per number ($)</label><input type="number" id="reserveFileCost" placeholder="0.00" step="0.01"></div>
                </div>
                <button class="btn btn-primary" onclick="addReserveNumbers()" style="background:linear-gradient(135deg,#8B5CF6,#6366F1)"><i class="fas fa-save"></i> Save reserve numbers</button>
            </div>
        </div>

        <!-- MY ACCOUNT -->
        <div class="content-section" id="myAccount">
            <h3 class="section-title"><i class="fas fa-user-cog"></i> My account</h3>
            <div class="form-container">
                <div class="form-group"><label>New password</label><input type="password" id="accNewPassword" placeholder="Leave blank if you don't want to change"></div>
                <div class="form-group"><label>Phone number</label><input type="tel" id="accNewPhone" placeholder="Phone number"></div>
                <button class="btn btn-primary" onclick="updateAccount()"><i class="fas fa-save"></i> Save</button>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
const socket=io();
let selectedReserveFile=null;

socket.on('connect',()=>{fetch('/api/user/my_account').then(r=>r.json()).then(data=>{if(data.success){document.getElementById('legendUsername').textContent=data.user.username||'Legend';socket.emit('join',{username:data.user.username})}})});

function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='dashboard')loadDashboardStats();
    if(sectionId==='usersList')loadUsersList();
    if(sectionId==='manageUsers')loadManageUsers();
    if(sectionId==='viewReserve')loadReserveFiles();
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':type==='info'?'info':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':type==='error'?'exclamation-circle':'info-circle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function loadDashboardStats(){
    const response=await fetch('/api/legend/dashboard_stats');
    const data=await response.json();
    if(data.success){
        document.getElementById('totalUsers').textContent=data.total_users;
        document.getElementById('activeUsers').textContent=data.active_users;
        document.getElementById('bannedUsers').textContent=data.banned_users;
        document.getElementById('reserveCount').textContent=data.total_reserve_numbers;
    }
}

async function createUser(){
    const username=document.getElementById('newUsername').value.trim();
    const password=document.getElementById('newPassword').value;
    const phone=document.getElementById('newPhone').value;
    if(!username||!password){showToast('Username and password required','error');return}
    const response=await fetch('/api/legend/create_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,phone})});
    const data=await response.json();
    if(data.success){
        showToast('User '+username+' created successfully!');
        document.getElementById('newUsername').value='';
        document.getElementById('newPassword').value='';
        document.getElementById('newPhone').value='';
    }else{showToast(data.message,'error');}
}

async function loadUsersList(){
    const response=await fetch('/api/legend/users_list');
    const data=await response.json();
    const tbody=document.getElementById('usersTable');
    tbody.innerHTML='';
    if(!data.users||data.users.length===0){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted)">No users</td></tr>';return;}
    for(const user of data.users){
        const statusClass=user.status==='active'?'status-active':'status-banned';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${user.username}</td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td>${user.phone||'-'}</td><td>${user.limit}</td><td class="text-muted">${user.created_by||'-'}</td><td class="text-muted">${user.created_at?new Date(user.created_at).toLocaleDateString():'-'}</td></tr>`;
    }
}

async function loadManageUsers(){
    const response=await fetch('/api/legend/users_list');
    const data=await response.json();
    const tbody=document.getElementById('manageUsersTable');
    tbody.innerHTML='';
    if(!data.users||data.users.length===0){tbody.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted)">No users</td></tr>';return;}
    for(const user of data.users){
        const statusClass=user.status==='active'?'status-active':'status-banned';
        const btnClass=user.status==='active'?'btn-danger':'btn-success';
        const btnIcon=user.status==='active'?'fa-ban':'fa-check';
        const btnText=user.status==='active'?'Ban':'Activate';
        tbody.innerHTML+=`<tr><td class="text-primary" style="font-weight:600">${user.username}</td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td class="text-muted">${user.created_at?new Date(user.created_at).toLocaleDateString():'-'}</td><td><button class="btn ${btnClass} btn-sm" onclick="toggleUserStatus('${user.username}')"><i class="fas ${btnIcon}"></i> ${btnText}</button></td></tr>`;
    }
}

async function toggleUserStatus(username){
    const response=await fetch('/api/legend/toggle_user_status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    const data=await response.json();
    if(data.success){showToast('User '+username+' is now '+data.status);loadManageUsers();loadDashboardStats();}
    else{showToast(data.message,'error');}
}

function handleReserveFileSelect(input){selectedReserveFile=input.files[0];if(selectedReserveFile)showToast('Reserve file selected: '+selectedReserveFile.name)}

async function addReserveNumbers(){
    if(!selectedReserveFile){showToast('Select reserve file first','error');return}
    const formData=new FormData();
    formData.append('file',selectedReserveFile);
    formData.append('filename',document.getElementById('reserveFileName').value);
    formData.append('cost',document.getElementById('reserveFileCost').value);
    const response=await fetch('/api/privileged/reserve_numbers',{method:'POST',body:formData});
    const data=await response.json();
    if(data.success){showToast('Added '+data.count+' reserve numbers in "'+data.filename+'"','success');selectedReserveFile=null;document.getElementById('reserveFile').value='';document.getElementById('reserveFileName').value='';document.getElementById('reserveFileCost').value='';}
    else{showToast(data.message,'error')}
}

async function loadReserveFiles(){
    const response=await fetch('/api/privileged/reserve_numbers');
    const data=await response.json();
    const container=document.getElementById('reserveFilesList');
    container.innerHTML='';
    if(Object.keys(data.files||{}).length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No reserve numbers yet</p></div>';return;}
    let html='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px">';
    for(const[name,info] of Object.entries(data.files||{})){
        html+=`<div class="form-container" style="border-color:rgba(139,92,246,0.3)"><h4 style="color:#A78BFA;margin-bottom:12px"><i class="fas fa-shield-alt"></i> ${name}</h4><div style="display:flex;justify-content:space-between;margin-bottom:10px;color:var(--muted);font-size:13px"><span>Count: ${info.count} numbers</span><span>Added: ${new Date(info.added_at).toLocaleDateString()}</span></div><div style="color:var(--success);font-weight:700;font-size:16px">Cost: $${info.cost} per number</div><div style="margin-top:10px;font-size:12px;color:var(--muted)">Added by: ${info.added_by}</div></div>`;
    }
    html+='</div>';
    container.innerHTML=html;
}

async function updateAccount(){
    const password=document.getElementById('accNewPassword').value;
    const phone=document.getElementById('accNewPhone').value;
    const response=await fetch('/api/user/update_account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,phone})});
    const data=await response.json();
    if(data.success){showToast('Account updated');document.getElementById('accNewPassword').value='';}
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
loadDashboardStats();
</script>
</body>
</html>
"""

USER_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - User Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#3B82F6;--accent-purple:#8B5CF6;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#D97706;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#FEF3C7 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#D97706}
[data-theme="light"] .nav-item:hover{background:rgba(245,158,11,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(245,158,11,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#2563EB;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#E0E7FF 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .file-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .sms-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .notification-panel{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#2563EB}
[data-theme="light"] .nav-item:hover{background:rgba(59,130,246,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(59,130,246,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#1E1B4B 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

/* ===== SIDEBAR ===== */
.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(59,130,246,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#60A5FA,#A78BFA);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(59,130,246,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(59,130,246,0.2),rgba(139,92,246,0.2));color:#fff;border:1px solid rgba(59,130,246,0.3)}
.nav-item.active i{color:#60A5FA}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}

/* ===== MAIN CONTENT ===== */
.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

/* ===== HEADER ===== */
.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--accent);background:rgba(59,130,246,0.1)}
.notification-badge{position:absolute;top:4px;right:4px;width:8px;height:8px;background-color:var(--destructive);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(1.2)}}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent-purple));border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

/* ===== SECTIONS ===== */
.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

/* ===== CARDS ===== */
.cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(59,130,246,0.3)}
.stat-card .icon{font-size:24px;margin-bottom:8px;display:block}
.stat-card .number{font-family:'Poppins',sans-serif;font-size:1.6rem;font-weight:700;margin-bottom:4px;color:var(--foreground)}
.stat-card .label{color:var(--muted);font-size:12px}

/* ===== BUTTONS ===== */
.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;box-shadow:0 4px 16px rgba(59,130,246,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(59,130,246,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(59,130,246,0.1);border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--destructive);color:white}
.btn-sm{padding:6px 12px;font-size:12px}

/* ===== FORMS ===== */
.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,0.15)}

/* ===== TABLE ===== */
.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(59,130,246,0.05)}
.text-primary{color:#60A5FA;font-weight:500}
.text-muted{color:var(--muted)}
.text-mono{font-family:'Courier New',monospace;font-weight:500;font-size:12px}
.text-success{color:var(--success);font-weight:500}

/* ===== FILE CARDS ===== */
.files-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}
.file-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:20px;transition:all 0.3s ease}
.file-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,0.2);border-color:rgba(59,130,246,0.3)}
.file-card h4{color:#60A5FA;margin-bottom:12px;font-size:15px;display:flex;align-items:center;gap:8px}
.file-card .info{display:flex;justify-content:space-between;margin-bottom:10px;color:var(--muted);font-size:13px}
.file-card .cost{color:var(--success);font-weight:700;font-size:16px}
.qty-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px}
.qty-btn{padding:10px;background:rgba(59,130,246,0.08);border:1px solid var(--border);border-radius:8px;color:#60A5FA;font-family:'Poppins',sans-serif;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s ease}
.qty-btn:hover,.qty-btn.selected{background:linear-gradient(135deg,var(--accent),var(--accent-purple));color:white;border-color:transparent;transform:scale(1.02)}

/* ===== SMS CARDS ===== */
.sms-card{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:16px;margin-bottom:12px;transition:all 0.3s ease}
.sms-card:hover{border-color:rgba(59,130,246,0.3);box-shadow:0 4px 16px rgba(59,130,246,0.1)}
.sms-card .phone{color:#60A5FA;font-weight:600;font-size:14px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.sms-card .message{color:var(--foreground);margin-bottom:10px;line-height:1.6;font-size:13px}
.sms-card .meta{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);align-items:center}
.sms-card .api-badge{background:rgba(59,130,246,0.15);color:#60A5FA;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600}
.sms-card.api-global{border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.03)}
.sms-card.api-global .phone{color:var(--warning)}

/* ===== NOTIFICATION PANEL ===== */
.notification-panel{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:16px;margin-bottom:12px;transition:all 0.2s ease}
.notification-panel.unread{border-color:var(--warning);background:rgba(245,158,11,0.05)}
.notification-panel .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.notification-panel .type{background:rgba(59,130,246,0.15);color:#60A5FA;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600}
.notification-panel .time{color:var(--muted);font-size:12px}
.notification-panel p{font-size:13px;color:var(--foreground);line-height:1.5}

/* ===== TOAST ===== */
.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
.toast.info{border-right-color:var(--accent)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ===== FOOTER ===== */
.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}

/* ===== SECTION TITLE ===== */
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
    .cards-grid{grid-template-columns:1fr}
    .qty-grid{grid-template-columns:repeat(2,1fr)}
    .files-grid{grid-template-columns:1fr}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>USER PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Numbers</div>
        <button class="nav-item" onclick="showSection('requestNumbers',this)"><i class="fas fa-plus-circle"></i> Request numbers</button>
        <button class="nav-item" onclick="showSection('myNumbers',this)"><i class="fas fa-list"></i> My Numbers</button>
        <button class="nav-item" onclick="showSection('myRange',this)"><i class="fas fa-chart-bar"></i> My Range</button>
        <button class="nav-item" onclick="showSection('myFiles',this)"><i class="fas fa-file-download"></i> My Files</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Messages</div>
        <button class="nav-item" onclick="showSection('mySMS',this)"><i class="fas fa-envelope"></i> My Messages</button>
        <button class="nav-item" onclick="showSection('latestMessages',this)"><i class="fas fa-bolt"></i> Latest messages</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Account</div>
        <button class="nav-item" onclick="showSection('notifications',this)"><i class="fas fa-bell"></i> notifications</button>
        <button class="nav-item" onclick="showSection('payments',this)"><i class="fas fa-credit-card"></i> Payments</button>
        <button class="nav-item" onclick="showSection('myAccount',this)"><i class="fas fa-user-cog"></i> My account</button>
    </div>
</div>

<div class="main-content">
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-user" style="color:var(--accent)"></i> AGENT PANEL</h2>
            <p>X PANEL</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <button class="header-icon-btn" onclick="showSection('notifications',this)" title="notifications">
                <i class="fas fa-bell"></i>
                <span class="notification-badge" id="notifBadge" style="display:none"></span>
            </button>
            <button class="header-icon-btn" title="Settings"><i class="fas fa-cog"></i></button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar" id="userAvatar">U</div>
                <span class="user-name" id="userNameDisplay">User</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <div class="page-content">
        <!-- DASHBOARD -->
        <div class="content-section active" id="dashboard">
            <div class="cards-grid">
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128241;</span><div class="number" id="totalMyNumbers">0</div><div class="label">Total My Numbers</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128172;</span><div class="number" id="totalMySMS">0</div><div class="label">Messages received</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--warning)">&#128194;</span><div class="number" id="totalMyFiles">0</div><div class="label">Files</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--success)">&#128176;</span><div class="number" id="totalSpent">0</div><div class="label">Balance ($)</div></div>
                <div class="stat-card"><span class="icon" style="color:var(--accent)">&#128202;</span><div class="number" id="dailyLimitRemaining">2000</div><div class="label">Remaining daily limit</div></div>
            </div>
        </div>

        <!-- REQUEST NUMBERS -->
        <div class="content-section" id="requestNumbers">
            <h3 class="section-title"><i class="fas fa-plus-circle"></i> Request new numbers</h3>
            <div id="availableFiles"></div>
        </div>

        <!-- MY NUMBERS -->
        <div class="content-section" id="myNumbers">
            <h3 class="section-title"><i class="fas fa-list"></i> My Numbers</h3>
            <div class="form-container" id="mnPanel">
                <div class="form-group">
                    <label>1. How many numbers</label>
                    <div class="qty-grid" id="mnQtyGrid" style="grid-template-columns:repeat(auto-fit,minmax(64px,1fr))">
                        <button type="button" class="qty-btn" onclick="mnSetQty(25,this)">25</button>
                        <button type="button" class="qty-btn" onclick="mnSetQty(50,this)">50</button>
                        <button type="button" class="qty-btn" onclick="mnSetQty(100,this)">100</button>
                        <button type="button" class="qty-btn" onclick="mnSetQty(200,this)">200</button>
                        <button type="button" class="qty-btn" onclick="mnSetQty(500,this)">500</button>
                        <button type="button" class="qty-btn selected" onclick="mnSetQty('all',this)">All</button>
                    </div>
                </div>
                <div class="form-group">
                    <label for="mnRange">2. Range</label>
                    <select id="mnRange" onchange="mnUpdateSummary()"></select>
                </div>
                <p id="mnSummary" class="text-muted" style="margin-bottom:14px;font-size:0.88rem"></p>
                <div class="form-group" style="margin-bottom:0">
                    <label>3. What do you want to do</label>
                    <div class="action-buttons" style="margin-bottom:0">
                        <button class="btn btn-primary" onclick="mnExport()"><i class="fas fa-file-export"></i> Export file txt</button>
                        <button class="btn btn-danger" onclick="mnDelete()"><i class="fas fa-trash"></i> Delete number</button>
                    </div>
                </div>
            </div>
            <div id="myNumbersList"></div>
        </div>

        <!-- MY RANGE -->
        <div class="content-section" id="myRange">
            <h3 class="section-title"><i class="fas fa-chart-bar"></i> My Range</h3>
            <div id="myRangeList"></div>
        </div>

        <!-- MY FILES -->
        <div class="content-section" id="myFiles">
            <h3 class="section-title"><i class="fas fa-file-download"></i> My Files</h3>
            <div id="myFilesList"></div>
        </div>

        <!-- MY SMS -->
        <div class="content-section" id="mySMS">
            <h3 class="section-title"><i class="fas fa-envelope"></i> My Messages</h3>
            <div class="action-buttons">
                <button class="btn btn-primary" id="refreshSMSBtn" onclick="refreshSMS()"><i class="fas fa-sync-alt"></i> Update messages</button>
            </div>
            <div class="form-container" style="padding:16px;margin-bottom:16px">
                <div style="display:flex;gap:10px;align-items:center">
                    <div style="flex:1">
                        <input type="text" id="smsSearchInput" placeholder="Search phone..." style="width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground)" onkeyup="searchSMS()">
                    </div>
                    <button class="btn btn-outline" onclick="clearSMSSearch()" style="white-space:nowrap"><i class="fas fa-times"></i> Clear</button>
                </div>
                <div id="smsSearchStats" style="margin-top:8px;font-size:12px;color:var(--muted)"></div>
            </div>
            <div id="smsDebugInfo" style="margin-bottom:16px;font-size:12px;color:var(--muted);display:none"></div>
            <div id="smsList"></div>
        </div>

        <!-- LATEST MESSAGES -->
        <div class="content-section" id="latestMessages">
            <h3 class="section-title"><i class="fas fa-bolt"></i> Latest messages</h3>
            <div class="form-container" style="padding:16px;margin-bottom:16px">
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <input type="text" id="cliSearchInput" placeholder="Service (e.g. Whatsapp)" style="flex:1;min-width:180px;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground)" onkeydown="if(event.key==='Enter')searchCli()">
                    <button class="btn btn-primary" onclick="searchCli()"><i class="fas fa-search"></i> Search cli</button>
                </div>
                <div id="cliResults" style="margin-top:12px"></div>
            </div>
            <div id="latestMessagesList"></div>
        </div>

        <!-- NOTIFICATIONS -->
        <div class="content-section" id="notifications">
            <h3 class="section-title"><i class="fas fa-bell"></i> notifications</h3>
            <div id="notificationsList"></div>
        </div>

        <!-- PAYMENTS -->
        <div class="content-section" id="payments">
            <h3 class="section-title"><i class="fas fa-credit-card"></i> Payments</h3>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Type</th><th>Details</th><th>Cost</th><th>Date</th></tr></thead>
                    <tbody id="paymentsTable"></tbody>
                </table>
            </div>
        </div>

        <!-- MY ACCOUNT -->
        <div class="content-section" id="myAccount">
            <h3 class="section-title"><i class="fas fa-user-cog"></i> Account settings</h3>
            <div class="form-container">
                <div class="form-group"><label>New password</label><input type="password" id="newPassword" placeholder="Leave blank if you don't want to change"></div>
                <div class="form-group"><label>Phone number</label><input type="tel" id="newPhone" placeholder="Phone number"></div>
                <button class="btn btn-primary" onclick="updateAccount()"><i class="fas fa-save"></i> Save</button>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.1/socket.io.js"></script>
<script>
const socket=io();
let currentUsername='',allSMSCache=[];

socket.on('connect',()=>{fetch('/api/user/my_account').then(r=>r.json()).then(data=>{if(data.success){currentUsername=data.user.username||'';document.getElementById('userAvatar').textContent=currentUsername.charAt(0).toUpperCase();document.getElementById('userNameDisplay').textContent=currentUsername;socket.emit('join',{username:currentUsername})}})});
socket.on('new_sms',(data)=>{showToast('New message from: '+data.number,'info');if(document.getElementById('mySMS').classList.contains('active')){loadMySMS()}updateNotificationBadge()});
socket.on('broadcast',(data)=>{showToast('Broadcast: '+data.message,'info');if('Notification' in window&&Notification.permission==='granted'){new Notification('X PANEL',{body:data.message})}});

function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='requestNumbers')loadAvailableFiles();
    if(sectionId==='myNumbers')loadMyNumbers();
    if(sectionId==='myRange')loadMyRange();
    if(sectionId==='myFiles')loadMyFiles();
    if(sectionId==='mySMS')loadMySMS();
    if(sectionId==='latestMessages')loadLatestMessages();
    if(sectionId==='notifications')loadNotifications();
    if(sectionId==='payments')loadPayments();
    if(sectionId==='dashboard')loadDashboardStats();
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':type==='info'?'info':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':type==='error'?'exclamation-circle':'info-circle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function loadDashboardStats(){
    const numbers=await fetch('/api/user/my_numbers').then(r=>r.json());
    const sms=await fetch('/api/user/my_sms').then(r=>r.json());
    const payments=await fetch('/api/user/payments').then(r=>r.json());
    const dailyLimit=await fetch('/api/user/daily_limit').then(r=>r.json());
    let totalNumbers=0;for(const nums of Object.values(numbers.numbers||{})){totalNumbers+=nums.length}
    let totalSMS=0;for(const msgs of Object.values(sms.sms||{})){totalSMS+=msgs.length}
    let totalSpent=0;for(const p of payments.payments||[]){if(p.type==='sms'){totalSpent+=p.cost||0}}
    document.getElementById('totalMyNumbers').textContent=totalNumbers;
    document.getElementById('totalMySMS').textContent=totalSMS;
    document.getElementById('totalMyFiles').textContent=Object.keys(numbers.numbers||{}).length;
    document.getElementById('totalSpent').textContent=totalSpent.toFixed(2);
    const remaining=dailyLimit.daily_remaining||2000;
    const limitEl=document.getElementById('dailyLimitRemaining');
    limitEl.textContent=remaining;
    if(remaining<100)limitEl.style.color='var(--destructive)';
    else if(remaining<500)limitEl.style.color='var(--warning)';
}

async function loadAvailableFiles(){
    const response=await fetch('/api/user/available_numbers');
    const data=await response.json();
    const container=document.getElementById('availableFiles');
    const files=Object.entries(data.files||{});
    if(!files.length){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No files available</p></div>';return}
    const prices=data.sms_prices||{};
    const th='padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap';
    const td='padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)';
    let html=`<div class="table-wrapper"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--glass)"><th style="${th}">Range</th><th style="${th}">Your Profit Per SMS</th><th style="${th}">Actions</th></tr></thead><tbody>`;
    for(const[name,info]of files){
        const avail=(info.numbers||[]).length;
        const take=Math.min(50,avail);
        html+=`<tr><td style="${td};font-weight:600">${lmEsc(name)} <span style="color:var(--muted);font-weight:400;font-size:11px">(${avail})</span></td><td style="${td}">$${prices[name]!=null?prices[name]:0.01}</td><td style="${td}"><button class="btn btn-primary" ${take?'':'disabled'} data-file="${lmEsc(name)}" onclick="requestNumbers(this.dataset.file,${take})"><i class="fas fa-plus-circle"></i> Request number</button></td></tr>`;
    }
    html+='</tbody></table></div>';
    container.innerHTML=html;
}

async function requestNumbers(filename,count){
    const response=await fetch('/api/user/request_numbers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename,count})});
    const data=await response.json();
    if(data.success){showToast(`Added ${data.assigned.length} numbers - Cost: $${data.cost} - Daily remaining: ${data.daily_remaining}`,'success');loadAvailableFiles();loadDashboardStats();}
    else{showToast(data.message,'error')}
}

async function loadMyNumbers(){
    const response=await fetch('/api/user/my_numbers');
    const data=await response.json();
    const container=document.getElementById('myNumbersList');
    container.innerHTML='';
    const costs=data.costs||{};
    mnFillRanges(data.numbers);

    if(!data.numbers || Object.keys(data.numbers).length===0){
        container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No numbers yet</p></div>';
        return;
    }

    for(const[filename,numbers]of Object.entries(data.numbers||{})){
        const costPerNumber=costs[filename]||0;
        const totalCost = (costPerNumber * numbers.length).toFixed(2);

        container.innerHTML+=`<div class="form-container" style="padding:0;overflow:hidden">
            <div style="padding:16px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);display:flex;align-items:center;gap:10px">
                <i class="fas fa-file-alt" style="color:var(--accent)"></i>
                <span style="font-weight:600;font-size:15px;color:var(--foreground)">${filename}</span>
                <span style="margin-right:auto;color:var(--muted);font-size:12px">${numbers.length} numbers</span>
            </div>
            <div style="overflow-x:auto">
                <table class="numbers-table" style="width:100%;border-collapse:collapse">
                    <thead>
                        <tr style="background:var(--glass)">
                            <th style="width:40px;padding:12px 16px;text-align:center">
                                <input type="checkbox" class="checkbox" onchange="toggleSelectAll('${filename}',this)" style="width:16px;height:16px;cursor:pointer;accent-color:var(--accent)">
                            </th>
                            <th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border)">Range</th>
                            <th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border)">Number</th>
                            <th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border)">My Payout</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${numbers.map((num,i)=>`<tr style="transition:background-color 0.2s ease" onmouseover="this.style.background='rgba(59,130,246,0.05)'" onmouseout="this.style.background='transparent'">
                            <td style="padding:12px 16px;text-align:center;border-bottom:1px solid var(--glass-border)">
                                <input type="checkbox" class="checkbox row-check-${filename}" value="${num}" style="width:16px;height:16px;cursor:pointer;accent-color:var(--accent)">
                            </td>
                            <td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);font-weight:500">${filename}</td>
                            <td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)" class="text-mono">${num}</td>
                            <td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--success);font-weight:600">$ ${costPerNumber.toFixed(2)}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>
            </div>
            <div style="padding:12px 20px;background:var(--glass);border-top:1px solid var(--glass-border);display:flex;justify-content:space-between;align-items:center">
                <span style="font-size:12px;color:var(--muted)">Total: ${numbers.length} numbers</span>
                <span style="font-size:13px;color:var(--success);font-weight:700">Total: $ ${totalCost}</span>
            </div>
        </div>`;
    }
}

function toggleSelectAll(filename,checkbox){
    const rows=document.querySelectorAll('.row-check-'+filename);
    rows.forEach(row=>row.checked=checkbox.checked);
}

let mnQty='all',mnData={};
function mnSetQty(q,btn){mnQty=q;document.querySelectorAll('#mnQtyGrid .qty-btn').forEach(b=>b.classList.remove('selected'));btn.classList.add('selected');mnUpdateSummary()}
function mnFillRanges(numbers){
    mnData=numbers||{};
    const sel=document.getElementById('mnRange');if(!sel)return;
    const prev=sel.value;sel.innerHTML='';
    for(const[f,n]of Object.entries(mnData)){const o=document.createElement('option');o.value=f;o.textContent=f+' ('+n.length+')';sel.appendChild(o)}
    if(prev&&mnData[prev])sel.value=prev;
    mnUpdateSummary();
}
function mnPick(){const f=document.getElementById('mnRange').value;const total=(mnData[f]||[]).length;return{f:f,total:total,n:mnQty==='all'?total:Math.min(mnQty,total)}}
function mnUpdateSummary(){const s=document.getElementById('mnSummary');if(!s)return;const p=mnPick();s.textContent=p.f?(p.n+' of '+p.total+' numbers from '+p.f):'No numbers yet'}
async function mnExport(){
    const p=mnPick();if(!p.f||!p.n){showToast('Choose a range first','error');return}
    const r=await fetch('/api/user/download_file',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:p.f,count:mnQty})});
    if(!r.ok){showToast('Export failed','error');return}
    const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=p.f+'_'+p.n+'.txt';a.click();
    showToast('Exported '+p.n+' numbers');
}
async function mnDelete(){
    const p=mnPick();if(!p.f||!p.n){showToast('Choose a range first','error');return}
    if(!confirm('Delete '+p.n+' numbers from '+p.f+'?'))return;
    const r=await fetch('/api/user/delete_my_numbers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:p.f,count:mnQty})});
    const d=await r.json();
    if(d.success){showToast('Deleted '+d.deleted+' numbers');loadMyNumbers()}else{showToast(d.message||'Delete failed','error')}
}

async function loadMyRange(){
    const response=await fetch('/api/user/my_range');
    const data=await response.json();
    const container=document.getElementById('myRangeList');
    container.innerHTML='';
    for(const[filename,count]of Object.entries(data.range||{})){container.innerHTML+=`<div class="stat-card" style="margin-bottom:12px"><span class="icon" style="color:var(--accent)">&#128194;</span><div class="number">${count}</div><div class="label">${filename}</div></div>`}
}

async function loadMyFiles(){
    const response=await fetch('/api/user/my_numbers');
    const data=await response.json();
    const container=document.getElementById('myFilesList');
    container.innerHTML='';
    for(const filename of Object.keys(data.numbers||{})){container.innerHTML+=`<div class="file-card"><h4><i class="fas fa-file-alt"></i> ${filename}</h4><button class="btn btn-primary" onclick="downloadFile('${filename}')" style="margin-top:12px"><i class="fas fa-download"></i> Download file</button></div>`}
}

async function downloadFile(filename){
    const response=await fetch('/api/user/download_file',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename})});
    if(response.ok){const blob=await response.blob();const url=window.URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename+'.txt';a.click();showToast('Downloaded')}
}

async function loadMySMS(){
    const response=await fetch('/api/user/my_sms');
    const data=await response.json();
    const container=document.getElementById('smsList');
    container.innerHTML='';
    allSMSCache=[];
    window.smsFileMap = {}; // phone -> filename mapping
    console.log('SMS Data:',data);
    if(!data.sms||Object.keys(data.sms).length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No messages</p></div>';return}

    // Get user's numbers to build phone->file mapping
    const numbersResponse = await fetch('/api/user/my_numbers');
    const numbersData = await numbersResponse.json();
    const phoneToFile = {};
    const phoneToFileNormalized = {};
    for(const[filename, nums] of Object.entries(numbersData.numbers || {})){
        if(Array.isArray(nums)){
            for(const num of nums){ 
                const cleanNum = String(num).trim();
                phoneToFile[cleanNum] = filename;
                // Also store normalized version (digits only) for flexible matching
                const normalized = cleanNum.replace(/\\D/g, '');
                if(normalized) phoneToFileNormalized[normalized] = filename;
            }
        }
    }
    window.smsFileMap = phoneToFile;
    console.log('Phone to File mapping:', phoneToFile);

    const filteredSMS={};
    for(const[phone,messages]of Object.entries(data.sms||{})){if(phone.startsWith('test_')||phone.startsWith('api_')){continue}filteredSMS[phone]=messages}

    // Build file filter dropdown options
    const fileSet = new Set();
    for(const[phone,messages]of Object.entries(filteredSMS)){
        const cleanPhone = phone.startsWith('api_') ? phone.replace('api_','').trim() : String(phone).trim();
        let fname = phoneToFile[cleanPhone];
        if(!fname) {
            const normalized = cleanPhone.replace(/\\D/g, '');
            fname = phoneToFileNormalized[normalized];
        }
        if(!fname) fname = 'Unknown';
        const rs=new Set((messages||[]).map(m=>m.range).filter(Boolean));
        if(rs.size){rs.forEach(x=>fileSet.add(x))}else{fileSet.add(fname)}
    }
    const fileOptions = Array.from(fileSet).sort();

    let tableHTML = '<div class="table-wrapper" style="margin-bottom:20px"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--glass)"><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Date</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">File Name</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Number</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Service</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Message</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Price</th></tr></thead><tbody id="smsTableBody">';

    let rowCount = 0;
    for(const[phone,messages]of Object.entries(filteredSMS)){
        if(!Array.isArray(messages))continue;
        const sortedMessages=[...messages].sort((a,b)=>new Date(b.time)-new Date(a.time));
        const isApiGlobal=phone.startsWith('api_');
        const displayPhone=isApiGlobal?phone.replace('api_','').trim():String(phone).trim();
        let fileName = phoneToFile[displayPhone];
            if(!fileName) {
                const normalizedPhone = displayPhone.replace(/\\D/g, '');
                fileName = phoneToFileNormalized[normalizedPhone];
            }
            if(!fileName) fileName = 'Unknown';
        for(const sms of sortedMessages){
            const msgText=sms.message||sms.text||sms.body||'No message';
            const apiName=sms.api||'Unknown';
            const rangeName=sms.range||fileName;
            const price=Number(sms.price||0);
            const timeStr=sms.time?new Date(sms.time).toLocaleString():'-';
            // Detect service from message
            let service = 'Other';
            const msgLower = msgText.toLowerCase();
            if(msgLower.includes('whatsapp') || msgLower.includes('واتس')) service = 'WhatsApp';
            else if(msgLower.includes('paypal') || msgLower.includes('باي بال')) service = 'PayPal';
            else if(msgLower.includes('telegram') || msgLower.includes('تلغرام')) service = 'Telegram';
            else if(msgLower.includes('facebook') || msgLower.includes('فيسبوك')) service = 'Facebook';
            else if(msgLower.includes('instagram') || msgLower.includes('انستغرام')) service = 'Instagram';
            else if(msgLower.includes('google') || msgLower.includes('جوجل')) service = 'Google';
            else if(msgLower.includes('twitter') || msgLower.includes('تويتر') || msgLower.includes('x.com')) service = 'Twitter/X';
            else if(msgLower.includes('amazon') || msgLower.includes('أمازون')) service = 'Amazon';
            else if(msgLower.includes('netflix') || msgLower.includes('نتفليكس')) service = 'Netflix';
            else if(msgLower.includes('uber') || msgLower.includes('أوبر')) service = 'Uber';
            else if(msgLower.includes('otp') || msgLower.includes('code') || msgLower.includes('كود')) service = 'OTP';

            allSMSCache.push({phone:displayPhone,message:msgText,api:apiName,time:sms.time,source:sms.source,isApiGlobal:false,fileName:rangeName,price:price,service:service});
            const serviceColor = service === 'WhatsApp' ? '#22c55e' : service === 'PayPal' ? '#003087' : service === 'Telegram' ? '#0088cc' : service === 'Google' ? '#ea4335' : service === 'Facebook' ? '#1877f2' : 'var(--accent)';
            tableHTML += `<tr data-filename="${rangeName}" data-price="${price}" style="transition:background-color 0.2s ease" onmouseover="this.style.background='rgba(59,130,246,0.05)'" onmouseout="this.style.background='transparent'"><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:12px;color:var(--muted);white-space:nowrap">${timeStr}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);font-weight:500">${rangeName}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)" class="text-mono">${displayPhone}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:12px;font-weight:600" style="color:${serviceColor}">${service}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);max-width:300px;overflow:hidden;text-overflow:ellipsis">${msgText}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--success);font-weight:600;white-space:nowrap" class="text-mono">+$${price.toFixed(2)}</td></tr>`;
            rowCount++;
        }
    }
    tableHTML += '</tbody></table></div>';

    // File filter dropdown
    let filterHTML = '<div class="form-container" style="padding:16px;margin-bottom:16px"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><label style="font-size:13px;font-weight:600;color:var(--foreground)"><i class="fas fa-filter"></i> Filter by file:</label><select id="smsFileFilter" onchange="filterSMSByFile()" style="padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);min-width:200px"><option value="ALL">All Files</option>';
    for(const fname of fileOptions){ filterHTML += `<option value="${fname}">${fname}</option>`; }
    filterHTML += '</select><span id="smsFilterCount" style="font-size:12px;color:var(--muted)"></span></div></div>';

    container.innerHTML = filterHTML + tableHTML;
    document.getElementById('smsFilterCount').textContent = `${rowCount} messages | earned $${Number(data.earned_total||0).toFixed(2)}`;
    console.log(`SMS Loaded: ${rowCount} total messages, Files: ${fileOptions.length}`);
}

function filterSMSByFile(){
    const selectedFile = document.getElementById('smsFileFilter').value;
    const rows = document.querySelectorAll('#smsTableBody tr');
    let visibleCount = 0, visibleSum = 0;
    rows.forEach(row => {
        const fileName = row.getAttribute('data-filename');
        if(selectedFile === 'ALL' || fileName === selectedFile){
            row.style.display = '';
            visibleCount++;
            visibleSum += parseFloat(row.getAttribute('data-price')||0);
        } else {
            row.style.display = 'none';
        }
    });
    document.getElementById('smsFilterCount').textContent = `${visibleCount} messages | $${visibleSum.toFixed(2)}`;
}

async function refreshSMS(){
    const btn=document.getElementById('refreshSMSBtn');
    btn.querySelector('i').classList.add('fa-spin');
    btn.disabled=true;
    const response=await fetch('/api/user/my_sms');
    const data=await response.json();
    console.log('Manual refresh - SMS data:',data);
    await loadMySMS();
    const totalMessages=Object.values(data.sms||{}).reduce((acc,arr)=>acc+(Array.isArray(arr)?arr.length:0),0);
    showToast(`Updated messages (${totalMessages} messages)`,totalMessages>0?'success':'info');
    btn.querySelector('i').classList.remove('fa-spin');
    btn.disabled=false;
}

function lmEsc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

async function loadLatestMessages(){
    const container=document.getElementById('latestMessagesList');
    let data;
    try{data=await (await fetch('/api/user/latest_messages')).json()}catch(e){return}
    const rows=data.rows||[];
    if(!rows.length){
        container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No messages yet</p></div>';
        return;
    }
    const th='padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap';
    const td='padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)';
    let html=`<div class="table-wrapper"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--glass)"><th style="${th}">Service</th><th style="${th}">Number</th><th style="${th}">Range</th><th style="${th}">Message</th></tr></thead><tbody>`;
    for(const x of rows){
        const numStyle=x.owned?';color:var(--success);font-weight:700':'';
        html+=`<tr><td style="${td};font-weight:600">${lmEsc(x.service)}</td><td style="${td}${numStyle}" class="text-mono">${lmEsc(x.number)}</td><td style="${td}">${lmEsc(x.range)}</td><td style="${td};max-width:360px;word-break:break-word">${lmEsc(x.message)}</td></tr>`;
    }
    html+='</tbody></table></div>';
    container.innerHTML=html;
}

async function searchCli(){
    const q=document.getElementById('cliSearchInput').value.trim();
    const box=document.getElementById('cliResults');
    let data;
    try{data=await (await fetch('/api/user/search_cli?service='+encodeURIComponent(q))).json()}catch(e){return}
    const res=data.results||[];
    if(!res.length){box.innerHTML='<p style="color:var(--muted);font-size:13px">No ranges found</p>';return}
    box.innerHTML='<div class="table-wrapper"><table style="width:100%;border-collapse:collapse"><thead><tr><th>Range</th><th>Service</th></tr></thead><tbody>'+res.map(x=>`<tr><td>${lmEsc(x.range)}</td><td>${lmEsc(x.service)}</td></tr>`).join('')+'</tbody></table></div>';
}

async function loadNotifications(){
    const response=await fetch('/api/user/notifications');
    const data=await response.json();
    const container=document.getElementById('notificationsList');
    container.innerHTML='';
    const notifs=data.notifications||[];
    if(notifs.length===0){container.innerHTML='<div class="form-container" style="text-align:center"><p style="color:var(--muted)">No notifications</p></div>';return}
    for(const notif of notifs.slice().reverse()){container.innerHTML+=`<div class="notification-panel ${notif.read?'':'unread'}"><div class="header"><span class="type">${notif.type}</span><span class="time">${new Date(notif.time).toLocaleString()}</span></div><p>${notif.message}</p></div>`}
    await fetch('/api/user/mark_read',{method:'POST'});
    updateNotificationBadge();
}

async function updateNotificationBadge(){
    const response=await fetch('/api/user/notifications');
    const data=await response.json();
    const unread=(data.notifications||[]).filter(n=>!n.read).length;
    const badge=document.getElementById('notifBadge');
    badge.style.display=unread>0?'block':'none';
}

async function loadPayments(){
    const response=await fetch('/api/user/payments');
    const data=await response.json();
    const tbody=document.getElementById('paymentsTable');
    tbody.innerHTML='';
    for(const payment of(data.payments||[]).slice().reverse()){
        const typeLabel=payment.type==='sms'?'SMS message':'Number purchase';
        const detail=payment.type==='sms'?`Number: ${payment.number||'-'} (File: ${payment.file||'-'})`:`File: ${payment.file||'-'} (${payment.count||0} numbers)`;
        tbody.innerHTML+=`<tr><td><span class="api-badge">${typeLabel}</span></td><td>${detail}</td><td class="text-success">$${payment.cost?.toFixed(2)||0}</td><td class="text-muted">${new Date(payment.time).toLocaleDateString()}</td></tr>`
    }
}

async function updateAccount(){
    const password=document.getElementById('newPassword').value;
    const phone=document.getElementById('newPhone').value;
    const response=await fetch('/api/user/update_account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,phone})});
    const data=await response.json();
    if(data.success){showToast('Account updated');document.getElementById('newPassword').value=''}
}

async function debugSMS(){
    const response=await fetch('/api/debug/sms_data');
    const data=await response.json();
    console.log('Debug SMS Data:',data);
    const debugDiv=document.getElementById('smsDebugInfo');
    debugDiv.style.display='block';
    debugDiv.innerHTML=`<strong>Diagnostic info:</strong><br>User: ${data.username}<br>SMS keys: ${data.all_sms_keys.join(', ')}<br>Your numbers: ${JSON.stringify(data.user_numbers)}<br>Your messages: ${JSON.stringify(data.user_sms)}`;
    showToast('Data printed to Console (F12)','info');
}

function searchSMS(){
    const query=document.getElementById('smsSearchInput').value.trim();
    const statsDiv=document.getElementById('smsSearchStats');
    if(!query){loadMySMS();statsDiv.textContent='';return}
    const filtered=allSMSCache.filter(sms=>{const phone=(sms.phone||'').toLowerCase();const message=(sms.message||'').toLowerCase();const file=(sms.fileName||'').toLowerCase();const service=(sms.service||'').toLowerCase();const q=query.toLowerCase();return phone.includes(q)||message.includes(q)||file.includes(q)||service.includes(q)});

    // Rebuild table with filtered results
    let tableHTML = '<div class="table-wrapper" style="margin-bottom:20px"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--glass)"><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Date</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">File Name</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Number</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Service</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Message</th><th style="padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap">Price</th></tr></thead><tbody>';

    for(const sms of filtered){
        const timeStr=sms.time?new Date(sms.time).toLocaleString():'-';
        const serviceColor = sms.service === 'WhatsApp' ? '#22c55e' : sms.service === 'PayPal' ? '#003087' : sms.service === 'Telegram' ? '#0088cc' : sms.service === 'Google' ? '#ea4335' : sms.service === 'Facebook' ? '#1877f2' : 'var(--accent)';
        tableHTML += `<tr style="transition:background-color 0.2s ease" onmouseover="this.style.background='rgba(59,130,246,0.05)'" onmouseout="this.style.background='transparent'"><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:12px;color:var(--muted);white-space:nowrap">${timeStr}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);font-weight:500">${sms.fileName}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground)" class="text-mono">${sms.phone}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:12px;font-weight:600;color:${serviceColor}">${sms.service}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--foreground);max-width:300px;overflow:hidden;text-overflow:ellipsis">${sms.message}</td><td style="padding:12px 16px;text-align:right;border-bottom:1px solid var(--glass-border);font-size:13px;color:var(--success);font-weight:600;white-space:nowrap" class="text-mono">+$${Number(sms.price||0).toFixed(2)}</td></tr>`;
    }
    tableHTML += '</tbody></table></div>';

    document.getElementById('smsList').innerHTML = `<div class="form-container" style="padding:16px;margin-bottom:16px"><h4 style="color:var(--accent);margin:0"><i class="fas fa-search"></i> Search results: "${query}"</h4></div>` + tableHTML;
    statsDiv.textContent=`Found ${filtered.length} messages`;
}

function clearSMSSearch(){
    document.getElementById('smsSearchInput').value='';
    document.getElementById('smsSearchStats').textContent='';
    loadMySMS();
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
loadDashboardStats();
updateNotificationBadge();
setInterval(()=>{if(document.getElementById('mySMS').classList.contains('active')){loadMySMS()}if(document.getElementById('latestMessages').classList.contains('active')){loadLatestMessages()}updateNotificationBadge()},5000);
</script>
</body>
</html>
"""

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>X PANEL - Admin Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--primary:#0F172A;--primary-light:#1E293B;--accent:#3B82F6;--accent-purple:#8B5CF6;--background:#0F172A;--foreground:#F1F5F9;--secondary:#1E293B;--border:#334155;--muted:#94A3B8;--destructive:#EF4444;--success:#10B981;--warning:#F59E0B;--glass:rgba(30,41,59,0.6);--glass-border:rgba(255,255,255,0.08);--sidebar-width:280px}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#D97706;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#FEF3C7 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#D97706}
[data-theme="light"] .nav-item:hover{background:rgba(245,158,11,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(245,158,11,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
[data-theme="light"]{--primary:#FFFFFF;--primary-light:#F8FAFC;--accent:#2563EB;--accent-purple:#7C3AED;--background:#F1F5F9;--foreground:#0F172A;--secondary:#E2E8F0;--border:#CBD5E1;--muted:#64748B;--destructive:#DC2626;--success:#059669;--warning:#D97706;--glass:rgba(255,255,255,0.85);--glass-border:rgba(0,0,0,0.08)}
[data-theme="light"] body{background:linear-gradient(135deg,#F1F5F9 0%,#E0E7FF 100%)}
[data-theme="light"] .sidebar{background:rgba(255,255,255,0.9);border-left:1px solid rgba(0,0,0,0.08)}
[data-theme="light"] .header{background:rgba(255,255,255,0.9)}
[data-theme="light"] .form-container{background:rgba(255,255,255,0.9)}
[data-theme="light"] .stat-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .table-wrapper{background:rgba(255,255,255,0.9)}
[data-theme="light"] .file-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .sms-card{background:rgba(255,255,255,0.9)}
[data-theme="light"] .notification-panel{background:rgba(255,255,255,0.9)}
[data-theme="light"] .nav-item{color:#64748B}
[data-theme="light"] .nav-item.active{color:#0F172A}
[data-theme="light"] .nav-item.active i{color:#2563EB}
[data-theme="light"] .nav-item:hover{background:rgba(59,130,246,0.1)}
[data-theme="light"] tbody tr:hover{background:rgba(59,130,246,0.05)}
[data-theme="light"] .form-group input,[data-theme="light"] .form-group select{background:#FFFFFF;color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .btn-outline{background:rgba(255,255,255,0.8);color:#0F172A;border-color:#CBD5E1}
[data-theme="light"] .toast{background:rgba(255,255,255,0.95);color:#0F172A}
[data-theme="light"] .user-avatar{color:white}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0F172A 0%,#1E1B4B 100%);color:var(--foreground);line-height:1.6;min-height:100vh}
h1,h2,h3,h4,h5,h6{font-family:'Poppins',sans-serif;font-weight:600}

.sidebar{position:fixed;right:0;top:0;width:var(--sidebar-width);height:100vh;background:var(--glass);backdrop-filter:blur(20px);border-left:1px solid var(--glass-border);padding:20px 0;overflow-y:auto;z-index:100;box-shadow:-4px 0 30px rgba(0,0,0,0.3)}
.sidebar-logo{text-align:center;margin-bottom:24px;padding:0 20px 20px;border-bottom:1px solid var(--glass-border)}
.sidebar-logo img{width:70px;height:auto;margin-bottom:8px;border-radius:10px;box-shadow:0 4px 16px rgba(245,158,11,0.3)}
.sidebar-logo h1{font-family:'Poppins',sans-serif;font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#F59E0B,#FBBF24);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sidebar-logo p{color:var(--muted);font-size:0.7rem;font-weight:500}
.nav-section{margin-top:8px;padding:0 12px}
.nav-section-title{font-size:0.65rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:8px;padding:0 10px;font-weight:700}
.nav-item{display:flex;align-items:center;padding:11px 16px;margin-bottom:4px;border-radius:10px;cursor:pointer;transition:all 0.3s ease;border:none;background:none;width:100%;text-align:right;font-family:'Inter',sans-serif;font-size:0.82rem;color:var(--muted);gap:12px}
.nav-item:hover{background:rgba(245,158,11,0.1);color:var(--foreground)}
.nav-item.active{background:linear-gradient(135deg,rgba(245,158,11,0.2),rgba(251,191,36,0.2));color:#fff;border:1px solid rgba(245,158,11,0.3)}
.nav-item.active i{color:#FBBF24}
.nav-item i{font-size:0.95rem;width:20px;text-align:center;transition:color 0.2s}
.role-badge{display:inline-block;padding:2px 8px;border-radius:8px;font-size:0.6rem;font-weight:700;margin-right:auto}
.role-admin{background:linear-gradient(135deg,#F59E0B,#D97706);color:white}

.main-content{margin-right:var(--sidebar-width);min-height:100vh;display:flex;flex-direction:column}
.page-content{flex:1;max-width:1400px;margin:0 auto;padding:24px 32px;width:100%}

.header{background:var(--glass);backdrop-filter:blur(20px);border-bottom:1px solid var(--glass-border);padding:14px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:40}
.header-left h2{font-size:20px;margin-bottom:2px;color:var(--foreground)}
.header-left p{font-size:13px;color:var(--muted)}
.header-right{display:flex;align-items:center;gap:14px}
.header-icon-btn{position:relative;background:none;border:none;cursor:pointer;color:var(--muted);transition:all 0.2s ease;padding:8px;border-radius:8px;font-size:18px}
.header-icon-btn:hover{color:var(--warning);background:rgba(245,158,11,0.1)}
.divider{width:1px;height:24px;background-color:var(--border)}
.user-profile{display:flex;align-items:center;gap:10px;cursor:pointer}
.user-avatar{width:34px;height:34px;background:linear-gradient(135deg,var(--warning),#FBBF24);border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:14px;font-weight:700}
.user-name{font-size:14px;font-weight:500}
.logout-btn{background:var(--destructive);color:#fff;border:none;padding:8px 18px;border-radius:8px;cursor:pointer;font-family:'Inter',sans-serif;font-weight:600;font-size:13px;transition:all 0.2s ease;display:inline-flex;align-items:center;gap:6px}
.logout-btn:hover{background:#DC2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}

.content-section{display:none;animation:fadeIn 0.3s ease}
.content-section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

.btn{padding:10px 18px;border-radius:8px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.3s ease;display:inline-flex;align-items:center;gap:8px;font-family:'Inter',sans-serif}
.btn-primary{background:linear-gradient(135deg,var(--warning),#FBBF24);color:#0F172A;box-shadow:0 4px 16px rgba(245,158,11,0.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(245,158,11,0.4)}
.btn-outline{background:var(--glass);color:var(--foreground);border:1px solid var(--border)}
.btn-outline:hover{background:rgba(245,158,11,0.1);border-color:var(--warning);color:var(--warning)}
.btn-danger{background:var(--destructive);color:white}
.btn-sm{padding:6px 12px;font-size:12px}

.form-container{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;padding:24px;margin-bottom:20px;transition:all 0.3s ease}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:13px;font-weight:500;color:var(--muted)}
.form-group input,.form-group select{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:10px;font-size:13px;background:var(--glass);color:var(--foreground);font-family:'Inter',sans-serif;transition:all 0.3s ease}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--warning);box-shadow:0 0 0 3px rgba(245,158,11,0.15)}

.table-wrapper{background:var(--glass);backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:12px;overflow:hidden;margin-bottom:20px}
.table-controls{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--glass);border-bottom:1px solid var(--glass-border);flex-wrap:wrap;gap:12px}
table{width:100%;border-collapse:collapse}
thead{background:var(--glass)}
th{padding:12px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--glass-border);white-space:nowrap}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid var(--glass-border);color:var(--foreground)}
tbody tr{transition:background-color 0.2s ease}
tbody tr:hover{background:rgba(245,158,11,0.05)}
.status-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;display:inline-block}
.status-active{background:rgba(16,185,129,0.15);color:#34D399;border:1px solid rgba(16,185,129,0.3)}
.status-pending{background:rgba(245,158,11,0.15);color:#FBBF24;border:1px solid rgba(245,158,11,0.3)}
.status-banned{background:rgba(239,68,68,0.15);color:#FCA5A5;border:1px solid rgba(239,68,68,0.3)}
.status-admin{background:rgba(59,130,246,0.15);color:#60A5FA;border:1px solid rgba(59,130,246,0.3)}
.text-primary{color:#FBBF24;font-weight:500}
.text-muted{color:var(--muted)}

.toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}
.toast{background:var(--glass);backdrop-filter:blur(20px);border-right:4px solid var(--success);border-radius:12px;padding:14px 18px;min-width:300px;box-shadow:0 10px 40px rgba(0,0,0,0.3);animation:toastIn 0.3s ease;font-size:13px;display:flex;align-items:center;gap:10px;color:var(--foreground)}
.toast.error{border-right-color:var(--destructive)}
@keyframes toastIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}

.footer{background:var(--glass);backdrop-filter:blur(10px);border-top:1px solid var(--glass-border);padding:16px 32px;text-align:center;font-size:12px;color:var(--muted);margin-top:auto}
.section-title{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--foreground);display:flex;align-items:center;gap:10px}
.section-title::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}

@media(max-width:768px){
    .sidebar{width:100%;transform:translateX(100%);transition:transform 0.3s ease}
    .sidebar.open{transform:translateX(0)}
    .main-content{margin-right:0}
}
</style>
<style id="xp-design">
/* ===== XP DESIGN LAYER v3 : flat surfaces, one accent, Arabic-first type ===== */
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --xp-font: 'IBM Plex Sans Arabic', 'Inter', system-ui, sans-serif;
  --xp-mono: 'JetBrains Mono', ui-monospace, monospace;
  --xp-r-sm: 8px;
  --xp-r-md: 12px;
  --xp-r-lg: 16px;

  --background: #0d1218;
  --primary: #131a22;
  --primary-light: #18212b;
  --secondary: #1d2833;
  --border: #26323f;
  --foreground: #e8edf3;
  --muted: #8896a6;
  --accent: #4f8cff;
  --accent-glow: rgba(79, 140, 255, 0.28);
  --accent-purple: #4f8cff;
  --accent-cyan: #4f8cff;
  --success: #34c38f;
  --warning: #f2b33d;
  --destructive: #f0616d;
  --glass: #131a22;
  --glass-border: #26323f;
  --xp-hover: rgba(255, 255, 255, 0.04);
  --xp-accent-soft: rgba(79, 140, 255, 0.14);
  --xp-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
}

[data-theme="light"] {
  --background: #f3f5f8;
  --primary: #ffffff;
  --primary-light: #f7f9fb;
  --secondary: #eaeef3;
  --border: #dbe2ea;
  --foreground: #121a24;
  --muted: #5d6b7c;
  --accent: #2563eb;
  --accent-glow: rgba(37, 99, 235, 0.18);
  --accent-purple: #2563eb;
  --accent-cyan: #2563eb;
  --success: #12936b;
  --warning: #b97a05;
  --destructive: #d0384a;
  --glass: #ffffff;
  --glass-border: #dbe2ea;
  --xp-hover: rgba(18, 26, 36, 0.04);
  --xp-accent-soft: rgba(37, 99, 235, 0.09);
  --xp-shadow: 0 1px 2px rgba(18, 26, 36, 0.06);
}

html body,
html[data-theme="light"] body {
  font-family: var(--xp-font);
  background: var(--background);
  color: var(--foreground);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
html body h1, html body h2, html body h3, html body h4, html body h5, html body h6 {
  font-family: var(--xp-font);
  font-weight: 600;
  letter-spacing: 0;
}
html body button, html body input, html body select, html body textarea { font-family: var(--xp-font); }
.text-mono, code, .sms-code, td.text-mono { font-family: var(--xp-mono); font-feature-settings: "tnum"; }

/* no blur, no floating orbs */
.bg-animation { display: none !important; }
html body .sidebar, html body .header, html body .form-container, html body .stat-card,
html body .table-wrapper, html body .file-card, html body .sms-card,
html body .notification-panel, html body .footer, html body .login-card, html body .loader {
  -webkit-backdrop-filter: none; backdrop-filter: none;
}

/* ---------- Sidebar ---------- */
html body .sidebar,
html[data-theme="light"] body .sidebar {
  background: var(--primary);
  border-left: 1px solid var(--border);
  box-shadow: none;
  padding: 18px 0;
}
html body .sidebar-logo { border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 16px; }
html body .sidebar-logo img { width: 56px; border-radius: var(--xp-r-md); box-shadow: none; }
html body .sidebar-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.15rem; font-weight: 700;
}
html body .sidebar-logo p { color: var(--muted); font-size: 0.72rem; }
html body .nav-section { margin-top: 14px; }
html body .nav-section-title {
  text-transform: none; letter-spacing: 0; font-size: 0.74rem; font-weight: 600;
  color: var(--muted); padding: 0 12px; margin-bottom: 6px;
}
html body .nav-item,
html[data-theme="light"] body .nav-item {
  font-family: var(--xp-font); font-size: 0.88rem; font-weight: 500;
  color: var(--muted); border: 1px solid transparent; background: transparent;
  border-radius: var(--xp-r-sm); padding: 10px 12px; margin-bottom: 2px; gap: 10px;
  position: relative; transition: background .15s, color .15s;
}
html body .nav-item i { color: var(--muted); width: 20px; }
html body .nav-item:hover,
html[data-theme="light"] body .nav-item:hover { background: var(--xp-hover); color: var(--foreground); }
html body .nav-item.active,
html[data-theme="light"] body .nav-item.active {
  background: var(--xp-accent-soft); color: var(--accent); border-color: transparent; font-weight: 600;
}
html body .nav-item.active i,
html[data-theme="light"] body .nav-item.active i { color: var(--accent); }
html body .nav-item.active::before {
  content: ''; position: absolute; right: -12px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 3px; background: var(--accent);
}

/* ---------- Header ---------- */
html body .header,
html[data-theme="light"] body .header {
  background: var(--primary); border-bottom: 1px solid var(--border); padding: 12px 28px;
}
html body .header-left h2 { font-size: 1.1rem; font-weight: 600; }
html body .header-left p { font-size: 0.82rem; color: var(--muted); }
html body .header-icon-btn { border-radius: var(--xp-r-sm); }
html body .header-icon-btn:hover { background: var(--xp-hover); color: var(--accent); }
html body .user-avatar { background: var(--xp-accent-soft); color: var(--accent); border: 1px solid var(--border); }
html[data-theme="light"] body .user-avatar { color: var(--accent); }
html body .page-content { padding: 24px 28px; }

/* ---------- Surfaces ---------- */
html body .form-container, html body .stat-card, html body .table-wrapper,
html body .file-card, html body .sms-card, html body .notification-panel,
html[data-theme="light"] body .form-container, html[data-theme="light"] body .stat-card,
html[data-theme="light"] body .table-wrapper, html[data-theme="light"] body .file-card,
html[data-theme="light"] body .sms-card, html[data-theme="light"] body .notification-panel {
  background: var(--primary);
  border: 1px solid var(--border);
  border-radius: var(--xp-r-lg);
  box-shadow: var(--xp-shadow);
}
html body .stat-card { padding: 18px 20px; transition: border-color .15s; }
html body .stat-card:hover, html body .file-card:hover { border-color: var(--accent); transform: none; box-shadow: var(--xp-shadow); }
html body .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 14px; }
html body .cards-grid { gap: 14px; }
html body .footer, html[data-theme="light"] body .footer {
  background: transparent; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;
}

/* ---------- Forms ---------- */
html body .form-group label, html body .input-group label {
  font-size: 0.84rem; font-weight: 500; color: var(--muted); margin-bottom: 6px;
}
html body .form-group input, html body .form-group select, html body .form-group textarea,
html body .input-group input,
html[data-theme="light"] body .form-group input, html[data-theme="light"] body .form-group select,
html[data-theme="light"] body .form-group textarea {
  background: var(--primary-light); color: var(--foreground);
  border: 1px solid var(--border); border-radius: var(--xp-r-md);
  padding: 11px 14px; font-size: 0.92rem; transition: border-color .15s, box-shadow .15s;
}
html body .form-group input:focus, html body .form-group select:focus, html body .form-group textarea:focus,
html body .input-group input:focus,
html[data-theme="light"] body .form-group input:focus, html[data-theme="light"] body .form-group select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
html body input::placeholder, html body textarea::placeholder { color: var(--muted); opacity: .65; }
html body .file-upload, html[data-theme="light"] body .file-upload {
  background: var(--primary-light); border: 1.5px dashed var(--border); border-radius: var(--xp-r-lg);
}
html body .file-upload:hover { border-color: var(--accent); background: var(--xp-accent-soft); }

/* ---------- Buttons ---------- */
html body .btn { font-family: var(--xp-font); font-weight: 600; border-radius: var(--xp-r-md); transition: background .15s, border-color .15s, transform .1s; }
html body .btn:active { transform: translateY(1px); }
html body .btn-primary { background: var(--accent); color: #fff; box-shadow: none; }
html body .btn-primary:hover { background: var(--accent); filter: brightness(1.1); transform: none; box-shadow: none; }
html body .btn-success { background: var(--success); color: #fff; box-shadow: none; }
html body .btn-danger { background: var(--destructive); color: #fff; box-shadow: none; }
html body .btn-warning { background: var(--warning); color: #1a1200; box-shadow: none; }
html body .btn-outline, html[data-theme="light"] body .btn-outline {
  background: transparent; color: var(--foreground); border: 1px solid var(--border);
}
html body .btn-outline:hover, html[data-theme="light"] body .btn-outline:hover {
  background: var(--xp-hover); border-color: var(--accent); color: var(--accent);
}
html body .btn-sm { border-radius: var(--xp-r-sm); }
html body .logout-btn { background: transparent; color: var(--destructive); border: 1px solid var(--border); }
html body .logout-btn:hover { background: var(--destructive); color: #fff; border-color: var(--destructive); transform: none; box-shadow: none; }
html body .qty-btn { border-radius: var(--xp-r-sm); border: 1px solid var(--border); background: var(--primary-light); color: var(--foreground); }
html body .qty-btn:hover, html body .qty-btn.active, html body .qty-btn.selected { border-color: var(--accent); background: var(--xp-accent-soft); color: var(--accent); }
html body :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* ---------- Tables ---------- */
html body .table-wrapper { overflow-x: auto; }
html body table { border-collapse: collapse; width: 100%; }
html body thead th {
  background: var(--primary-light); color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: none; letter-spacing: 0; padding: 11px 14px; border-bottom: 1px solid var(--border);
  position: sticky; top: 0;
}
html body tbody td { padding: 11px 14px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
html body tbody tr:last-child td { border-bottom: none; }
html body tbody tr:hover, html[data-theme="light"] body tbody tr:hover { background: var(--xp-hover); }

/* ---------- Badges ---------- */
html body .status-badge, html body .role-badge, html body .reserve-badge {
  border-radius: 999px; font-weight: 600; font-size: 0.74rem; padding: 3px 10px; border: 1px solid transparent;
}
html body .status-active { background: rgba(52,195,143,.14); color: var(--success); }
html body .status-pending { background: rgba(242,179,61,.14); color: var(--warning); }
html body .status-banned { background: rgba(240,97,109,.14); color: var(--destructive); }
html body .status-admin, html body .status-general, html body .status-legend { background: var(--xp-accent-soft); color: var(--accent); }
html body .role-owner, html body .role-admin, html body .role-general, html body .role-legend {
  background: var(--xp-accent-soft); color: var(--accent); border-color: var(--border);
}

/* ---------- SMS / OTP cards ---------- */
html body .sms-card { padding: 14px 16px; border-inline-start: 3px solid var(--accent); }

/* ---------- Toasts ---------- */
html body .toast, html[data-theme="light"] body .toast {
  background: var(--primary); color: var(--foreground); border: 1px solid var(--border);
  border-radius: var(--xp-r-md); box-shadow: 0 8px 24px rgba(0,0,0,.25); backdrop-filter: none;
}

/* ---------- Login ---------- */
html body .login-page { padding: 20px; }
html body .login-card, html[data-theme="light"] body .login-card {
  background: var(--primary); border: 1px solid var(--border); border-radius: 20px;
  box-shadow: 0 20px 50px rgba(0,0,0,.18); padding: 40px; max-width: 420px;
}
html body .login-logo { margin-bottom: 24px; }
html body .login-logo img { width: 84px; border-radius: 18px; box-shadow: none; margin-bottom: 14px; }
html body .login-logo h1, html[data-theme="light"] body .login-logo h1 {
  background: none; -webkit-text-fill-color: currentColor; color: var(--foreground);
  font-size: 1.7rem; font-weight: 700; margin-bottom: 4px;
}
html body .login-logo p { color: var(--muted); font-size: 0.9rem; }
html body .version-badge { background: var(--xp-accent-soft); border: none; color: var(--accent); font-size: 0.72rem; }
html body .lang-chip { border-radius: 999px; background: transparent; font-family: var(--xp-font); padding: 6px 14px; font-size: 0.82rem; }
html body .lang-chip:hover { border-color: var(--accent); color: var(--accent); box-shadow: none; }
html body .lang-chip.active { background: var(--accent); color: #fff; border-color: var(--accent); box-shadow: none; }
html body .toggle-register a { color: var(--accent); }
html body .toggle-register a:hover { color: var(--accent); }
html body .alert { border-radius: var(--xp-r-md); }
html body .loader { background: var(--background); opacity: .96; }

/* ---------- Scrollbars ---------- */
* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

/* ---------- Mobile ---------- */
@media (max-width: 900px) {
  html body .page-content { padding: 16px 14px; }
  html body .header { padding: 10px 14px; }
  html body .nav-item.active::before { display: none; }
}
@media (max-width: 480px) {
  html body .login-card { padding: 28px 20px; }
  html body .stat-card { padding: 14px 16px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}
</style>
</head>
<body>

<div class="sidebar">
    <div class="sidebar-logo">
        <img src="https://i.ibb.co/CKXS2Lcg/1000146872.png" alt="X PANEL">
        <h1>X PANEL</h1>
        <p>ADMIN PANEL</p>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">main Dashboard</div>
        <button class="nav-item active" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</button>
    </div>

    <div class="nav-section">
        <div class="nav-section-title">Accounts</div>
        <button class="nav-item" onclick="showSection('createAccount',this)"><i class="fas fa-user-plus"></i> Create account</button>
        <button class="nav-item" onclick="showSection('deleteAccount',this)"><i class="fas fa-user-times"></i> delete account</button>
        <button class="nav-item" onclick="showSection('usersList',this)"><i class="fas fa-users"></i> Users</button>
    </div>
</div>

<div class="main-content">
    <header class="header">
        <div class="header-left">
            <h2><i class="fas fa-user-shield" style="color:var(--warning)"></i> Admin Panel</h2>
            <p>User account management</p>
        </div>
        <div class="header-right">
            <button class="header-icon-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">
                <i class="fas fa-sun" id="themeIconHeader"></i>
            </button>
            <button class="header-icon-btn" title="Settings"><i class="fas fa-cog"></i></button>
            <div class="divider"></div>
            <div class="user-profile">
                <div class="user-avatar">A</div>
                <span class="user-name">Admin</span>
                <span class="role-badge role-admin">ADMIN</span>
            </div>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
        </div>
    </header>

    <div class="page-content">
        <div class="content-section active" id="dashboard">
            <div class="form-container" style="text-align:center;padding:48px">
                <i class="fas fa-user-shield" style="font-size:4rem;background:linear-gradient(135deg,#F59E0B,#FBBF24);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:20px"></i>
                <h3 style="color:var(--warning);margin-bottom:12px">Welcome to Admin Panel</h3>
                <p style="color:var(--muted)">You can create and delete user accounts and manage the system</p>
            </div>
        </div>

        <div class="content-section" id="createAccount">
            <h3 class="section-title"><i class="fas fa-user-plus"></i> Create user account</h3>
            <div class="form-container">
                <div class="form-group"><label>Username</label><input type="text" id="newUsername" placeholder="Username"></div>
                <div class="form-group"><label>Password</label><input type="password" id="newPassword" placeholder="Password"></div>
                <div class="form-group"><label>Phone number</label><input type="tel" id="newPhone" placeholder="Phone number"></div>
                <button class="btn btn-primary" onclick="createAccount()"><i class="fas fa-plus"></i> Create account</button>
            </div>
        </div>

        <div class="content-section" id="deleteAccount">
            <h3 class="section-title"><i class="fas fa-user-times"></i> delete user account</h3>
            <div class="form-container">
                <div class="form-group"><label>Select account</label><select id="deleteUserSelect" style="padding:12px 16px;background:var(--glass);border:1px solid var(--border);border-radius:10px;color:var(--foreground);width:100%"></select></div>
                <button class="btn btn-danger" onclick="deleteAccount()"><i class="fas fa-trash"></i> delete account</button>
            </div>
        </div>

        <div class="content-section" id="usersList">
            <h3 class="section-title"><i class="fas fa-users"></i> User list</h3>
            <div class="table-wrapper">
                <div class="table-controls">
                    <div class="table-show"><span>Show</span><select><option>10</option><option>25</option><option>50</option></select><span>entries</span></div>
                </div>
                <table>
                    <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Limit</th><th>Date</th></tr></thead>
                    <tbody id="usersTable"></tbody>
                </table>
            </div>
        </div>
    </div>

    <footer class="footer">
        <p>&copy; 2026 X PANEL OTP System v2.0. All rights reserved.</p>
    </footer>
</div>

<div class="toast-container" id="toastContainer"></div>

<script>
function showSection(sectionId,btn){
    document.querySelectorAll('.content-section').forEach(s=>s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    if(btn) btn.classList.add('active');
    if(sectionId==='deleteAccount')loadUsersForDelete();
    if(sectionId==='usersList')loadUsersList();
}

function showToast(message,type='success'){
    const container=document.getElementById('toastContainer');
    const toast=document.createElement('div');
    toast.className='toast '+(type==='error'?'error':'');
    toast.innerHTML=`<i class="fas fa-${type==='success'?'check-circle':'exclamation-circle'}"></i> ${message}`;
    container.appendChild(toast);
    setTimeout(()=>toast.remove(),5000);
}

async function createAccount(){
    const username=document.getElementById('newUsername').value;
    const password=document.getElementById('newPassword').value;
    const phone=document.getElementById('newPhone').value;
    const response=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,phone})});
    const data=await response.json();
    if(data.success){showToast('Account created');document.getElementById('newUsername').value='';document.getElementById('newPassword').value='';document.getElementById('newPhone').value='';}
    else{showToast(data.message,'error')}
}

async function loadUsersForDelete(){
    const response=await fetch('/api/owner/accounts');
    const data=await response.json();
    const select=document.getElementById('deleteUserSelect');
    select.innerHTML='';
    for(const username of Object.keys(data.users||{})){if(username!=='Patrickselvaa'){select.innerHTML+=`<option value="${username}">${username}</option>`}}
}

async function loadUsersList(){
    const response=await fetch('/api/owner/accounts');
    const data=await response.json();
    const tbody=document.getElementById('usersTable');
    tbody.innerHTML='';
    for(const[username,user]of Object.entries(data.users||{})){
        if(username==='Patrickselvaa')continue;
        const statusClass=user.status==='active'?'status-active':user.status==='pending'?'status-pending':'status-banned';
        const roleClass=user.role==='admin'?'status-admin':user.role==='general'?'status-general':user.role==='legend'?'status-legend':'';
        tbody.innerHTML+=`<tr><td class="text-primary">${username}</td><td><span class="status-badge ${roleClass}">${user.role}</span></td><td><span class="status-badge ${statusClass}">${user.status}</span></td><td>${user.limit||0}</td><td class="text-muted">${new Date(user.created_at).toLocaleDateString()}</td></tr>`;
    }
}

async function deleteAccount(){
    const username=document.getElementById('deleteUserSelect').value;
    if(!username)return;
    showToast('Deleted '+username);
    loadUsersForDelete();
}

function toggleTheme(){
    const html=document.documentElement;
    const current=html.getAttribute('data-theme')||'light';
    const next=current==='dark'?'light':'dark';
    html.setAttribute('data-theme',next);
    localStorage.setItem('xpanel-theme-v2',next);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=next==='dark'?'fas fa-sun':'fas fa-moon';
}
(function(){
    const saved=localStorage.getItem('xpanel-theme-v2')||'light';
    document.documentElement.setAttribute('data-theme',saved);
    const icon=document.getElementById('themeIconHeader');
    if(icon)icon.className=saved==='dark'?'fas fa-sun':'fas fa-moon';
})();

function logout(){window.location.href='/logout'}
</script>
</body>
</html>
"""


# ============================================================
# IMPORT VALIDATION HELPERS
# ============================================================

def validate_import_data(filename, data):
    """Validate imported data structure"""
    validators = {
        'users.json': lambda d: isinstance(d, dict) and all(isinstance(v, dict) for v in d.values()),
        'numbers.json': lambda d: isinstance(d, dict),
        'sms.json': lambda d: isinstance(d, dict),
        'notifications.json': lambda d: isinstance(d, dict),
        'pending_users.json': lambda d: isinstance(d, dict),
        'payments.json': lambda d: isinstance(d, dict),
        'test_numbers.json': lambda d: isinstance(d, dict),
        'daily_limits.json': lambda d: isinstance(d, dict),
        'user_sms_costs.json': lambda d: isinstance(d, dict),
        'smpp_config.json': lambda d: isinstance(d, dict),
        'reserve_numbers.json': lambda d: isinstance(d, dict),
        'security_log.json': lambda d: isinstance(d, list),
        'login_attempts.json': lambda d: isinstance(d, dict),
        'file_services.json': lambda d: isinstance(d, dict),
        'range_prices.json': lambda d: isinstance(d, dict),
    }

    validator = validators.get(filename)
    if validator and not validator(data):
        return f'Invalid data structure for {filename}'
    return None


def ensure_owner_exists():
    """Ensure owner account exists after users import"""
    users = load_data(USERS_FILE)
    if 'Patrickselvaa' not in users:
        users['Patrickselvaa'] = {
            'password': hash_password('Patrickselvaa'),
            'phone': '',
            'role': 'owner',
            'status': 'active',
            'created_at': datetime.now().isoformat(),
            'limit': 999999,
            'stats': {'numbers_added': 0, 'sms_received': 0, 'files_downloaded': 0}
        }
        save_data(USERS_FILE, users)
        print("[Import] Owner account recreated after import")


# ============================================================
# TELEGRAM BOTS CONFIGURATION
# ============================================================
OWNER_BOT_TOKEN = os.getenv('OWNER_BOT_TOKEN', '')
OWNER_CHAT_ID = os.getenv('OWNER_CHAT_ID', '')
SMS_BOT_TOKEN = os.getenv('SMS_BOT_TOKEN', '')
UPLOAD_BOT_TOKEN = os.getenv('UPLOAD_BOT_TOKEN', '')

owner_bot = None
sms_bot = None
upload_bot = None

def get_data_files_info():
    files_info = {}
    for filepath, default in [
        (USERS_FILE, {}), (DAILY_LIMITS_FILE, {}), (NUMBERS_FILE, {}),
        (TEST_NUMBERS_FILE, {}), (SMS_FILE, {}), (NOTIFICATIONS_FILE, {}),
        (PENDING_USERS_FILE, {}), (PAYMENTS_FILE, {}), (RESERVE_NUMBERS_FILE, {}),
    ]:
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            mtime = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
            files_info[os.path.basename(filepath)] = {'size': size, 'modified': mtime}
    return files_info

async def send_data_to_owner():
    global owner_bot
    if not owner_bot: return
    try:
        files_info = get_data_files_info()
        summary = "&#128202; *Data Report - X PANEL*\n\n"
        for fname, info in files_info.items():
            summary += f"&#128193; `{fname}`\n"
            summary += f"   Size: {info['size']} bytes\n"
            summary += f"   Last modified: {info['modified']}\n\n"
        await owner_bot.send_message(chat_id=OWNER_CHAT_ID, text=summary, parse_mode='MarkdownV2')
        for filepath in [USERS_FILE, NUMBERS_FILE, TEST_NUMBERS_FILE, SMS_FILE, NOTIFICATIONS_FILE, PENDING_USERS_FILE, PAYMENTS_FILE, DAILY_LIMITS_FILE, RESERVE_NUMBERS_FILE]:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    await owner_bot.send_document(chat_id=OWNER_CHAT_ID, document=f, caption=f"&#128196; {os.path.basename(filepath)}")
        print(f"[Telegram Owner Bot] Data files sent to owner at {datetime.now()}")
    except Exception as e: print(f"[Telegram Owner Bot] Error sending data: {e}")

async def send_user_approval_notification(username):
    global owner_bot
    if not owner_bot: return
    try:
        await owner_bot.send_message(chat_id=OWNER_CHAT_ID, text=f"&#9989; New user approved: {username}\n&#128197; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", parse_mode='MarkdownV2')
        await send_data_to_owner()
    except Exception as e: print(f"[Telegram Owner Bot] Error: {e}")

async def send_registration_notification(username, phone):
    global owner_bot
    if not owner_bot: return
    try:
        await owner_bot.send_message(chat_id=OWNER_CHAT_ID, text=f"&#127381; *New Registration*\n\n&#128100; User: `{username}`\n&#128241; Phone: `{phone}`\n&#128197; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", parse_mode='MarkdownV2')
        await send_data_to_owner()
    except Exception as e: print(f"[Telegram Owner Bot] Error: {e}")

async def send_data_change_notification(change_type, details):
    global owner_bot
    if not owner_bot: return
    try:
        await owner_bot.send_message(chat_id=OWNER_CHAT_ID, text=f"&#128221; *Data Change*\n\n&#128204; Type: {change_type}\n&#128203; Details: {details}\n&#128197; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", parse_mode='MarkdownV2')
        await send_data_to_owner()
    except Exception as e: print(f"[Telegram Owner Bot] Error: {e}")

async def owner_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [KeyboardButton("&#128202; Export current data")],
        [KeyboardButton("&#128229; Import data")],
        [KeyboardButton("&#128203; View users")],
        [KeyboardButton("&#128241; View numbers")],
        [KeyboardButton("&#128172; View messages")],
        [KeyboardButton("&#128276; Notifications")],
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text("Welcome to X PANEL Bot!\nChoose an action:", reply_markup=reply_markup)

async def owner_export_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("&#9203; Exporting data...")
    await send_data_to_owner()
    await update.message.reply_text("&#9989; All data files sent!")

async def owner_import_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("&#128229; Send a JSON file to import data\nSupported files: users.json, numbers.json, sms.json, etc.")
    context.user_data['waiting_for_import'] = True

async def owner_handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_data = context.user_data if context.user_data else {}
    if not user_data.get('waiting_for_import'): return
    try:
        document = update.message.document
        file_name = document.file_name
        file = await context.bot.get_file(document.file_id)
        file_path = os.path.join(DATA_DIR, file_name)
        await file.download_to_drive(file_path)
        with open(file_path, 'r', encoding='utf-8') as f: data = json.load(f)
        file_map = {
            'users.json': USERS_FILE, 'daily_limits.json': DAILY_LIMITS_FILE,
            'numbers.json': NUMBERS_FILE, 'test_numbers.json': TEST_NUMBERS_FILE,
            'sms.json': SMS_FILE, 'notifications.json': NOTIFICATIONS_FILE,
            'pending_users.json': PENDING_USERS_FILE, 'payments.json': PAYMENTS_FILE,
            'reserve_numbers.json': RESERVE_NUMBERS_FILE,
        }
        if file_name in file_map:
            save_data(file_map[file_name], data)
            await update.message.reply_text(f"&#9989; {file_name} imported successfully!")
            await send_data_change_notification("Data import", f"File {file_name} imported")
        else: await update.message.reply_text(f"&#9888;&#65039; Unknown file: {file_name}")
        context.user_data['waiting_for_import'] = False
    except Exception as e:
        await update.message.reply_text(f"&#10060; Error: {str(e)}")
        context.user_data['waiting_for_import'] = False

async def owner_show_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = load_data(USERS_FILE)
    text = "&#128101; *Users*\n\n"
    for username, user in users.items():
        status = "&#9989;" if user.get('status') == 'active' else "&#9940;"
        role = user.get('role', 'user')
        text += f"{status} `{username}` | Role: {role}\n"
    await update.message.reply_text(text, parse_mode='MarkdownV2')

async def owner_show_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    numbers = load_data(NUMBERS_FILE)
    available = numbers.get('_available', {})
    text = "&#128241; *Available Numbers*\n\n"
    for fname, info in available.items():
        count = len(info.get('numbers', []))
        cost = info.get('cost', 0)
        text += f"&#128193; `{fname}`: {count} numbers | Price: ${cost}\n"
    # Add reserve numbers info
    reserve = load_data(RESERVE_NUMBERS_FILE, {})
    if reserve:
        text += "\n&#128737; *Reserve Numbers*\n\n"
        for fname, info in reserve.items():
            count = len(info.get('numbers', []))
            cost = info.get('cost', 0)
            text += f"&#128193; `{fname}`: {count} numbers | Price: ${cost}\n"
    await update.message.reply_text(text, parse_mode='MarkdownV2')

async def owner_show_sms(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sms_data = load_data(SMS_FILE)
    total_sms = sum(len(msgs) for msgs in sms_data.values() if isinstance(msgs, dict))
    text = f"&#128172; *Total Messages*\n\n&#128202; Total users with messages: {len(sms_data)}\n&#128231; Total messages: {total_sms}"
    await update.message.reply_text(text, parse_mode='MarkdownV2')

async def owner_show_notifications(update: Update, context: ContextTypes.DEFAULT_TYPE):
    notifications = load_data(NOTIFICATIONS_FILE)
    text = "&#128276; *Notifications*\n\n"
    for user, notifs in notifications.items():
        unread = sum(1 for n in notifs if not n.get('read', False))
        text += f"&#128100; `{user}`: {len(notifs)} notifications | {unread} unread\n"
    await update.message.reply_text(text, parse_mode='MarkdownV2')

async def owner_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "📤 Export current data":
        await owner_export_data(update, context)
    elif text == "📥 Import data":
        await owner_import_data(update, context)
    elif text == "📤 Upload Data to Panel":
        await owner_upload_data(update, context)
    elif text == "👥 View users":
        await owner_show_users(update, context)
    elif text == "📱 View numbers":
        await owner_show_numbers(update, context)
    elif text == "💬 View messages":
        await owner_show_sms(update, context)
    elif text == "🔔 Notifications":
        await owner_show_notifications(update, context)
    else:
        user_data = context.user_data if context.user_data else {}
        if user_data.get('waiting_for_import'):
            await update.message.reply_text("📥 Send a JSON file to import")
        else:
            await update.message.reply_text("❓ Choose a command from the menu")

async def sms_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [KeyboardButton("&#128231; My messages")],
        [KeyboardButton("&#128241; My numbers")],
        [KeyboardButton("&#128202; My stats")],
        [KeyboardButton("&#128260; Refresh")],
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text("Welcome to X PANEL Messages Bot!\nSend your username to link:", reply_markup=reply_markup)

async def sms_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "&#128231; My messages":
        username = context.user_data.get('linked_username')
        if not username: await update.message.reply_text("&#10060; Account not linked! Send your username first."); return
        sms_data = load_data(SMS_FILE)
        user_sms = sms_data.get(username, {})
        if not user_sms: await update.message.reply_text("&#128237; No messages yet"); return
        total = 0
        for phone, messages in user_sms.items():
            if not isinstance(messages, list): continue
            for msg in messages[-10:]:
                total += 1
                time_str = msg.get('time', 'unknown')
                api = msg.get('api', 'unknown')
                msg_text = msg.get('message', 'no text')
                await update.message.reply_text(f"&#128241; *Number:* `{phone}`\n&#128231; *Message:* {msg_text}\n&#128268; *Source:* {api}\n&#128336; *Time:* {time_str}", parse_mode='MarkdownV2')
                if total >= 20: break
            if total >= 20: break
        await update.message.reply_text(f"&#9989; Displayed {total} messages")
    elif text == "&#128241; My numbers":
        username = context.user_data.get('linked_username')
        if not username: await update.message.reply_text("&#10060; Account not linked!"); return
        numbers_data = load_data(NUMBERS_FILE)
        user_numbers = numbers_data.get(username, {})
        text_msg = "&#128241; *Your Numbers*\n\n"
        for fname, nums in user_numbers.items(): text_msg += f"&#128193; `{fname}`: {len(nums)} numbers\n"
        await update.message.reply_text(text_msg, parse_mode='MarkdownV2')
    elif text == "&#128202; My stats":
        username = context.user_data.get('linked_username')
        if not username: await update.message.reply_text("&#10060; Account not linked!"); return
        users = load_data(USERS_FILE)
        user = users.get(username, {})
        sms_data = load_data(SMS_FILE)
        user_sms = sms_data.get(username, {})
        total_sms = sum(len(msgs) for msgs in user_sms.values() if isinstance(msgs, list))
        text_msg = f"&#128202; *Your Stats*\n\n&#128100; User: `{username}`\n&#128231; Total messages: {total_sms}\n&#128202; Limit: {user.get('limit', 0)}"
        await update.message.reply_text(text_msg, parse_mode='MarkdownV2')
    elif text == "&#128260; Refresh":
        await update.message.reply_text("&#128260; Refreshing..."); await update.message.reply_text("&#9989; Refreshed!")
    else:
        username = text.strip()
        users = load_data(USERS_FILE)
        if username in users:
            context.user_data['linked_username'] = username
            await update.message.reply_text(f"&#9989; Account linked: `{username}`\nYou can now use the buttons.", parse_mode='MarkdownV2')
        else: await update.message.reply_text("&#10060; Username not found! Send a valid username.")

def init_telegram_bots():
    global owner_bot, sms_bot, upload_bot
    try: 
        owner_bot = Bot(token=OWNER_BOT_TOKEN)
        sms_bot = Bot(token=SMS_BOT_TOKEN)
        upload_bot = Bot(token=UPLOAD_BOT_TOKEN)
        print("[Telegram] All bots initialized (Owner + SMS + Upload)")
    except Exception as e: print(f"[Telegram] Error initializing bots: {e}")



# ============================================================
# UPLOAD BOT FUNCTIONS
# ============================================================

async def upload_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [KeyboardButton("📤 Upload Data File")],
        [KeyboardButton("📋 Help")],
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    welcome_text = """👋 Welcome to X PANEL Upload Bot!

📤 Send me a JSON data file to upload it to the panel.
Supported files: users.json, numbers.json, sms.json, etc.

⚠️ Note: This will REPLACE the current data!"""
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)


async def upload_handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        document = update.message.document
        file_name = document.file_name

        # Validate filename
        allowed_files = [
            'users.json', 'daily_limits.json', 'numbers.json', 'test_numbers.json',
            'sms.json', 'notifications.json', 'pending_users.json', 'payments.json',
            'user_sms_costs.json', 'smpp_config.json', 'reserve_numbers.json',
            'security_log.json', 'login_attempts.json', 'file_services.json', 'range_prices.json'
        ]

        if file_name not in allowed_files:
            invalid_text = f"❌ Invalid file: `{file_name}`\n\n"
            invalid_text += "✅ Allowed files:\n" + "\n".join([f"• {f}" for f in allowed_files])
            await update.message.reply_text(invalid_text, parse_mode='Markdown')
            return

        # Download file
        await update.message.reply_text(f"⏳ Downloading {file_name}...")
        file = await context.bot.get_file(document.file_id)
        file_path = os.path.join(DATA_DIR, file_name)
        await file.download_to_drive(file_path)

        # Validate JSON
        await update.message.reply_text(f"🔍 Validating {file_name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        validation_error = validate_import_data(file_name, data)
        if validation_error:
            await update.message.reply_text(f"❌ Validation error: {validation_error}")
            return

        # Create backup
        backup_path = os.path.join(DATA_DIR, file_name + '.backup.' + datetime.now().strftime("%Y%m%d_%H%M%S"))
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                backup_data = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_data)

        # Save data
        save_data(file_path, data)

        if file_name == 'users.json':
            ensure_owner_exists()

        # Send notification to owner
        try:
            loop = asyncio.get_event_loop()
            msg = f"File {file_name} uploaded via Telegram Upload Bot"
            if loop.is_running():
                asyncio.create_task(send_data_change_notification("Telegram Upload", msg))
                asyncio.create_task(send_data_to_owner())
            else:
                loop.run_until_complete(send_data_change_notification("Telegram Upload", msg))
                loop.run_until_complete(send_data_to_owner())
        except Exception as e:
            print(f"[Telegram Upload] Notification error: {e}")

        records_count = len(data) if isinstance(data, dict) else len(data) if isinstance(data, list) else 0

        success_text = f"""✅ **Upload Successful!**

📁 File: `{file_name}`
📊 Records: {records_count}
💾 Backup created

🔄 Data has been updated in the panel."""
        await update.message.reply_text(success_text, parse_mode='Markdown')

    except json.JSONDecodeError as e:
        await update.message.reply_text(f"❌ Invalid JSON format: {str(e)}")
    except Exception as e:
        await update.message.reply_text(f"❌ Upload failed: {str(e)}")
        import traceback
        print(traceback.format_exc())


async def upload_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "📤 Upload Data File":
        help_text = """📤 Please send me a JSON file now.

Just attach the file directly in the chat.
Supported: users.json, numbers.json, sms.json, etc."""
        await update.message.reply_text(help_text)
    elif text == "📋 Help":
        help_md = """📋 **Upload Bot Help**

1. Press 📤 Upload Data File
2. Send a JSON file
3. The bot will validate and upload it

⚠️ Warning: Uploading replaces current data!
💾 Backup is created automatically."""
        await update.message.reply_text(help_md, parse_mode='Markdown')
    else:
        err_text = """❓ Please use the buttons below or send a JSON file directly.
Press 📤 Upload Data File to start."""
        await update.message.reply_text(err_text)


# ============================================================
# OWNER BOT - UPLOAD BUTTON
# ============================================================

async def owner_upload_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upload_text = """📤 **Upload Data to Panel**

You can upload data in two ways:

1️⃣ **Via this bot:**
   Send a JSON file directly in this chat

2️⃣ **Via Upload Bot:**
   Use bot with token starting with 8721...
   (Dedicated upload bot for large files)

⚠️ Note: This will REPLACE current data!
💾 Backup is created automatically."""
    await update.message.reply_text(upload_text, parse_mode='Markdown')
    context.user_data['waiting_for_import'] = True

def start_owner_bot():
    try:
        application = Application.builder().token(OWNER_BOT_TOKEN).build()
        application.add_handler(CommandHandler("start", owner_start_command))
        application.add_handler(MessageHandler(filters.Document.ALL, owner_handle_document))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, owner_text_handler))
        print("[Telegram Owner Bot] Starting...")
        application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
    except Exception as e: print(f"[Telegram Owner Bot] Error: {e}")


def start_upload_bot():
    try:
        application = Application.builder().token(UPLOAD_BOT_TOKEN).build()
        application.add_handler(CommandHandler("start", upload_start_command))
        application.add_handler(MessageHandler(filters.Document.ALL, upload_handle_document))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, upload_text_handler))
        print("[Telegram Upload Bot] Starting...")
        application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
    except Exception as e: print(f"[Telegram Upload Bot] Error: {e}")

def start_sms_bot():
    try:
        application = Application.builder().token(SMS_BOT_TOKEN).build()
        application.add_handler(CommandHandler("start", sms_start_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, sms_text_handler))
        print("[Telegram SMS Bot] Starting...")
        application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
    except Exception as e: print(f"[Telegram SMS Bot] Error: {e}")

# ============================================================
# DATA CHANGE MONITORING
# ============================================================

class DataChangeMonitor:
    def __init__(self):
        self.file_hashes = {}
        self.last_check = time.time()

    def get_file_hash(self, filepath):
        if not os.path.exists(filepath): return None
        with open(filepath, 'rb') as f: return hashlib.md5(f.read()).hexdigest()

    def check_changes(self):
        files_to_monitor = [USERS_FILE, NUMBERS_FILE, SMS_FILE, PENDING_USERS_FILE, PAYMENTS_FILE, RESERVE_NUMBERS_FILE]
        changes = []
        for filepath in files_to_monitor:
            current_hash = self.get_file_hash(filepath)
            if filepath in self.file_hashes:
                if current_hash != self.file_hashes[filepath]: changes.append(os.path.basename(filepath))
            self.file_hashes[filepath] = current_hash
        return changes

    def monitor_loop(self):
        while True:
            try:
                changes = self.check_changes()
                if changes:
                    try:
                        loop = asyncio.get_event_loop()
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    if loop.is_running():
                        asyncio.create_task(send_data_change_notification("Auto change", f"Changed in: {', '.join(changes)}"))
                        asyncio.create_task(send_data_to_owner())
                    else:
                        loop.run_until_complete(send_data_change_notification("Auto change", f"Changed in: {', '.join(changes)}"))
                        loop.run_until_complete(send_data_to_owner())
            except Exception as e: print(f"[Monitor] Error: {e}")
            time.sleep(30)

def start_data_monitor():
    monitor = DataChangeMonitor()
    thread = threading.Thread(target=monitor.monitor_loop, daemon=True)
    thread.start()
    print("[Data Monitor] Started monitoring data changes")

# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == '__main__':
    start_sms_monitoring()
    try: init_smpp_client()
    except Exception as e: print(f"[SMPP] Auto-init error: {e}")

    # Initialize telegram bots
    init_telegram_bots()

    # Start owner bot in background thread
    owner_bot_thread = threading.Thread(target=start_owner_bot, daemon=True)
    owner_bot_thread.start()

    # Start SMS bot in background thread
    sms_bot_thread = threading.Thread(target=start_sms_bot, daemon=True)
    sms_bot_thread.start()

    # Start upload bot in background thread
    upload_bot_thread = threading.Thread(target=start_upload_bot, daemon=True)
    upload_bot_thread.start()

    # Start data monitor
    start_data_monitor()
    print("""
    &#9556;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9557;
    &#9553;     X PANEL OTP SYSTEM v2.0 - STARTED      &#9553;
    &#9562;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9565;
    &#9553;  Owner Login: Patrickselvaa / Patrickselvaa         &#9553;
    &#9553;  URL: http://localhost:7860               &#9553;
    &#9553;                                           &#9553;
    &#9553;  APIs Monitoring: 3 APIs + SMPP          &#9553;
    &#9553;  SMS Check Interval: 15 seconds           &#9553;
    &#9553;  Security: Enhanced (v2.0)                &#9553;
    &#9553;  Roles: owner/admin/general/legend/user   &#9553;
    &#9556;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9552;&#9557;
    """)
    socketio.run(app, host='0.0.0.0', port=7860, debug=True, allow_unsafe_werkzeug=True)
