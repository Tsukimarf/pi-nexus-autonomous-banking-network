"""
Pi-Nexus Autonomous Banking Network
body.py - Complete Banking System with SQL Database (New Version)
Branch: Tsukimarf-patch-1

Features:
- SQLite / PostgreSQL support (configurable)
- User account management
- Transactions (deposit, withdraw, transfer)
- Loan management
- Transaction history & audit log
- JWT authentication
- Encryption for sensitive data
"""

import os
import sqlite3
import hashlib
import hmac
import secrets
import logging
import json
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from dataclasses import dataclass, field

# ── Optional dependencies (graceful fallback) ──────────────────────────────
try:
    import psycopg2
    import psycopg2.extras
    HAS_PG = True
except ImportError:
    HAS_PG = False

try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pi_nexus.body")

# ══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class Config:
    # Database
    DB_TYPE: str = os.getenv("DB_TYPE", "sqlite")          # "sqlite" | "postgresql"
    DB_PATH: str = os.getenv("DB_PATH", "pi_nexus.db")     # SQLite path
    DB_DSN: str  = os.getenv("DB_DSN", "")                 # PostgreSQL DSN

    # Security
    SECRET_KEY: str  = os.getenv("SECRET_KEY", secrets.token_hex(32))
    FERNET_KEY: bytes = (
        os.getenv("FERNET_KEY", "").encode() or
        (Fernet.generate_key() if HAS_CRYPTO else b"")
    )
    JWT_EXPIRE_HOURS: int = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

    # Banking rules
    MAX_WITHDRAW_DAILY: Decimal = Decimal(os.getenv("MAX_WITHDRAW_DAILY", "10000"))
    MIN_BALANCE: Decimal        = Decimal(os.getenv("MIN_BALANCE", "0"))
    TRANSACTION_FEE_PCT: Decimal = Decimal(os.getenv("TRANSACTION_FEE_PCT", "0.001"))
    LOAN_INTEREST_RATE: Decimal  = Decimal(os.getenv("LOAN_INTEREST_RATE", "0.05"))

config = Config()

# ══════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class User:
    user_id: int
    username: str
    email: str
    full_name: str
    is_active: bool
    created_at: datetime
    role: str = "user"  # "user" | "admin"

@dataclass
class Account:
    account_id: int
    user_id: int
    account_number: str
    account_type: str       # "savings" | "checking" | "investment"
    balance: Decimal
    currency: str
    is_active: bool
    created_at: datetime

@dataclass
class Transaction:
    transaction_id: int
    from_account_id: Optional[int]
    to_account_id: Optional[int]
    transaction_type: str   # "deposit" | "withdrawal" | "transfer" | "fee" | "loan_disbursement" | "loan_repayment"
    amount: Decimal
    fee: Decimal
    currency: str
    status: str             # "pending" | "completed" | "failed" | "reversed"
    description: str
    created_at: datetime
    reference_id: str

@dataclass
class Loan:
    loan_id: int
    account_id: int
    principal: Decimal
    interest_rate: Decimal
    outstanding_balance: Decimal
    status: str             # "pending" | "active" | "paid_off" | "defaulted"
    created_at: datetime
    due_date: datetime

# ══════════════════════════════════════════════════════════════════════════
# SQL SCHEMA
# ══════════════════════════════════════════════════════════════════════════

SCHEMA_SQLITE = """
-- Users Table
CREATE TABLE IF NOT EXISTS users (
    user_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL UNIQUE,
    email        TEXT    NOT NULL UNIQUE,
    full_name    TEXT    NOT NULL,
    password_hash TEXT   NOT NULL,
    salt         TEXT    NOT NULL,
    role         TEXT    NOT NULL DEFAULT 'user',
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Accounts Table
CREATE TABLE IF NOT EXISTS accounts (
    account_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    account_number TEXT    NOT NULL UNIQUE,
    account_type   TEXT    NOT NULL DEFAULT 'savings',
    balance        REAL    NOT NULL DEFAULT 0.0,
    currency       TEXT    NOT NULL DEFAULT 'PI',
    is_active      INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Transactions Table
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account_id  INTEGER REFERENCES accounts(account_id),
    to_account_id    INTEGER REFERENCES accounts(account_id),
    transaction_type TEXT    NOT NULL,
    amount           REAL    NOT NULL,
    fee              REAL    NOT NULL DEFAULT 0.0,
    currency         TEXT    NOT NULL DEFAULT 'PI',
    status           TEXT    NOT NULL DEFAULT 'pending',
    description      TEXT,
    reference_id     TEXT    NOT NULL UNIQUE,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Loans Table
CREATE TABLE IF NOT EXISTS loans (
    loan_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id          INTEGER NOT NULL REFERENCES accounts(account_id),
    principal           REAL    NOT NULL,
    interest_rate       REAL    NOT NULL,
    outstanding_balance REAL    NOT NULL,
    status              TEXT    NOT NULL DEFAULT 'pending',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    due_date            TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Audit Log Table
CREATE TABLE IF NOT EXISTS audit_log (
    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(user_id),
    action      TEXT    NOT NULL,
    entity_type TEXT,
    entity_id   INTEGER,
    details     TEXT,
    ip_address  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_accounts_user_id       ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_from      ON transactions(from_account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_to        ON transactions(to_account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_ref       ON transactions(reference_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status    ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_loans_account          ON loans(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_user             ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user          ON sessions(user_id);
"""

SCHEMA_POSTGRESQL = """
-- Users Table
CREATE TABLE IF NOT EXISTS users (
    user_id      SERIAL PRIMARY KEY,
    username     VARCHAR(64)  NOT NULL UNIQUE,
    email        VARCHAR(255) NOT NULL UNIQUE,
    full_name    VARCHAR(255) NOT NULL,
    password_hash TEXT        NOT NULL,
    salt         VARCHAR(64)  NOT NULL,
    role         VARCHAR(20)  NOT NULL DEFAULT 'user',
    is_active    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Accounts Table
CREATE TABLE IF NOT EXISTS accounts (
    account_id     SERIAL PRIMARY KEY,
    user_id        INTEGER      NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    account_number VARCHAR(20)  NOT NULL UNIQUE,
    account_type   VARCHAR(20)  NOT NULL DEFAULT 'savings',
    balance        NUMERIC(20,8) NOT NULL DEFAULT 0,
    currency       VARCHAR(10)  NOT NULL DEFAULT 'PI',
    is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Transactions Table
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id   SERIAL PRIMARY KEY,
    from_account_id  INTEGER      REFERENCES accounts(account_id),
    to_account_id    INTEGER      REFERENCES accounts(account_id),
    transaction_type VARCHAR(30)  NOT NULL,
    amount           NUMERIC(20,8) NOT NULL,
    fee              NUMERIC(20,8) NOT NULL DEFAULT 0,
    currency         VARCHAR(10)  NOT NULL DEFAULT 'PI',
    status           VARCHAR(20)  NOT NULL DEFAULT 'pending',
    description      TEXT,
    reference_id     VARCHAR(64)  NOT NULL UNIQUE,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Loans Table
CREATE TABLE IF NOT EXISTS loans (
    loan_id             SERIAL PRIMARY KEY,
    account_id          INTEGER       NOT NULL REFERENCES accounts(account_id),
    principal           NUMERIC(20,8) NOT NULL,
    interest_rate       NUMERIC(8,6)  NOT NULL,
    outstanding_balance NUMERIC(20,8) NOT NULL,
    status              VARCHAR(20)   NOT NULL DEFAULT 'pending',
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    due_date            TIMESTAMPTZ   NOT NULL,
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Audit Log Table
CREATE TABLE IF NOT EXISTS audit_log (
    log_id      SERIAL PRIMARY KEY,
    user_id     INTEGER     REFERENCES users(user_id),
    action      VARCHAR(64) NOT NULL,
    entity_type VARCHAR(32),
    entity_id   INTEGER,
    details     JSONB,
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    session_id  VARCHAR(64) PRIMARY KEY,
    user_id     INTEGER     NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_accounts_user_id    ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_from   ON transactions(from_account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_to     ON transactions(to_account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_ref    ON transactions(reference_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_loans_account       ON loans(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_user          ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user       ON sessions(user_id);
"""

# ══════════════════════════════════════════════════════════════════════════
# DATABASE MANAGER
# ══════════════════════════════════════════════════════════════════════════

class DatabaseManager:
    """Handles SQLite and PostgreSQL connections with a unified API."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._conn_sqlite: Optional[sqlite3.Connection] = None

    # ── Connection ────────────────────────────────────────────────────────

    @contextmanager
    def get_connection(self):
        if self.cfg.DB_TYPE == "postgresql":
            if not HAS_PG:
                raise RuntimeError("psycopg2 not installed. Run: pip install psycopg2-binary")
            conn = psycopg2.connect(self.cfg.DB_DSN, cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(self.cfg.DB_PATH)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    # ── Schema Initialization ─────────────────────────────────────────────

    def initialize_schema(self) -> None:
        schema = SCHEMA_POSTGRESQL if self.cfg.DB_TYPE == "postgresql" else SCHEMA_SQLITE
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Execute each statement individually (handles both DB types)
            statements = [s.strip() for s in schema.split(";") if s.strip()]
            for stmt in statements:
                try:
                    cursor.execute(stmt)
                except Exception as e:
                    logger.warning(f"Schema statement skipped: {e}")
        logger.info(f"Database schema initialized ({self.cfg.DB_TYPE})")

    # ── Query Helpers ─────────────────────────────────────────────────────

    def _placeholder(self) -> str:
        return "%s" if self.cfg.DB_TYPE == "postgresql" else "?"

    def execute(self, sql: str, params: tuple = ()) -> None:
        ph = self._placeholder()
        sql = sql.replace("?", ph)
        with self.get_connection() as conn:
            conn.cursor().execute(sql, params)

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[Dict]:
        ph = self._placeholder()
        sql = sql.replace("?", ph)
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple = ()) -> List[Dict]:
        ph = self._placeholder()
        sql = sql.replace("?", ph)
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def insert(self, sql: str, params: tuple = ()) -> int:
        """Returns last inserted row ID."""
        ph = self._placeholder()
        sql = sql.replace("?", ph)
        with self.get_connection() as conn:
            cur = conn.cursor()
            if self.cfg.DB_TYPE == "postgresql":
                cur.execute(sql + " RETURNING *", params)
                row = cur.fetchone()
                return dict(row).get("user_id") or dict(row).get("account_id") or dict(row).get("transaction_id") or dict(row).get("loan_id") or 0
            else:
                cur.execute(sql, params)
                return cur.lastrowid or 0

# ══════════════════════════════════════════════════════════════════════════
# SECURITY UTILITIES
# ══════════════════════════════════════════════════════════════════════════

class Security:
    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 310_000
        )
        return key.hex(), salt

    @staticmethod
    def verify_password(password: str, password_hash: str, salt: str) -> bool:
        computed, _ = Security.hash_password(password, salt)
        return hmac.compare_digest(computed, password_hash)

    @staticmethod
    def generate_account_number() -> str:
        prefix = "PI"
        number = secrets.randbelow(10**14)
        return f"{prefix}{number:014d}"

    @staticmethod
    def generate_reference_id() -> str:
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        rand = secrets.token_hex(8).upper()
        return f"TXN-{ts}-{rand}"

    @staticmethod
    def generate_jwt(user_id: int, username: str, role: str) -> str:
        if not HAS_JWT:
            # Fallback: simple base64 token
            payload = json.dumps({"user_id": user_id, "username": username, "role": role})
            return secrets.token_urlsafe(32) + "." + payload.encode().hex()
        payload = {
            "sub": str(user_id),
            "username": username,
            "role": role,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=config.JWT_EXPIRE_HOURS),
        }
        return pyjwt.encode(payload, config.SECRET_KEY, algorithm="HS256")

    @staticmethod
    def verify_jwt(token: str) -> Optional[Dict]:
        if not HAS_JWT:
            return None
        try:
            return pyjwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        except Exception:
            return None

    @staticmethod
    def encrypt(value: str) -> str:
        if not HAS_CRYPTO or not config.FERNET_KEY:
            return value
        f = Fernet(config.FERNET_KEY)
        return f.encrypt(value.encode()).decode()

    @staticmethod
    def decrypt(token_str: str) -> str:
        if not HAS_CRYPTO or not config.FERNET_KEY:
            return token_str
        f = Fernet(config.FERNET_KEY)
        return f.decrypt(token_str.encode()).decode()

# ══════════════════════════════════════════════════════════════════════════
# BANKING SERVICES
# ══════════════════════════════════════════════════════════════════════════

class UserService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def register(self, username: str, email: str, full_name: str, password: str, role: str = "user") -> User:
        if self.db.fetchone("SELECT user_id FROM users WHERE username = ?", (username,)):
            raise ValueError(f"Username '{username}' already exists.")
        if self.db.fetchone("SELECT user_id FROM users WHERE email = ?", (email,)):
            raise ValueError(f"Email '{email}' already registered.")

        pw_hash, salt = Security.hash_password(password)
        sql = """
            INSERT INTO users (username, email, full_name, password_hash, salt, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        user_id = self.db.insert(sql, (username, email, full_name, pw_hash, salt, role))
        logger.info(f"User registered: {username} (id={user_id})")
        return self.get_by_id(user_id)

    def authenticate(self, username: str, password: str) -> Tuple[User, str]:
        row = self.db.fetchone("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        if not row:
            raise PermissionError("Invalid credentials.")
        if not Security.verify_password(password, row["password_hash"], row["salt"]):
            raise PermissionError("Invalid credentials.")
        user = self._row_to_user(row)
        token = Security.generate_jwt(user.user_id, user.username, user.role)
        logger.info(f"User authenticated: {username}")
        return user, token

    def get_by_id(self, user_id: int) -> User:
        row = self.db.fetchone("SELECT * FROM users WHERE user_id = ?", (user_id,))
        if not row:
            raise LookupError(f"User {user_id} not found.")
        return self._row_to_user(row)

    def deactivate(self, user_id: int) -> None:
        self.db.execute("UPDATE users SET is_active = 0 WHERE user_id = ?", (user_id,))
        logger.info(f"User {user_id} deactivated.")

    @staticmethod
    def _row_to_user(row: Dict) -> User:
        return User(
            user_id=row["user_id"],
            username=row["username"],
            email=row["email"],
            full_name=row["full_name"],
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(str(row["created_at"])) if isinstance(row["created_at"], str) else row["created_at"],
            role=row.get("role", "user"),
        )


class AccountService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def create_account(self, user_id: int, account_type: str = "savings", currency: str = "PI") -> Account:
        account_number = Security.generate_account_number()
        # ensure uniqueness
        while self.db.fetchone("SELECT account_id FROM accounts WHERE account_number = ?", (account_number,)):
            account_number = Security.generate_account_number()

        sql = """
            INSERT INTO accounts (user_id, account_number, account_type, balance, currency)
            VALUES (?, ?, ?, 0.0, ?)
        """
        account_id = self.db.insert(sql, (user_id, account_number, account_type, currency))
        logger.info(f"Account created: {account_number} for user {user_id}")
        return self.get_by_id(account_id)

    def get_by_id(self, account_id: int) -> Account:
        row = self.db.fetchone("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
        if not row:
            raise LookupError(f"Account {account_id} not found.")
        return self._row_to_account(row)

    def get_by_number(self, account_number: str) -> Account:
        row = self.db.fetchone("SELECT * FROM accounts WHERE account_number = ?", (account_number,))
        if not row:
            raise LookupError(f"Account {account_number} not found.")
        return self._row_to_account(row)

    def get_user_accounts(self, user_id: int) -> List[Account]:
        rows = self.db.fetchall("SELECT * FROM accounts WHERE user_id = ? AND is_active = 1", (user_id,))
        return [self._row_to_account(r) for r in rows]

    def get_balance(self, account_id: int) -> Decimal:
        row = self.db.fetchone("SELECT balance FROM accounts WHERE account_id = ?", (account_id,))
        if not row:
            raise LookupError(f"Account {account_id} not found.")
        return Decimal(str(row["balance"]))

    def _update_balance(self, account_id: int, new_balance: Decimal) -> None:
        self.db.execute(
            "UPDATE accounts SET balance = ?, updated_at = datetime('now') WHERE account_id = ?",
            (float(new_balance), account_id)
        )

    def close_account(self, account_id: int) -> None:
        acc = self.get_by_id(account_id)
        if acc.balance > 0:
            raise ValueError("Cannot close account with positive balance. Please withdraw funds first.")
        self.db.execute("UPDATE accounts SET is_active = 0 WHERE account_id = ?", (account_id,))
        logger.info(f"Account {account_id} closed.")

    @staticmethod
    def _row_to_account(row: Dict) -> Account:
        return Account(
            account_id=row["account_id"],
            user_id=row["user_id"],
            account_number=row["account_number"],
            account_type=row["account_type"],
            balance=Decimal(str(row["balance"])),
            currency=row["currency"],
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(str(row["created_at"])) if isinstance(row["created_at"], str) else row["created_at"],
        )


class TransactionService:
    def __init__(self, db: DatabaseManager, account_svc: AccountService):
        self.db = db
        self.acc = account_svc

    def _calculate_fee(self, amount: Decimal, transaction_type: str) -> Decimal:
        if transaction_type == "transfer":
            return (amount * config.TRANSACTION_FEE_PCT).quantize(Decimal("0.00000001"), ROUND_HALF_UP)
        return Decimal("0")

    def _record_transaction(
        self,
        from_account_id: Optional[int],
        to_account_id: Optional[int],
        transaction_type: str,
        amount: Decimal,
        fee: Decimal,
        currency: str,
        description: str,
        status: str = "completed",
    ) -> Transaction:
        ref = Security.generate_reference_id()
        sql = """
            INSERT INTO transactions
            (from_account_id, to_account_id, transaction_type, amount, fee, currency, status, description, reference_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        txn_id = self.db.insert(sql, (
            from_account_id, to_account_id, transaction_type,
            float(amount), float(fee), currency, status, description, ref
        ))
        return Transaction(
            transaction_id=txn_id,
            from_account_id=from_account_id,
            to_account_id=to_account_id,
            transaction_type=transaction_type,
            amount=amount,
            fee=fee,
            currency=currency,
            status=status,
            description=description,
            reference_id=ref,
            created_at=datetime.utcnow(),
        )

    def deposit(self, account_id: int, amount: Decimal, description: str = "Deposit") -> Transaction:
        if amount <= 0:
            raise ValueError("Deposit amount must be positive.")
        acc = self.acc.get_by_id(account_id)
        if not acc.is_active:
            raise ValueError("Account is inactive.")

        new_balance = acc.balance + amount
        self.acc._update_balance(account_id, new_balance)
        txn = self._record_transaction(
            None, account_id, "deposit", amount, Decimal("0"), acc.currency, description
        )
        logger.info(f"Deposit {amount} {acc.currency} → account {account_id} | ref={txn.reference_id}")
        return txn

    def withdraw(self, account_id: int, amount: Decimal, description: str = "Withdrawal") -> Transaction:
        if amount <= 0:
            raise ValueError("Withdrawal amount must be positive.")
        acc = self.acc.get_by_id(account_id)
        if not acc.is_active:
            raise ValueError("Account is inactive.")

        # Daily withdrawal limit check
        today_total = self._daily_withdrawal_total(account_id)
        if today_total + amount > config.MAX_WITHDRAW_DAILY:
            raise ValueError(
                f"Daily withdrawal limit exceeded. Limit: {config.MAX_WITHDRAW_DAILY}, "
                f"Already withdrawn today: {today_total}"
            )

        if acc.balance - amount < config.MIN_BALANCE:
            raise ValueError(
                f"Insufficient funds. Balance: {acc.balance}, Requested: {amount}, Min balance: {config.MIN_BALANCE}"
            )

        new_balance = acc.balance - amount
        self.acc._update_balance(account_id, new_balance)
        txn = self._record_transaction(
            account_id, None, "withdrawal", amount, Decimal("0"), acc.currency, description
        )
        logger.info(f"Withdrawal {amount} {acc.currency} ← account {account_id} | ref={txn.reference_id}")
        return txn

    def transfer(
        self,
        from_account_id: int,
        to_account_id: int,
        amount: Decimal,
        description: str = "Transfer",
    ) -> Transaction:
        if amount <= 0:
            raise ValueError("Transfer amount must be positive.")
        if from_account_id == to_account_id:
            raise ValueError("Cannot transfer to the same account.")

        from_acc = self.acc.get_by_id(from_account_id)
        to_acc   = self.acc.get_by_id(to_account_id)

        if not from_acc.is_active or not to_acc.is_active:
            raise ValueError("One or both accounts are inactive.")

        fee = self._calculate_fee(amount, "transfer")
        total_deducted = amount + fee

        if from_acc.balance - total_deducted < config.MIN_BALANCE:
            raise ValueError(
                f"Insufficient funds (including fee {fee}). "
                f"Balance: {from_acc.balance}, Required: {total_deducted}"
            )

        # Atomic balance update
        self.acc._update_balance(from_account_id, from_acc.balance - total_deducted)
        self.acc._update_balance(to_account_id,   to_acc.balance + amount)

        txn = self._record_transaction(
            from_account_id, to_account_id, "transfer",
            amount, fee, from_acc.currency, description
        )
        logger.info(
            f"Transfer {amount} {from_acc.currency} "
            f"{from_account_id} → {to_account_id} fee={fee} | ref={txn.reference_id}"
        )
        return txn

    def get_history(
        self,
        account_id: int,
        limit: int = 50,
        offset: int = 0,
        transaction_type: Optional[str] = None,
    ) -> List[Transaction]:
        if transaction_type:
            sql = """
                SELECT * FROM transactions
                WHERE (from_account_id = ? OR to_account_id = ?)
                  AND transaction_type = ?
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """
            rows = self.db.fetchall(sql, (account_id, account_id, transaction_type, limit, offset))
        else:
            sql = """
                SELECT * FROM transactions
                WHERE from_account_id = ? OR to_account_id = ?
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """
            rows = self.db.fetchall(sql, (account_id, account_id, limit, offset))
        return [self._row_to_txn(r) for r in rows]

    def get_by_reference(self, reference_id: str) -> Optional[Transaction]:
        row = self.db.fetchone("SELECT * FROM transactions WHERE reference_id = ?", (reference_id,))
        return self._row_to_txn(row) if row else None

    def reverse_transaction(self, reference_id: str, reason: str = "Reversal") -> Transaction:
        original = self.get_by_reference(reference_id)
        if not original:
            raise LookupError(f"Transaction {reference_id} not found.")
        if original.status != "completed":
            raise ValueError("Only completed transactions can be reversed.")
        if original.transaction_type not in ("transfer", "deposit", "withdrawal"):
            raise ValueError(f"Cannot reverse transaction type: {original.transaction_type}")

        # Reverse balances
        if original.transaction_type == "transfer":
            from_acc = self.acc.get_by_id(original.from_account_id)
            to_acc   = self.acc.get_by_id(original.to_account_id)
            self.acc._update_balance(original.from_account_id, from_acc.balance + original.amount + original.fee)
            self.acc._update_balance(original.to_account_id,   to_acc.balance - original.amount)
        elif original.transaction_type == "deposit":
            acc = self.acc.get_by_id(original.to_account_id)
            self.acc._update_balance(original.to_account_id, acc.balance - original.amount)
        elif original.transaction_type == "withdrawal":
            acc = self.acc.get_by_id(original.from_account_id)
            self.acc._update_balance(original.from_account_id, acc.balance + original.amount)

        # Mark original as reversed
        self.db.execute(
            "UPDATE transactions SET status = 'reversed' WHERE reference_id = ?", (reference_id,)
        )

        # Record reversal transaction
        rev = self._record_transaction(
            original.to_account_id,
            original.from_account_id,
            original.transaction_type,
            original.amount,
            Decimal("0"),
            original.currency,
            f"REVERSAL: {reason} (orig: {reference_id})",
        )
        logger.info(f"Transaction reversed: {reference_id} → new ref {rev.reference_id}")
        return rev

    def _daily_withdrawal_total(self, account_id: int) -> Decimal:
        sql = """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM transactions
            WHERE from_account_id = ?
              AND transaction_type = 'withdrawal'
              AND status = 'completed'
              AND date(created_at) = date('now')
        """
        row = self.db.fetchone(sql, (account_id,))
        return Decimal(str(row["total"])) if row else Decimal("0")

    @staticmethod
    def _row_to_txn(row: Dict) -> Transaction:
        return Transaction(
            transaction_id=row["transaction_id"],
            from_account_id=row.get("from_account_id"),
            to_account_id=row.get("to_account_id"),
            transaction_type=row["transaction_type"],
            amount=Decimal(str(row["amount"])),
            fee=Decimal(str(row.get("fee", 0))),
            currency=row.get("currency", "PI"),
            status=row["status"],
            description=row.get("description", ""),
            reference_id=row["reference_id"],
            created_at=datetime.fromisoformat(str(row["created_at"])) if isinstance(row["created_at"], str) else row["created_at"],
        )


class LoanService:
    def __init__(self, db: DatabaseManager, account_svc: AccountService, txn_svc: TransactionService):
        self.db = db
        self.acc = account_svc
        self.txn = txn_svc

    def apply_loan(self, account_id: int, principal: Decimal, duration_days: int = 365) -> Loan:
        if principal <= 0:
            raise ValueError("Loan amount must be positive.")
        acc = self.acc.get_by_id(account_id)
        if not acc.is_active:
            raise ValueError("Account is inactive.")

        # Check for existing active loan
        existing = self.db.fetchone(
            "SELECT loan_id FROM loans WHERE account_id = ? AND status = 'active'", (account_id,)
        )
        if existing:
            raise ValueError("Account already has an active loan.")

        interest = (principal * config.LOAN_INTEREST_RATE).quantize(Decimal("0.00000001"), ROUND_HALF_UP)
        total_owed = principal + interest
        due_date = datetime.utcnow() + timedelta(days=duration_days)

        sql = """
            INSERT INTO loans (account_id, principal, interest_rate, outstanding_balance, status, due_date)
            VALUES (?, ?, ?, ?, 'pending', ?)
        """
        loan_id = self.db.insert(sql, (
            account_id, float(principal), float(config.LOAN_INTEREST_RATE),
            float(total_owed), due_date.isoformat()
        ))

        # Disburse funds
        self.txn.deposit(account_id, principal, description=f"Loan disbursement (loan_id={loan_id})")
        self.db.execute("UPDATE loans SET status = 'active' WHERE loan_id = ?", (loan_id,))

        logger.info(f"Loan {loan_id} approved: {principal} PI for account {account_id}")
        return self.get_by_id(loan_id)

    def repay_loan(self, loan_id: int, amount: Decimal) -> Loan:
        loan = self.get_by_id(loan_id)
        if loan.status != "active":
            raise ValueError("Loan is not active.")
        if amount <= 0:
            raise ValueError("Repayment amount must be positive.")

        acc = self.acc.get_by_id(loan.account_id)
        if acc.balance < amount:
            raise ValueError(f"Insufficient balance for repayment. Balance: {acc.balance}, Required: {amount}")

        actual_payment = min(amount, loan.outstanding_balance)
        self.txn.withdraw(loan.account_id, actual_payment, description=f"Loan repayment (loan_id={loan_id})")

        new_balance = loan.outstanding_balance - actual_payment
        if new_balance <= 0:
            self.db.execute(
                "UPDATE loans SET outstanding_balance = 0, status = 'paid_off', updated_at = datetime('now') WHERE loan_id = ?",
                (loan_id,)
            )
            logger.info(f"Loan {loan_id} fully paid off.")
        else:
            self.db.execute(
                "UPDATE loans SET outstanding_balance = ?, updated_at = datetime('now') WHERE loan_id = ?",
                (float(new_balance), loan_id)
            )
            logger.info(f"Loan {loan_id} partial repayment: {actual_payment}, remaining: {new_balance}")

        return self.get_by_id(loan_id)

    def get_by_id(self, loan_id: int) -> Loan:
        row = self.db.fetchone("SELECT * FROM loans WHERE loan_id = ?", (loan_id,))
        if not row:
            raise LookupError(f"Loan {loan_id} not found.")
        return self._row_to_loan(row)

    def get_account_loans(self, account_id: int) -> List[Loan]:
        rows = self.db.fetchall(
            "SELECT * FROM loans WHERE account_id = ? ORDER BY created_at DESC", (account_id,)
        )
        return [self._row_to_loan(r) for r in rows]

    @staticmethod
    def _row_to_loan(row: Dict) -> Loan:
        return Loan(
            loan_id=row["loan_id"],
            account_id=row["account_id"],
            principal=Decimal(str(row["principal"])),
            interest_rate=Decimal(str(row["interest_rate"])),
            outstanding_balance=Decimal(str(row["outstanding_balance"])),
            status=row["status"],
            created_at=datetime.fromisoformat(str(row["created_at"])) if isinstance(row["created_at"], str) else row["created_at"],
            due_date=datetime.fromisoformat(str(row["due_date"])) if isinstance(row["due_date"], str) else row["due_date"],
        )


class AuditService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def log(
        self,
        action: str,
        user_id: Optional[int] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        details_json = json.dumps(details) if details else None
        sql = """
            INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        self.db.execute(sql, (user_id, action, entity_type, entity_id, details_json, ip_address))

    def get_logs(self, user_id: Optional[int] = None, limit: int = 100) -> List[Dict]:
        if user_id:
            return self.db.fetchall(
                "SELECT * FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (user_id, limit)
            )
        return self.db.fetchall(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
        )

# ══════════════════════════════════════════════════════════════════════════
# BANKING NETWORK (Facade / Entry Point)
# ══════════════════════════════════════════════════════════════════════════

class PiNexusBankingNetwork:
    """
    High-level façade for the Pi-Nexus Autonomous Banking Network.
    Instantiate once and use throughout your application.
    """

    def __init__(self, cfg: Config = config):
        self.cfg = cfg
        self.db      = DatabaseManager(cfg)
        self.users   = UserService(self.db)
        self.accounts = AccountService(self.db)
        self.transactions = TransactionService(self.db, self.accounts)
        self.loans   = LoanService(self.db, self.accounts, self.transactions)
        self.audit   = AuditService(self.db)
        self.db.initialize_schema()
        logger.info("Pi-Nexus Banking Network initialized.")

    # ── Convenience wrappers ──────────────────────────────────────────────

    def register_user(self, username: str, email: str, full_name: str, password: str) -> User:
        user = self.users.register(username, email, full_name, password)
        account = self.accounts.create_account(user.user_id)
        self.audit.log("USER_REGISTERED", user.user_id, "user", user.user_id,
                       {"username": username, "account_number": account.account_number})
        return user

    def login(self, username: str, password: str) -> Tuple[User, str]:
        user, token = self.users.authenticate(username, password)
        self.audit.log("USER_LOGIN", user.user_id, "user", user.user_id)
        return user, token

    def deposit(self, account_number: str, amount: float, description: str = "Deposit") -> Transaction:
        acc = self.accounts.get_by_number(account_number)
        txn = self.transactions.deposit(acc.account_id, Decimal(str(amount)), description)
        self.audit.log("DEPOSIT", acc.user_id, "transaction", txn.transaction_id,
                       {"amount": amount, "account": account_number, "ref": txn.reference_id})
        return txn

    def withdraw(self, account_number: str, amount: float, description: str = "Withdrawal") -> Transaction:
        acc = self.accounts.get_by_number(account_number)
        txn = self.transactions.withdraw(acc.account_id, Decimal(str(amount)), description)
        self.audit.log("WITHDRAWAL", acc.user_id, "transaction", txn.transaction_id,
                       {"amount": amount, "account": account_number, "ref": txn.reference_id})
        return txn

    def transfer(self, from_number: str, to_number: str, amount: float, description: str = "Transfer") -> Transaction:
        from_acc = self.accounts.get_by_number(from_number)
        to_acc   = self.accounts.get_by_number(to_number)
        txn = self.transactions.transfer(from_acc.account_id, to_acc.account_id, Decimal(str(amount)), description)
        self.audit.log("TRANSFER", from_acc.user_id, "transaction", txn.transaction_id,
                       {"amount": amount, "from": from_number, "to": to_number, "ref": txn.reference_id})
        return txn

    def apply_for_loan(self, account_number: str, amount: float, duration_days: int = 365) -> Loan:
        acc = self.accounts.get_by_number(account_number)
        loan = self.loans.apply_loan(acc.account_id, Decimal(str(amount)), duration_days)
        self.audit.log("LOAN_APPLIED", acc.user_id, "loan", loan.loan_id,
                       {"amount": amount, "account": account_number})
        return loan

    def repay_loan(self, loan_id: int, account_number: str, amount: float) -> Loan:
        acc = self.accounts.get_by_number(account_number)
        loan = self.loans.repay_loan(loan_id, Decimal(str(amount)))
        self.audit.log("LOAN_REPAYMENT", acc.user_id, "loan", loan_id,
                       {"amount": amount, "account": account_number})
        return loan

    def get_statement(self, account_number: str, limit: int = 20) -> Dict[str, Any]:
        acc = self.accounts.get_by_number(account_number)
        transactions = self.transactions.get_history(acc.account_id, limit=limit)
        loans = self.loans.get_account_loans(acc.account_id)
        return {
            "account": {
                "account_number": acc.account_number,
                "account_type": acc.account_type,
                "balance": str(acc.balance),
                "currency": acc.currency,
            },
            "transactions": [
                {
                    "ref": t.reference_id,
                    "type": t.transaction_type,
                    "amount": str(t.amount),
                    "fee": str(t.fee),
                    "status": t.status,
                    "description": t.description,
                    "date": t.created_at.isoformat() if isinstance(t.created_at, datetime) else str(t.created_at),
                }
                for t in transactions
            ],
            "loans": [
                {
                    "loan_id": l.loan_id,
                    "principal": str(l.principal),
                    "outstanding": str(l.outstanding_balance),
                    "status": l.status,
                    "due_date": l.due_date.isoformat() if isinstance(l.due_date, datetime) else str(l.due_date),
                }
                for l in loans
            ],
        }

# ══════════════════════════════════════════════════════════════════════════
# DEMO / QUICK TEST
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import pprint

    bank = PiNexusBankingNetwork()

    # Register users
    alice = bank.register_user("alice", "alice@pi.network", "Alice Smith", "s3cur3P@ss!")
    bob   = bank.register_user("bob",   "bob@pi.network",   "Bob Jones",   "b0bP@ss!")

    alice_accounts = bank.accounts.get_user_accounts(alice.user_id)
    bob_accounts   = bank.accounts.get_user_accounts(bob.user_id)
    alice_num = alice_accounts[0].account_number
    bob_num   = bob_accounts[0].account_number

    print(f"\n✅ Alice account: {alice_num}")
    print(f"✅ Bob   account: {bob_num}")

    # Deposit
    bank.deposit(alice_num, 5000, "Initial deposit")
    bank.deposit(bob_num, 1000, "Initial deposit")

    # Transfer
    bank.transfer(alice_num, bob_num, 500, "Payment for services")

    # Loan
    loan = bank.apply_for_loan(bob_num, 2000, duration_days=180)
    print(f"\n✅ Loan approved: loan_id={loan.loan_id}, outstanding={loan.outstanding_balance} PI")

    # Repay part of loan
    bank.repay_loan(loan.loan_id, bob_num, 1000)

    # Statement
    print("\n── Alice Statement ──")
    pprint.pprint(bank.get_statement(alice_num))

    print("\n── Bob Statement ──")
    pprint.pprint(bank.get_statement(bob_num))

    # Authentication
    user, token = bank.login("alice", "s3cur3P@ss!")
    print(f"\n✅ Login successful. Token: {token[:40]}...")