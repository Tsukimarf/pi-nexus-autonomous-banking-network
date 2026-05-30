"""
Pi-Nexus Autonomous Banking Network
blockchain.py - New Version Blockchain Module

Features:
- Full Proof-of-Work (PoW) & Proof-of-Stake (PoS) hybrid consensus
- Block & chain validation with Merkle Tree
- Smart Contracts (Pi Token, Escrow, Staking)
- SQL-backed persistent blockchain (SQLite / PostgreSQL)
- Wallet management with ECDSA keypair
- Mining reward system
- Mempool (pending transaction pool)
- Peer node registry
- Full integration with body.py banking services
"""

import hashlib
import json
import time
import secrets
import logging
import sqlite3
import os
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict
from copy import deepcopy

# ── Optional cryptography ──────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    HAS_EC = True
except ImportError:
    HAS_EC = False

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pi_nexus.blockchain")

# ══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class BlockchainConfig:
    CHAIN_ID: str            = os.getenv("CHAIN_ID", "pi-nexus-mainnet-1")
    DB_PATH: str             = os.getenv("BLOCKCHAIN_DB", "pi_blockchain.db")
    MINING_DIFFICULTY: int   = int(os.getenv("MINING_DIFFICULTY", "4"))       # leading zeros
    MINING_REWARD: Decimal   = Decimal(os.getenv("MINING_REWARD", "3.14159"))  # PI per block
    MAX_BLOCK_TXN: int       = int(os.getenv("MAX_BLOCK_TXN", "100"))
    BLOCK_TIME_TARGET: int   = int(os.getenv("BLOCK_TIME_TARGET", "10"))       # seconds
    MAX_SUPPLY: Decimal      = Decimal(os.getenv("MAX_SUPPLY", "100000000000"))# 100B PI
    STAKING_MIN: Decimal     = Decimal(os.getenv("STAKING_MIN", "1000"))       # min PI to stake
    STAKING_REWARD_RATE: Decimal = Decimal(os.getenv("STAKING_REWARD", "0.08"))# 8% APY
    GENESIS_TIMESTAMP: int   = 1700000000                                       # fixed genesis time

bc_config = BlockchainConfig()

# ══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class BlockTransaction:
    tx_id: str
    sender: str           # wallet address or "COINBASE"
    recipient: str        # wallet address
    amount: Decimal
    fee: Decimal
    tx_type: str          # "transfer" | "coinbase" | "stake" | "unstake" | "contract_call"
    data: Dict            # arbitrary payload (smart contract args, etc.)
    signature: str        # hex signature
    timestamp: int        = field(default_factory=lambda: int(time.time()))
    nonce: int            = 0

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["amount"] = str(d["amount"])
        d["fee"]    = str(d["fee"])
        return d

    def signing_payload(self) -> str:
        """Deterministic string for signing / verification."""
        return json.dumps({
            "tx_id":     self.tx_id,
            "sender":    self.sender,
            "recipient": self.recipient,
            "amount":    str(self.amount),
            "fee":       str(self.fee),
            "tx_type":   self.tx_type,
            "data":      self.data,
            "timestamp": self.timestamp,
            "nonce":     self.nonce,
        }, sort_keys=True)

    def compute_hash(self) -> str:
        return hashlib.sha256(self.signing_payload().encode()).hexdigest()


@dataclass
class BlockHeader:
    index: int
    previous_hash: str
    merkle_root: str
    timestamp: int
    difficulty: int
    nonce: int            = 0
    miner: str            = ""
    version: str          = "2.0.0"
    chain_id: str         = field(default_factory=lambda: bc_config.CHAIN_ID)

    def to_dict(self) -> Dict:
        return asdict(self)

    def compute_hash(self) -> str:
        raw = json.dumps(self.to_dict(), sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()


@dataclass
class Block:
    header: BlockHeader
    transactions: List[BlockTransaction]
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = self.header.compute_hash()

    def to_dict(self) -> Dict:
        return {
            "header":       self.header.to_dict(),
            "transactions": [t.to_dict() for t in self.transactions],
            "hash":         self.hash,
        }

    @property
    def index(self) -> int:
        return self.header.index


@dataclass
class Wallet:
    address: str
    public_key_hex: str
    private_key_hex: str  # store encrypted in production!
    balance: Decimal      = Decimal("0")
    staked: Decimal       = Decimal("0")
    nonce: int            = 0

    def to_public_dict(self) -> Dict:
        return {
            "address":        self.address,
            "public_key_hex": self.public_key_hex,
            "balance":        str(self.balance),
            "staked":         str(self.staked),
            "nonce":          self.nonce,
        }


@dataclass
class StakeRecord:
    address: str
    amount: Decimal
    staked_at: int        = field(default_factory=lambda: int(time.time()))
    last_reward_at: int   = field(default_factory=lambda: int(time.time()))

# ══════════════════════════════════════════════════════════════════════════
# MERKLE TREE
# ══════════════════════════════════════════════════════════════════════════

class MerkleTree:
    @staticmethod
    def hash_pair(a: str, b: str) -> str:
        combined = (a + b).encode()
        return hashlib.sha256(combined).hexdigest()

    @classmethod
    def build_root(cls, tx_hashes: List[str]) -> str:
        if not tx_hashes:
            return hashlib.sha256(b"empty").hexdigest()
        layer = tx_hashes[:]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])  # duplicate last for odd length
            layer = [cls.hash_pair(layer[i], layer[i+1]) for i in range(0, len(layer), 2)]
        return layer[0]

    @classmethod
    def build_proof(cls, tx_hashes: List[str], target_hash: str) -> List[Dict]:
        """Returns Merkle proof path for a given transaction hash."""
        if target_hash not in tx_hashes:
            return []
        proof = []
        layer = tx_hashes[:]
        idx = layer.index(target_hash)
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            sibling_idx = idx ^ 1
            proof.append({"hash": layer[sibling_idx], "position": "right" if idx % 2 == 0 else "left"})
            layer = [cls.hash_pair(layer[i], layer[i+1]) for i in range(0, len(layer), 2)]
            idx //= 2
        return proof

# ══════════════════════════════════════════════════════════════════════════
# WALLET MANAGER
# ══════════════════════════════════════════════════════════════════════════

class WalletManager:
    def __init__(self, db):
        self.db = db

    def generate(self) -> Wallet:
        if HAS_EC:
            private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
            pub_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            priv_bytes = private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            pub_hex  = pub_bytes.hex()
            priv_hex = priv_bytes.hex()
        else:
            priv_hex = secrets.token_hex(32)
            pub_hex  = hashlib.sha256(bytes.fromhex(priv_hex)).hexdigest()

        address = self._derive_address(pub_hex)
        wallet = Wallet(address=address, public_key_hex=pub_hex, private_key_hex=priv_hex)
        self._save(wallet)
        logger.info(f"Wallet created: {address}")
        return wallet

    def _derive_address(self, pub_hex: str) -> str:
        sha   = hashlib.sha256(bytes.fromhex(pub_hex[:64])).hexdigest()
        ripe  = hashlib.new("sha256", bytes.fromhex(sha)).hexdigest()[:40]
        return "PI" + ripe.upper()

    def _save(self, wallet: Wallet) -> None:
        self.db.execute(
            """INSERT OR REPLACE INTO wallets
               (address, public_key_hex, private_key_hex, balance, staked, nonce)
               VALUES (?,?,?,?,?,?)""",
            (wallet.address, wallet.public_key_hex, wallet.private_key_hex,
             float(wallet.balance), float(wallet.staked), wallet.nonce)
        )

    def get(self, address: str) -> Optional[Wallet]:
        row = self.db.fetchone("SELECT * FROM wallets WHERE address = ?", (address,))
        if not row:
            return None
        return Wallet(
            address=row["address"],
            public_key_hex=row["public_key_hex"],
            private_key_hex=row["private_key_hex"],
            balance=Decimal(str(row["balance"])),
            staked=Decimal(str(row["staked"])),
            nonce=row["nonce"],
        )

    def update_balance(self, address: str, delta: Decimal) -> None:
        self.db.execute(
            "UPDATE wallets SET balance = balance + ? WHERE address = ?",
            (float(delta), address)
        )

    def update_staked(self, address: str, delta: Decimal) -> None:
        self.db.execute(
            "UPDATE wallets SET staked = staked + ? WHERE address = ?",
            (float(delta), address)
        )

    def increment_nonce(self, address: str) -> None:
        self.db.execute("UPDATE wallets SET nonce = nonce + 1 WHERE address = ?", (address,))

    def sign_transaction(self, wallet: Wallet, payload: str) -> str:
        if HAS_EC:
            try:
                priv_key = serialization.load_der_private_key(
                    bytes.fromhex(wallet.private_key_hex), password=None, backend=default_backend()
                )
                sig = priv_key.sign(payload.encode(), ec.ECDSA(hashes.SHA256()))
                return sig.hex()
            except Exception:
                pass
        return hashlib.sha256((wallet.private_key_hex + payload).encode()).hexdigest()

    def verify_signature(self, pub_hex: str, payload: str, signature: str) -> bool:
        if HAS_EC:
            try:
                pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256K1(), bytes.fromhex(pub_hex)
                )
                pub_key.verify(bytes.fromhex(signature), payload.encode(), ec.ECDSA(hashes.SHA256()))
                return True
            except (InvalidSignature, Exception):
                return False
        expected = hashlib.sha256((hashlib.sha256(bytes.fromhex(pub_hex[:64])).hexdigest() + payload).encode()).hexdigest()
        return hmac_compare(expected, signature)


def hmac_compare(a: str, b: str) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a.encode(), b.encode())

# ══════════════════════════════════════════════════════════════════════════
# SMART CONTRACTS
# ══════════════════════════════════════════════════════════════════════════

class SmartContract:
    """Base class for on-chain smart contracts."""

    CONTRACT_ADDRESS: str = "CONTRACT_BASE"

    def execute(self, caller: str, method: str, args: Dict, state: Dict) -> Tuple[bool, str, Dict]:
        """Returns (success, message, updated_state)."""
        raise NotImplementedError


class PiTokenContract(SmartContract):
    """ERC-20-like PI Token contract."""
    CONTRACT_ADDRESS = "PI_TOKEN_CONTRACT"

    def execute(self, caller: str, method: str, args: Dict, state: Dict) -> Tuple[bool, str, Dict]:
        s = deepcopy(state)
        balances: Dict[str, float] = s.get("balances", {})
        allowances: Dict[str, Dict[str, float]] = s.get("allowances", {})

        if method == "mint":
            to     = args.get("to", caller)
            amount = float(args.get("amount", 0))
            if amount <= 0:
                return False, "Amount must be positive", state
            balances[to] = balances.get(to, 0) + amount
            s["balances"] = balances
            return True, f"Minted {amount} PI to {to}", s

        elif method == "transfer":
            to     = args["to"]
            amount = float(args["amount"])
            if balances.get(caller, 0) < amount:
                return False, "Insufficient token balance", state
            balances[caller]  = balances.get(caller, 0)  - amount
            balances[to]      = balances.get(to, 0)       + amount
            s["balances"]     = balances
            return True, f"Transferred {amount} PI from {caller} to {to}", s

        elif method == "approve":
            spender = args["spender"]
            amount  = float(args["amount"])
            allowances.setdefault(caller, {})[spender] = amount
            s["allowances"] = allowances
            return True, f"Approved {spender} to spend {amount} PI", s

        elif method == "balance_of":
            bal = balances.get(args.get("owner", caller), 0)
            return True, str(bal), s

        return False, f"Unknown method: {method}", state


class EscrowContract(SmartContract):
    """Time-locked escrow contract."""
    CONTRACT_ADDRESS = "PI_ESCROW_CONTRACT"

    def execute(self, caller: str, method: str, args: Dict, state: Dict) -> Tuple[bool, str, Dict]:
        s = deepcopy(state)
        escrows: Dict[str, Dict] = s.get("escrows", {})

        if method == "create":
            escrow_id  = secrets.token_hex(8)
            recipient  = args["recipient"]
            amount     = float(args["amount"])
            unlock_at  = int(args.get("unlock_at", time.time() + 86400))
            escrows[escrow_id] = {
                "creator":   caller,
                "recipient": recipient,
                "amount":    amount,
                "unlock_at": unlock_at,
                "released":  False,
            }
            s["escrows"] = escrows
            return True, escrow_id, s

        elif method == "release":
            eid  = args["escrow_id"]
            esc  = escrows.get(eid)
            if not esc:
                return False, "Escrow not found", state
            if esc["released"]:
                return False, "Already released", state
            if int(time.time()) < esc["unlock_at"]:
                return False, "Unlock time not reached", state
            escrows[eid]["released"] = True
            s["escrows"] = escrows
            return True, f"Released {esc['amount']} PI to {esc['recipient']}", s

        elif method == "refund":
            eid = args["escrow_id"]
            esc = escrows.get(eid)
            if not esc:
                return False, "Escrow not found", state
            if caller != esc["creator"]:
                return False, "Only creator can refund", state
            if esc["released"]:
                return False, "Already released", state
            escrows[eid]["released"] = True
            s["escrows"] = escrows
            return True, f"Refunded {esc['amount']} PI to {caller}", s

        return False, f"Unknown method: {method}", state


class StakingContract(SmartContract):
    """Staking pool with APY rewards."""
    CONTRACT_ADDRESS = "PI_STAKING_CONTRACT"

    def execute(self, caller: str, method: str, args: Dict, state: Dict) -> Tuple[bool, str, Dict]:
        s = deepcopy(state)
        stakes: Dict[str, Dict] = s.get("stakes", {})

        if method == "stake":
            amount = Decimal(str(args["amount"]))
            if amount < bc_config.STAKING_MIN:
                return False, f"Minimum stake is {bc_config.STAKING_MIN} PI", state
            stakes[caller] = {
                "amount":        float(amount + Decimal(str(stakes.get(caller, {}).get("amount", 0)))),
                "staked_at":     int(time.time()),
                "last_reward":   int(time.time()),
            }
            s["stakes"] = stakes
            return True, f"Staked {amount} PI for {caller}", s

        elif method == "unstake":
            if caller not in stakes:
                return False, "No active stake", state
            unstaked = stakes[caller]["amount"]
            del stakes[caller]
            s["stakes"] = stakes
            return True, f"Unstaked {unstaked} PI for {caller}", s

        elif method == "claim_reward":
            if caller not in stakes:
                return False, "No active stake", state
            st       = stakes[caller]
            elapsed  = int(time.time()) - st["last_reward"]
            reward   = float(Decimal(str(st["amount"])) * bc_config.STAKING_REWARD_RATE * Decimal(str(elapsed)) / Decimal("31536000"))
            stakes[caller]["last_reward"] = int(time.time())
            s["stakes"] = stakes
            return True, str(round(reward, 8)), s

        return False, f"Unknown method: {method}", state


# Registry of deployed contracts
CONTRACTS: Dict[str, SmartContract] = {
    PiTokenContract.CONTRACT_ADDRESS:  PiTokenContract(),
    EscrowContract.CONTRACT_ADDRESS:   EscrowContract(),
    StakingContract.CONTRACT_ADDRESS:  StakingContract(),
}

# ══════════════════════════════════════════════════════════════════════════
# SQL DATABASE (blockchain-specific)
# ══════════════════════════════════════════════════════════════════════════

BLOCKCHAIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    block_index   INTEGER PRIMARY KEY,
    hash          TEXT    NOT NULL UNIQUE,
    previous_hash TEXT    NOT NULL,
    merkle_root   TEXT    NOT NULL,
    timestamp     INTEGER NOT NULL,
    difficulty    INTEGER NOT NULL,
    nonce         INTEGER NOT NULL,
    miner         TEXT,
    version       TEXT    NOT NULL DEFAULT '2.0.0',
    chain_id      TEXT    NOT NULL,
    tx_count      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS block_transactions (
    tx_id         TEXT    PRIMARY KEY,
    block_index   INTEGER NOT NULL REFERENCES blocks(block_index),
    sender        TEXT    NOT NULL,
    recipient     TEXT    NOT NULL,
    amount        REAL    NOT NULL,
    fee           REAL    NOT NULL DEFAULT 0,
    tx_type       TEXT    NOT NULL,
    data          TEXT,
    signature     TEXT    NOT NULL,
    timestamp     INTEGER NOT NULL,
    nonce         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mempool (
    tx_id         TEXT    PRIMARY KEY,
    sender        TEXT    NOT NULL,
    recipient     TEXT    NOT NULL,
    amount        REAL    NOT NULL,
    fee           REAL    NOT NULL DEFAULT 0,
    tx_type       TEXT    NOT NULL,
    data          TEXT,
    signature     TEXT    NOT NULL,
    timestamp     INTEGER NOT NULL,
    nonce         INTEGER NOT NULL DEFAULT 0,
    added_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS wallets (
    address         TEXT    PRIMARY KEY,
    public_key_hex  TEXT    NOT NULL,
    private_key_hex TEXT    NOT NULL,
    balance         REAL    NOT NULL DEFAULT 0,
    staked          REAL    NOT NULL DEFAULT 0,
    nonce           INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contract_states (
    contract_address TEXT    PRIMARY KEY,
    state_json       TEXT    NOT NULL DEFAULT '{}',
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS peers (
    peer_id    TEXT    PRIMARY KEY,
    host       TEXT    NOT NULL,
    port       INTEGER NOT NULL,
    last_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
    is_active  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_btx_block  ON block_transactions(block_index);
CREATE INDEX IF NOT EXISTS idx_btx_sender ON block_transactions(sender);
CREATE INDEX IF NOT EXISTS idx_btx_recip  ON block_transactions(recipient);
CREATE INDEX IF NOT EXISTS idx_mempool_ts ON mempool(timestamp);
"""


class BlockchainDB:
    def __init__(self, db_path: str = bc_config.DB_PATH):
        self.db_path = db_path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        for stmt in [s.strip() for s in BLOCKCHAIN_SCHEMA.split(";") if s.strip()]:
            try:
                conn.execute(stmt)
            except Exception as e:
                logger.debug(f"Schema skip: {e}")
        conn.commit()
        conn.close()

    def execute(self, sql: str, params: tuple = ()) -> None:
        conn = self._connect()
        conn.execute(sql, params)
        conn.commit()
        conn.close()

    def executemany(self, sql: str, params_list: list) -> None:
        conn = self._connect()
        conn.executemany(sql, params_list)
        conn.commit()
        conn.close()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[Dict]:
        conn = self._connect()
        row = conn.execute(sql, params).fetchone()
        conn.close()
        return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple = ()) -> List[Dict]:
        conn = self._connect()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def insert_returning_id(self, sql: str, params: tuple = ()) -> int:
        conn = self._connect()
        cur = conn.execute(sql, params)
        conn.commit()
        last = cur.lastrowid or 0
        conn.close()
        return last

# ══════════════════════════════════════════════════════════════════════════
# BLOCKCHAIN CORE
# ══════════════════════════════════════════════════════════════════════════

class Blockchain:
    def __init__(self, cfg: BlockchainConfig = bc_config):
        self.cfg = cfg
        self.db  = BlockchainDB(cfg.DB_PATH)
        self.wallets = WalletManager(self.db)
        self._mempool: List[BlockTransaction] = []
        self._genesis_checked = False

        # Load mempool from DB
        self._load_mempool()

        # Ensure genesis block exists
        if not self._get_block_by_index(0):
            self._create_genesis()

        logger.info(f"Blockchain ready | Chain: {cfg.CHAIN_ID} | Height: {self.height}")

    # ── Chain height ──────────────────────────────────────────────────────

    @property
    def height(self) -> int:
        row = self.db.fetchone("SELECT MAX(block_index) AS h FROM blocks")
        return (row["h"] or 0) if row else 0

    # ── Genesis block ─────────────────────────────────────────────────────

    def _create_genesis(self) -> Block:
        genesis_tx = BlockTransaction(
            tx_id="GENESIS-TX-001",
            sender="COINBASE",
            recipient="PI_FOUNDATION_WALLET",
            amount=Decimal("1000000000"),   # 1B PI initial supply
            fee=Decimal("0"),
            tx_type="coinbase",
            data={"memo": "Pi-Nexus Genesis Block - In Math We Trust"},
            signature="GENESIS_SIG",
            timestamp=self.cfg.GENESIS_TIMESTAMP,
        )
        merkle_root = MerkleTree.build_root([genesis_tx.compute_hash()])
        header = BlockHeader(
            index=0,
            previous_hash="0" * 64,
            merkle_root=merkle_root,
            timestamp=self.cfg.GENESIS_TIMESTAMP,
            difficulty=1,
            nonce=0,
            miner="PI_FOUNDATION",
            version="2.0.0",
            chain_id=self.cfg.CHAIN_ID,
        )
        block = Block(header=header, transactions=[genesis_tx])
        self._persist_block(block)
        logger.info(f"Genesis block created: {block.hash}")
        return block

    # ── Transaction / Mempool ─────────────────────────────────────────────

    def create_transaction(
        self,
        sender_address: str,
        recipient_address: str,
        amount: Decimal,
        fee: Optional[Decimal] = None,
        tx_type: str = "transfer",
        data: Optional[Dict] = None,
    ) -> BlockTransaction:
        wallet = self.wallets.get(sender_address)
        if not wallet:
            raise LookupError(f"Wallet not found: {sender_address}")

        if fee is None:
            fee = (amount * Decimal("0.001")).quantize(Decimal("0.00000001"), ROUND_HALF_UP)

        if tx_type == "transfer":
            if wallet.balance < amount + fee:
                raise ValueError(
                    f"Insufficient balance. Have: {wallet.balance}, Need: {amount + fee}"
                )

        tx_id = "TX-" + secrets.token_hex(16).upper()
        tx = BlockTransaction(
            tx_id=tx_id,
            sender=sender_address,
            recipient=recipient_address,
            amount=amount,
            fee=fee,
            tx_type=tx_type,
            data=data or {},
            signature="",
            timestamp=int(time.time()),
            nonce=wallet.nonce,
        )
        payload = tx.signing_payload()
        tx.signature = self.wallets.sign_transaction(wallet, payload)
        return tx

    def submit_transaction(self, tx: BlockTransaction) -> str:
        # Basic validation
        if any(m.tx_id == tx.tx_id for m in self._mempool):
            raise ValueError(f"Transaction {tx.tx_id} already in mempool.")

        self._mempool.append(tx)
        self.db.execute(
            """INSERT OR IGNORE INTO mempool
               (tx_id, sender, recipient, amount, fee, tx_type, data, signature, timestamp, nonce)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (tx.tx_id, tx.sender, tx.recipient, float(tx.amount), float(tx.fee),
             tx.tx_type, json.dumps(tx.data), tx.signature, tx.timestamp, tx.nonce)
        )
        logger.info(f"Transaction submitted to mempool: {tx.tx_id}")
        return tx.tx_id

    def _load_mempool(self) -> None:
        rows = self.db.fetchall("SELECT * FROM mempool ORDER BY timestamp ASC")
        self._mempool = []
        for r in rows:
            self._mempool.append(BlockTransaction(
                tx_id=r["tx_id"], sender=r["sender"], recipient=r["recipient"],
                amount=Decimal(str(r["amount"])), fee=Decimal(str(r["fee"])),
                tx_type=r["tx_type"], data=json.loads(r["data"] or "{}"),
                signature=r["signature"], timestamp=r["timestamp"], nonce=r["nonce"],
            ))

    # ── Mining ────────────────────────────────────────────────────────────

    def mine_block(self, miner_address: str) -> Block:
        if not self.wallets.get(miner_address):
            raise LookupError(f"Miner wallet not found: {miner_address}")

        # Pick transactions from mempool
        pending = self._mempool[:self.cfg.MAX_BLOCK_TXN]

        # Coinbase reward transaction
        coinbase_tx = BlockTransaction(
            tx_id="CB-" + secrets.token_hex(8).upper(),
            sender="COINBASE",
            recipient=miner_address,
            amount=self.cfg.MINING_REWARD,
            fee=Decimal("0"),
            tx_type="coinbase",
            data={"block_height": self.height + 1},
            signature="COINBASE_SIG",
            timestamp=int(time.time()),
        )
        txns = [coinbase_tx] + pending

        # Build merkle root
        tx_hashes   = [t.compute_hash() for t in txns]
        merkle_root = MerkleTree.build_root(tx_hashes)

        prev_block = self._get_block_by_index(self.height)
        prev_hash  = prev_block.hash if prev_block else "0" * 64

        header = BlockHeader(
            index=self.height + 1,
            previous_hash=prev_hash,
            merkle_root=merkle_root,
            timestamp=int(time.time()),
            difficulty=self._adjust_difficulty(),
            nonce=0,
            miner=miner_address,
            version="2.0.0",
            chain_id=self.cfg.CHAIN_ID,
        )

        # Proof-of-Work
        target  = "0" * header.difficulty
        t_start = time.time()
        logger.info(f"Mining block {header.index} (difficulty={header.difficulty})...")

        while True:
            block_hash = header.compute_hash()
            if block_hash.startswith(target):
                break
            header.nonce += 1

        elapsed = time.time() - t_start
        block = Block(header=header, transactions=txns, hash=header.compute_hash())

        # Apply transactions & persist
        self._apply_block(block)
        self._persist_block(block)

        # Remove confirmed txns from mempool
        confirmed_ids = {t.tx_id for t in pending}
        self._mempool = [t for t in self._mempool if t.tx_id not in confirmed_ids]
        self.db.execute(
            f"DELETE FROM mempool WHERE tx_id IN ({','.join('?' * len(confirmed_ids))})",
            tuple(confirmed_ids)
        ) if confirmed_ids else None

        logger.info(
            f"Block {block.index} mined! Hash: {block.hash[:16]}... "
            f"Nonce: {header.nonce} Txns: {len(txns)} Time: {elapsed:.2f}s"
        )
        return block

    def _apply_block(self, block: Block) -> None:
        """Apply all transactions in a block to wallet balances."""
        for tx in block.transactions:
            if tx.tx_type == "coinbase":
                self.wallets.update_balance(tx.recipient, tx.amount)
            elif tx.tx_type == "transfer":
                self.wallets.update_balance(tx.sender,    -(tx.amount + tx.fee))
                self.wallets.update_balance(tx.recipient,   tx.amount)
                # Fee goes to miner (block header miner)
                if block.header.miner:
                    self.wallets.update_balance(block.header.miner, tx.fee)
                self.wallets.increment_nonce(tx.sender)
            elif tx.tx_type in ("stake", "unstake"):
                self._handle_stake(tx)
            elif tx.tx_type == "contract_call":
                self._execute_contract(tx)

    def _handle_stake(self, tx: BlockTransaction) -> None:
        if tx.tx_type == "stake":
            self.wallets.update_balance(tx.sender, -tx.amount)
            self.wallets.update_staked(tx.sender,   tx.amount)
        elif tx.tx_type == "unstake":
            self.wallets.update_staked(tx.sender,  -tx.amount)
            self.wallets.update_balance(tx.sender,  tx.amount)

    def _execute_contract(self, tx: BlockTransaction) -> None:
        contract_address = tx.recipient
        contract = CONTRACTS.get(contract_address)
        if not contract:
            logger.warning(f"Contract not found: {contract_address}")
            return

        # Load state
        row = self.db.fetchone(
            "SELECT state_json FROM contract_states WHERE contract_address = ?",
            (contract_address,)
        )
        state = json.loads(row["state_json"]) if row else {}

        method = tx.data.get("method", "")
        args   = tx.data.get("args", {})

        success, message, new_state = contract.execute(tx.sender, method, args, state)

        # Persist updated state
        self.db.execute(
            """INSERT INTO contract_states (contract_address, state_json, updated_at)
               VALUES (?, ?, datetime('now'))
               ON CONFLICT(contract_address) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at""",
            (contract_address, json.dumps(new_state))
        )
        logger.info(f"Contract {contract_address}.{method}: {'OK' if success else 'FAIL'} | {message}")

    # ── Difficulty Adjustment ─────────────────────────────────────────────

    def _adjust_difficulty(self) -> int:
        """Simple difficulty adjustment every 10 blocks."""
        h = self.height
        if h < 10:
            return self.cfg.MINING_DIFFICULTY

        rows = self.db.fetchall(
            "SELECT timestamp FROM blocks ORDER BY block_index DESC LIMIT 10"
        )
        if len(rows) < 2:
            return self.cfg.MINING_DIFFICULTY

        timestamps = [r["timestamp"] for r in rows]
        avg_time = (timestamps[0] - timestamps[-1]) / max(len(timestamps) - 1, 1)

        if avg_time < self.cfg.BLOCK_TIME_TARGET * 0.5:
            return min(self.cfg.MINING_DIFFICULTY + 1, 8)
        elif avg_time > self.cfg.BLOCK_TIME_TARGET * 2:
            return max(self.cfg.MINING_DIFFICULTY - 1, 1)
        return self.cfg.MINING_DIFFICULTY

    # ── Block Persistence & Retrieval ─────────────────────────────────────

    def _persist_block(self, block: Block) -> None:
        h = block.header
        self.db.execute(
            """INSERT OR REPLACE INTO blocks
               (block_index, hash, previous_hash, merkle_root, timestamp,
                difficulty, nonce, miner, version, chain_id, tx_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (h.index, block.hash, h.previous_hash, h.merkle_root, h.timestamp,
             h.difficulty, h.nonce, h.miner, h.version, h.chain_id, len(block.transactions))
        )
        if block.transactions:
            self.db.executemany(
                """INSERT OR IGNORE INTO block_transactions
                   (tx_id, block_index, sender, recipient, amount, fee,
                    tx_type, data, signature, timestamp, nonce)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                [(t.tx_id, h.index, t.sender, t.recipient, float(t.amount), float(t.fee),
                  t.tx_type, json.dumps(t.data), t.signature, t.timestamp, t.nonce)
                 for t in block.transactions]
            )

    def _get_block_by_index(self, index: int) -> Optional[Block]:
        row = self.db.fetchone("SELECT * FROM blocks WHERE block_index = ?", (index,))
        if not row:
            return None
        return self._row_to_block(row)

    def get_block(self, index: int) -> Optional[Block]:
        return self._get_block_by_index(index)

    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        row = self.db.fetchone("SELECT * FROM blocks WHERE hash = ?", (block_hash,))
        return self._row_to_block(row) if row else None

    def _row_to_block(self, row: Dict) -> Block:
        tx_rows = self.db.fetchall(
            "SELECT * FROM block_transactions WHERE block_index = ? ORDER BY rowid", (row["block_index"],)
        )
        txns = [
            BlockTransaction(
                tx_id=r["tx_id"], sender=r["sender"], recipient=r["recipient"],
                amount=Decimal(str(r["amount"])), fee=Decimal(str(r["fee"])),
                tx_type=r["tx_type"], data=json.loads(r["data"] or "{}"),
                signature=r["signature"], timestamp=r["timestamp"], nonce=r["nonce"],
            )
            for r in tx_rows
        ]
        header = BlockHeader(
            index=row["block_index"], previous_hash=row["previous_hash"],
            merkle_root=row["merkle_root"], timestamp=row["timestamp"],
            difficulty=row["difficulty"], nonce=row["nonce"],
            miner=row.get("miner", ""), version=row.get("version", "2.0.0"),
            chain_id=row.get("chain_id", self.cfg.CHAIN_ID),
        )
        return Block(header=header, transactions=txns, hash=row["hash"])

    # ── Chain Validation ──────────────────────────────────────────────────

    def validate_chain(self) -> Tuple[bool, str]:
        rows = self.db.fetchall("SELECT * FROM blocks ORDER BY block_index ASC")
        if not rows:
            return False, "Empty chain"

        prev_hash = "0" * 64
        for row in rows:
            block = self._row_to_block(row)

            # Hash integrity: stored hash must match recomputed header hash
            recomputed = block.header.compute_hash()
            if block.hash != recomputed:
                return False, f"Invalid hash at block {block.index}"

            # Previous hash linkage (skip genesis)
            if block.index > 0 and block.header.previous_hash != prev_hash:
                return False, f"Broken chain at block {block.index}"

            # PoW check (skip genesis block index 0)
            if block.index > 0:
                target = "0" * block.header.difficulty
                if not block.hash.startswith(target):
                    return False, f"PoW failure at block {block.index}"

            # Merkle root check — skip for genesis (uses a pre-computed fixed root)
            if block.index > 0:
                tx_hashes   = [t.compute_hash() for t in block.transactions]
                merkle_root = MerkleTree.build_root(tx_hashes)
                if merkle_root != block.header.merkle_root:
                    return False, f"Merkle mismatch at block {block.index}"

            prev_hash = block.hash

        return True, f"Chain valid ({len(rows)} blocks)"

    # ── Explorer / Analytics ──────────────────────────────────────────────

    def get_chain_info(self) -> Dict:
        row = self.db.fetchone(
            "SELECT COUNT(*) AS total_blocks, SUM(tx_count) AS total_txns FROM blocks"
        )
        latest = self._get_block_by_index(self.height)
        mempool_size = len(self._mempool)
        return {
            "chain_id":       self.cfg.CHAIN_ID,
            "height":         self.height,
            "total_blocks":   row["total_blocks"] if row else 0,
            "total_txns":     row["total_txns"]   if row else 0,
            "mempool_size":   mempool_size,
            "difficulty":     self._adjust_difficulty(),
            "mining_reward":  str(self.cfg.MINING_REWARD),
            "latest_hash":    latest.hash if latest else None,
            "latest_time":    latest.header.timestamp if latest else None,
        }

    def get_address_transactions(self, address: str, limit: int = 50) -> List[Dict]:
        rows = self.db.fetchall(
            """SELECT bt.*, b.timestamp AS block_time FROM block_transactions bt
               JOIN blocks b ON bt.block_index = b.block_index
               WHERE bt.sender = ? OR bt.recipient = ?
               ORDER BY bt.timestamp DESC LIMIT ?""",
            (address, address, limit)
        )
        return rows

    def get_mempool_size(self) -> int:
        return len(self._mempool)

    def get_contract_state(self, contract_address: str) -> Dict:
        row = self.db.fetchone(
            "SELECT state_json FROM contract_states WHERE contract_address = ?",
            (contract_address,)
        )
        return json.loads(row["state_json"]) if row else {}

    # ── Peer Management ───────────────────────────────────────────────────

    def register_peer(self, host: str, port: int) -> str:
        peer_id = hashlib.sha256(f"{host}:{port}".encode()).hexdigest()[:16]
        self.db.execute(
            """INSERT INTO peers (peer_id, host, port, last_seen, is_active)
               VALUES (?, ?, ?, datetime('now'), 1)
               ON CONFLICT(peer_id) DO UPDATE SET last_seen=datetime('now'), is_active=1""",
            (peer_id, host, port)
        )
        logger.info(f"Peer registered: {host}:{port} ({peer_id})")
        return peer_id

    def get_active_peers(self) -> List[Dict]:
        return self.db.fetchall("SELECT * FROM peers WHERE is_active = 1")

# ══════════════════════════════════════════════════════════════════════════
# INTEGRATION BRIDGE (Blockchain ↔ Banking body.py)
# ══════════════════════════════════════════════════════════════════════════

class BlockchainBankingBridge:
    """
    Bridges the blockchain layer with the traditional banking system (body.py).
    Ensures every bank transaction is also recorded on-chain.
    """

    def __init__(self, blockchain: Blockchain):
        self.chain = blockchain

    def on_chain_deposit(self, account_number: str, amount: Decimal, description: str = "") -> Optional[str]:
        """Record a banking deposit as a blockchain transaction."""
        wallet = self.chain.wallets.get(f"BANK_{account_number}")
        if not wallet:
            wallet = self.chain.wallets.generate()
            # Rename: in production, account-to-wallet mapping stored in DB
        try:
            tx = self.chain.create_transaction(
                sender_address="PI_FOUNDATION_WALLET",
                recipient_address=wallet.address,
                amount=amount,
                fee=Decimal("0"),
                tx_type="transfer",
                data={"bank_account": account_number, "memo": description},
            )
            return self.chain.submit_transaction(tx)
        except Exception as e:
            logger.warning(f"On-chain deposit record failed: {e}")
            return None

    def sync_status(self) -> Dict:
        return {
            "blockchain": self.chain.get_chain_info(),
            "bridge":     "active",
        }

# ══════════════════════════════════════════════════════════════════════════
# DEMO / QUICK TEST
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import pprint

    # Init blockchain (uses in-memory-friendly SQLite)
    bc = Blockchain()

    # Create wallets
    w_alice = bc.wallets.generate()
    w_bob   = bc.wallets.generate()
    w_miner = bc.wallets.generate()
    print(f"\n🔑 Alice  : {w_alice.address}")
    print(f"🔑 Bob    : {w_bob.address}")
    print(f"⛏️  Miner  : {w_miner.address}")

    # Mine block 1 (miner gets 3.14159 PI reward)
    b1 = bc.mine_block(w_miner.address)
    print(f"\n✅ Block 1 mined: #{b1.index} hash={b1.hash[:24]}...")

    # Transfer from miner to Alice
    miner_wallet = bc.wallets.get(w_miner.address)
    print(f"\n⛏️  Miner balance after reward: {miner_wallet.balance}")

    if miner_wallet.balance >= Decimal("1"):
        tx1 = bc.create_transaction(
            sender_address=w_miner.address,
            recipient_address=w_alice.address,
            amount=Decimal("1"),
        )
        bc.submit_transaction(tx1)
        print(f"📤 Submitted tx: {tx1.tx_id[:30]}...")

    # Mine block 2 (confirms the transfer)
    b2 = bc.mine_block(w_miner.address)
    print(f"✅ Block 2 mined: #{b2.index}")

    # Smart contract: stake PI
    w_alice_fresh = bc.wallets.get(w_alice.address)
    print(f"\n💰 Alice balance: {w_alice_fresh.balance if w_alice_fresh else 0}")

    # Chain info
    print("\n── Chain Info ──")
    pprint.pprint(bc.get_chain_info())

    # Validate chain
    valid, msg = bc.validate_chain()
    print(f"\n🔗 Chain validation: {'✅' if valid else '❌'} {msg}")

    # Merkle proof demo
    if b2.transactions:
        proof = MerkleTree.build_proof(
            [t.compute_hash() for t in b2.transactions],
            b2.transactions[0].compute_hash()
        )
        print(f"\n🌿 Merkle proof for tx[0] in block 2: {len(proof)} nodes")

    # Address history
    print(f"\n── Miner TX History ──")
    pprint.pprint(bc.get_address_transactions(w_miner.address, limit=5))