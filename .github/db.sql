-- ============================================================
--  PI NEXUS AUTONOMOUS BANKING NETWORK
--  MQL Database Schema Body File (v2.0.0)
--  Pi Network Banking Data Handler
--  Compatible: MQL4 / MQL5 | MySQL 8.x / PostgreSQL 15+
--  Repository: pi-nexus-autonomous-banking-network
--  Folder: .github/database/
-- ============================================================

-- ------------------------------------------------------------
-- 1. DATABASE INITIALIZATION
-- ------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS pi_nexus_banking
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE pi_nexus_banking;

-- ------------------------------------------------------------
-- 2. ENUMERATIONS / LOOKUP TABLES
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_network_status (
    status_id       TINYINT UNSIGNED    NOT NULL AUTO_INCREMENT,
    status_code     VARCHAR(32)         NOT NULL UNIQUE,   -- 'PENDING','CONFIRMED','FAILED','REVERSED'
    description     VARCHAR(128)        NOT NULL,
    is_terminal     BOOLEAN             NOT NULL DEFAULT FALSE,
    created_at      DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (status_id)
) ENGINE=InnoDB COMMENT='Pi Network transaction status lookup';

INSERT IGNORE INTO pi_network_status (status_code, description, is_terminal) VALUES
    ('PENDING',     'Transaction submitted, awaiting confirmation',  FALSE),
    ('PROCESSING',  'Transaction is being processed by the network', FALSE),
    ('CONFIRMED',   'Transaction confirmed on Pi Network mainnet',   TRUE),
    ('FAILED',      'Transaction failed or rejected',                TRUE),
    ('REVERSED',    'Transaction reversed or refunded',              TRUE),
    ('EXPIRED',     'Transaction expired before confirmation',       TRUE);

CREATE TABLE IF NOT EXISTS pi_wallet_type (
    type_id         TINYINT UNSIGNED    NOT NULL AUTO_INCREMENT,
    type_code       VARCHAR(32)         NOT NULL UNIQUE,   -- 'USER','BANK','ESCROW','TREASURY'
    description     VARCHAR(128)        NOT NULL,
    PRIMARY KEY (type_id)
) ENGINE=InnoDB COMMENT='Wallet type classification';

INSERT IGNORE INTO pi_wallet_type (type_code, description) VALUES
    ('USER',        'Standard user Pi wallet'),
    ('BANK',        'Institutional bank node wallet'),
    ('ESCROW',      'Escrow holding wallet'),
    ('TREASURY',    'Pi Nexus treasury reserve wallet'),
    ('MERCHANT',    'Merchant payment acceptance wallet');

-- ------------------------------------------------------------
-- 3. CORE ENTITY: PI WALLETS
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_wallets (
    wallet_id           BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    wallet_uid          CHAR(36)            NOT NULL UNIQUE,          -- UUID v4
    wallet_type_id      TINYINT UNSIGNED    NOT NULL,
    pi_network_address  VARCHAR(128)        NOT NULL UNIQUE,           -- Stellar/Pi public key
    display_name        VARCHAR(128)        NOT NULL DEFAULT '',
    balance_pi          DECIMAL(28, 7)      NOT NULL DEFAULT 0.0000000,
    balance_locked_pi   DECIMAL(28, 7)      NOT NULL DEFAULT 0.0000000,
    kyc_verified        BOOLEAN             NOT NULL DEFAULT FALSE,
    kyc_verified_at     DATETIME(3)         NULL,
    is_active           BOOLEAN             NOT NULL DEFAULT TRUE,
    metadata_json       JSON                NULL,                      -- extra MQL fields / tags
    created_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                            ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (wallet_id),
    CONSTRAINT fk_wallet_type FOREIGN KEY (wallet_type_id)
        REFERENCES pi_wallet_type(type_id) ON UPDATE CASCADE,
    INDEX idx_wallet_address  (pi_network_address),
    INDEX idx_wallet_type     (wallet_type_id),
    INDEX idx_wallet_active   (is_active)
) ENGINE=InnoDB COMMENT='Pi Network wallet registry';

-- ------------------------------------------------------------
-- 4. CORE ENTITY: USERS / BANK NODES
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_users (
    user_id             BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    user_uid            CHAR(36)            NOT NULL UNIQUE,
    wallet_id           BIGINT UNSIGNED     NOT NULL,
    pi_username         VARCHAR(64)         NOT NULL UNIQUE,          -- @username on Pi Network
    email               VARCHAR(255)        NULL,
    phone_hash          VARCHAR(64)         NULL,                      -- hashed for privacy
    country_code        CHAR(2)             NULL,                      -- ISO 3166-1 alpha-2
    kyc_level           TINYINT UNSIGNED    NOT NULL DEFAULT 0,        -- 0=none,1=basic,2=full
    mql_node_id         VARCHAR(64)         NULL,                      -- MQL node identifier
    is_bank_node        BOOLEAN             NOT NULL DEFAULT FALSE,
    node_region         VARCHAR(64)         NULL,
    last_login_at       DATETIME(3)         NULL,
    created_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                            ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (user_id),
    CONSTRAINT fk_user_wallet FOREIGN KEY (wallet_id)
        REFERENCES pi_wallets(wallet_id) ON UPDATE CASCADE,
    INDEX idx_user_pi_name    (pi_username),
    INDEX idx_user_node       (mql_node_id),
    INDEX idx_user_bank_node  (is_bank_node)
) ENGINE=InnoDB COMMENT='Pi Network users and bank node operators';

-- ------------------------------------------------------------
-- 5. CORE ENTITY: TRANSACTIONS
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_transactions (
    tx_id               BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    tx_uid              CHAR(36)            NOT NULL UNIQUE,           -- UUID v4
    tx_hash             VARCHAR(256)        NULL UNIQUE,               -- on-chain hash
    sender_wallet_id    BIGINT UNSIGNED     NOT NULL,
    receiver_wallet_id  BIGINT UNSIGNED     NOT NULL,
    amount_pi           DECIMAL(28, 7)      NOT NULL,
    fee_pi              DECIMAL(28, 7)      NOT NULL DEFAULT 0.0010000,
    net_amount_pi       DECIMAL(28, 7)      GENERATED ALWAYS AS
                            (amount_pi - fee_pi) STORED,
    status_id           TINYINT UNSIGNED    NOT NULL,
    tx_type             ENUM(
                            'TRANSFER',
                            'PAYMENT',
                            'ESCROW_LOCK',
                            'ESCROW_RELEASE',
                            'ESCROW_CANCEL',
                            'BANK_SETTLEMENT',
                            'REWARD',
                            'REFUND'
                        )                   NOT NULL DEFAULT 'TRANSFER',
    memo                VARCHAR(512)        NULL,
    mql_sequence        BIGINT UNSIGNED     NULL,                      -- MQL ledger sequence
    mql_ledger_ref      VARCHAR(128)        NULL,                      -- MQL ledger reference
    confirmed_at        DATETIME(3)         NULL,
    expires_at          DATETIME(3)         NULL,
    metadata_json       JSON                NULL,
    created_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                            ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (tx_id),
    CONSTRAINT fk_tx_sender   FOREIGN KEY (sender_wallet_id)
        REFERENCES pi_wallets(wallet_id) ON UPDATE CASCADE,
    CONSTRAINT fk_tx_receiver FOREIGN KEY (receiver_wallet_id)
        REFERENCES pi_wallets(wallet_id) ON UPDATE CASCADE,
    CONSTRAINT fk_tx_status   FOREIGN KEY (status_id)
        REFERENCES pi_network_status(status_id) ON UPDATE CASCADE,
    INDEX idx_tx_hash          (tx_hash),
    INDEX idx_tx_sender        (sender_wallet_id),
    INDEX idx_tx_receiver      (receiver_wallet_id),
    INDEX idx_tx_status        (status_id),
    INDEX idx_tx_type          (tx_type),
    INDEX idx_tx_created       (created_at),
    INDEX idx_tx_mql_seq       (mql_sequence)
) ENGINE=InnoDB COMMENT='Pi Network banking transactions';

-- ------------------------------------------------------------
-- 6. ESCROW CONTRACTS
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_escrow_contracts (
    escrow_id           BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    escrow_uid          CHAR(36)            NOT NULL UNIQUE,
    initiator_wallet_id BIGINT UNSIGNED     NOT NULL,
    beneficiary_wallet_id BIGINT UNSIGNED   NOT NULL,
    escrow_wallet_id    BIGINT UNSIGNED     NOT NULL,
    locked_amount_pi    DECIMAL(28, 7)      NOT NULL,
    condition_json      JSON                NOT NULL,                  -- release conditions
    status_id           TINYINT UNSIGNED    NOT NULL,
    lock_tx_id          BIGINT UNSIGNED     NULL,
    release_tx_id       BIGINT UNSIGNED     NULL,
    auto_release_at     DATETIME(3)         NULL,
    created_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    resolved_at         DATETIME(3)         NULL,
    PRIMARY KEY (escrow_id),
    CONSTRAINT fk_escrow_init   FOREIGN KEY (initiator_wallet_id)
        REFERENCES pi_wallets(wallet_id),
    CONSTRAINT fk_escrow_bene   FOREIGN KEY (beneficiary_wallet_id)
        REFERENCES pi_wallets(wallet_id),
    CONSTRAINT fk_escrow_wallet FOREIGN KEY (escrow_wallet_id)
        REFERENCES pi_wallets(wallet_id),
    CONSTRAINT fk_escrow_status FOREIGN KEY (status_id)
        REFERENCES pi_network_status(status_id),
    INDEX idx_escrow_status     (status_id),
    INDEX idx_escrow_auto_rel   (auto_release_at)
) ENGINE=InnoDB COMMENT='Pi Network escrow smart contracts';

-- ------------------------------------------------------------
-- 7. BANK NODE SETTLEMENTS
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_bank_settlements (
    settlement_id       BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    settlement_uid      CHAR(36)            NOT NULL UNIQUE,
    bank_node_user_id   BIGINT UNSIGNED     NOT NULL,
    total_pi            DECIMAL(28, 7)      NOT NULL,
    total_fiat_equiv    DECIMAL(20, 4)      NULL,
    fiat_currency       CHAR(3)             NULL DEFAULT 'USD',        -- ISO 4217
    exchange_rate       DECIMAL(20, 8)      NULL,
    settlement_batch    JSON                NULL,                      -- array of tx_ids
    status_id           TINYINT UNSIGNED    NOT NULL,
    settled_at          DATETIME(3)         NULL,
    created_at          DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (settlement_id),
    CONSTRAINT fk_settle_node   FOREIGN KEY (bank_node_user_id)
        REFERENCES pi_users(user_id),
    CONSTRAINT fk_settle_status FOREIGN KEY (status_id)
        REFERENCES pi_network_status(status_id),
    INDEX idx_settle_node       (bank_node_user_id),
    INDEX idx_settle_status     (status_id)
) ENGINE=InnoDB COMMENT='Bank node batch settlement records';

-- ------------------------------------------------------------
-- 8. MQL AUDIT / EVENT LOG
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_mql_audit_log (
    log_id              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    log_uid             CHAR(36)            NOT NULL UNIQUE,
    event_type          VARCHAR(64)         NOT NULL,                  -- 'TX_CREATE','STATUS_CHANGE', etc.
    entity_type         ENUM('WALLET','USER','TRANSACTION','ESCROW','SETTLEMENT') NOT NULL,
    entity_id           BIGINT UNSIGNED     NOT NULL,
    old_value_json      JSON                NULL,
    new_value_json      JSON                NULL,
    triggered_by_user   BIGINT UNSIGNED     NULL,
    mql_node_id         VARCHAR(64)         NULL,
    ip_address          VARCHAR(45)         NULL,                      -- IPv4/IPv6
    occurred_at         DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (log_id),
    INDEX idx_audit_entity      (entity_type, entity_id),
    INDEX idx_audit_event       (event_type),
    INDEX idx_audit_occurred    (occurred_at),
    INDEX idx_audit_node        (mql_node_id)
) ENGINE=InnoDB COMMENT='Full MQL audit trail for Pi Network banking events';

-- ------------------------------------------------------------
-- 9. STORED PROCEDURES (MQL Data Handler Routines)
-- ------------------------------------------------------------

DELIMITER $$

-- 9a. Record a new Pi Network transaction
CREATE PROCEDURE IF NOT EXISTS usp_create_pi_transaction (
    IN  p_tx_uid            CHAR(36),
    IN  p_sender_address    VARCHAR(128),
    IN  p_receiver_address  VARCHAR(128),
    IN  p_amount_pi         DECIMAL(28,7),
    IN  p_tx_type           VARCHAR(32),
    IN  p_memo              VARCHAR(512),
    OUT p_tx_id             BIGINT UNSIGNED,
    OUT p_error_msg         VARCHAR(256)
)
BEGIN
    DECLARE v_sender_id     BIGINT UNSIGNED DEFAULT NULL;
    DECLARE v_receiver_id   BIGINT UNSIGNED DEFAULT NULL;
    DECLARE v_pending_id    TINYINT UNSIGNED DEFAULT NULL;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        GET DIAGNOSTICS CONDITION 1 p_error_msg = MESSAGE_TEXT;
        SET p_tx_id = NULL;
    END;

    SET p_error_msg = NULL;

    SELECT wallet_id INTO v_sender_id
        FROM pi_wallets WHERE pi_network_address = p_sender_address AND is_active = TRUE LIMIT 1;
    SELECT wallet_id INTO v_receiver_id
        FROM pi_wallets WHERE pi_network_address = p_receiver_address AND is_active = TRUE LIMIT 1;
    SELECT status_id INTO v_pending_id
        FROM pi_network_status WHERE status_code = 'PENDING' LIMIT 1;

    IF v_sender_id IS NULL OR v_receiver_id IS NULL OR v_pending_id IS NULL THEN
        SET p_error_msg = 'Invalid sender, receiver, or status lookup';
        SET p_tx_id = NULL;
    ELSE
        START TRANSACTION;
            INSERT INTO pi_transactions
                (tx_uid, sender_wallet_id, receiver_wallet_id, amount_pi,
                 tx_type, memo, status_id)
            VALUES
                (p_tx_uid, v_sender_id, v_receiver_id, p_amount_pi,
                 p_tx_type, p_memo, v_pending_id);
            SET p_tx_id = LAST_INSERT_ID();
        COMMIT;
    END IF;
END$$

-- 9b. Update transaction status (MQL node callback)
CREATE PROCEDURE IF NOT EXISTS usp_update_tx_status (
    IN  p_tx_uid        CHAR(36),
    IN  p_tx_hash       VARCHAR(256),
    IN  p_status_code   VARCHAR(32),
    IN  p_mql_sequence  BIGINT UNSIGNED,
    OUT p_success       BOOLEAN,
    OUT p_error_msg     VARCHAR(256)
)
BEGIN
    DECLARE v_status_id     TINYINT UNSIGNED DEFAULT NULL;
    DECLARE v_tx_id         BIGINT UNSIGNED DEFAULT NULL;
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        GET DIAGNOSTICS CONDITION 1 p_error_msg = MESSAGE_TEXT;
        SET p_success = FALSE;
    END;

    SET p_error_msg = NULL;
    SET p_success   = FALSE;

    SELECT status_id INTO v_status_id
        FROM pi_network_status WHERE status_code = p_status_code LIMIT 1;
    SELECT tx_id INTO v_tx_id
        FROM pi_transactions WHERE tx_uid = p_tx_uid LIMIT 1;

    IF v_status_id IS NULL OR v_tx_id IS NULL THEN
        SET p_error_msg = 'Transaction or status not found';
    ELSE
        START TRANSACTION;
            UPDATE pi_transactions
            SET  status_id    = v_status_id,
                 tx_hash      = COALESCE(p_tx_hash, tx_hash),
                 mql_sequence = COALESCE(p_mql_sequence, mql_sequence),
                 confirmed_at = CASE WHEN p_status_code = 'CONFIRMED'
                                     THEN NOW(3) ELSE confirmed_at END
            WHERE tx_id = v_tx_id;
            SET p_success = TRUE;
        COMMIT;
    END IF;
END$$

-- 9c. Get wallet balance summary
CREATE PROCEDURE IF NOT EXISTS usp_get_wallet_balance (
    IN  p_pi_address    VARCHAR(128)
)
BEGIN
    SELECT
        w.pi_network_address,
        w.display_name,
        w.balance_pi,
        w.balance_locked_pi,
        (w.balance_pi - w.balance_locked_pi)    AS available_pi,
        wt.type_code                            AS wallet_type,
        w.kyc_verified,
        w.updated_at
    FROM pi_wallets w
    JOIN pi_wallet_type wt ON wt.type_id = w.wallet_type_id
    WHERE w.pi_network_address = p_pi_address
      AND w.is_active = TRUE
    LIMIT 1;
END$$

DELIMITER ;

-- ------------------------------------------------------------
-- 10. VIEWS FOR MQL REPORTING
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW vw_pi_transaction_summary AS
SELECT
    t.tx_uid,
    t.tx_hash,
    sw.pi_network_address           AS sender_address,
    rw.pi_network_address           AS receiver_address,
    t.amount_pi,
    t.fee_pi,
    t.net_amount_pi,
    t.tx_type,
    s.status_code                   AS status,
    t.memo,
    t.mql_sequence,
    t.mql_ledger_ref,
    t.confirmed_at,
    t.created_at
FROM pi_transactions t
JOIN pi_wallets       sw ON sw.wallet_id = t.sender_wallet_id
JOIN pi_wallets       rw ON rw.wallet_id = t.receiver_wallet_id
JOIN pi_network_status s ON s.status_id  = t.status_id;

CREATE OR REPLACE VIEW vw_pi_bank_node_stats AS
SELECT
    u.pi_username,
    u.mql_node_id,
    u.node_region,
    w.pi_network_address,
    w.balance_pi,
    COUNT(t.tx_id)                  AS total_transactions,
    COALESCE(SUM(t.amount_pi), 0)   AS total_volume_pi,
    MAX(t.created_at)               AS last_tx_at
FROM pi_users u
JOIN pi_wallets w ON w.wallet_id = u.wallet_id
LEFT JOIN pi_transactions t ON
    (t.sender_wallet_id = w.wallet_id OR t.receiver_wallet_id = w.wallet_id)
WHERE u.is_bank_node = TRUE
GROUP BY u.user_id, u.pi_username, u.mql_node_id, u.node_region,
         w.pi_network_address, w.balance_pi;

-- ------------------------------------------------------------
-- 11. INDEXES FOR MQL QUERY PERFORMANCE
-- ------------------------------------------------------------

-- Composite index for time-range transaction queries (MQL analytics)
CREATE INDEX IF NOT EXISTS idx_tx_status_created
    ON pi_transactions (status_id, created_at DESC);

-- Covering index for audit trail lookups
CREATE INDEX IF NOT EXISTS idx_audit_entity_event
    ON pi_mql_audit_log (entity_type, entity_id, event_type, occurred_at DESC);

-- ------------------------------------------------------------
-- 12. SCHEMA VERSION TRACKING
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pi_schema_version (
    version_id      INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    version         VARCHAR(16)         NOT NULL,
    description     VARCHAR(256)        NOT NULL,
    applied_at      DATETIME(3)         NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    applied_by      VARCHAR(64)         NOT NULL DEFAULT 'system',
    PRIMARY KEY (version_id)
) ENGINE=InnoDB COMMENT='MQL database schema migration tracker';

INSERT INTO pi_schema_version (version, description, applied_by) VALUES
    ('2.0.0', 'Initial MQL database body file for Pi Network banking data handler', 'pi-nexus-autonomous-banking-network');

-- ============================================================
-- END OF SCHEMA BODY FILE
-- pi_network_banking_db.sql  |  v2.0.0
-- ============================================================