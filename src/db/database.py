import os
import shutil
import random
import threading
import contextlib
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session

Base = declarative_base()

# ── 6 NEW NORMALIZED TABLES + BACKWARD COMPATIBLE TABLES ─────────────────────

class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    username      = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    role          = Column(String(50), nullable=False)
    totp_secret   = Column(String(100), nullable=True)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class AuditReport(Base):
    __tablename__ = "audit_reports"
    id                = Column(Integer, primary_key=True, autoincrement=True)
    session_id        = Column(String(100), unique=True, index=True) # maps to UI's UUID session_id
    session_title     = Column(String(300))
    auditee_id        = Column(Integer, nullable=True) # maps to User.id (nullable if created anonymously)
    framework         = Column(String(100)) # ISO 27001, SOC 2, NIST, GDPR
    controls_selected = Column(Text) # JSON serialized list of control integers
    status            = Column(String(50), default="Draft") # Draft, Pending Review, Reviewed, Approved, Rejected
    created_at             = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    reviewed_at            = Column(DateTime, nullable=True)
    requires_scoping_review = Column(Boolean, default=False)
    scoping_note           = Column(Text, nullable=True)

class EvidenceFile(Base):
    __tablename__ = "evidence_files"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    report_id   = Column(Integer, index=True) # links to audit_reports.id
    filename    = Column(String(200))
    file_path   = Column(Text)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    status      = Column(String(50), default="Pending")
    is_auditor_uploaded = Column(Boolean, default=False, server_default="false")

class Finding(Base):
    __tablename__ = "findings"
    id                    = Column(Integer, primary_key=True, autoincrement=True)
    report_id             = Column(Integer, index=True) # links to audit_reports.id
    control_id            = Column(String(100)) # e.g. A.12.6.1
    control_name          = Column(String(200)) # e.g. Access Restriction
    severity              = Column(String(100)) # P1 Critical -> P4 Low
    description           = Column(Text) # finding description details
    gap_detected          = Column(Text) # detected gap text
    relevance_score       = Column(Integer, default=0)
    evidence_found        = Column(String(100))
    evidence_snippet      = Column(Text)
    recommendation        = Column(Text)
    reasoning             = Column(Text)
    status                = Column(String(100), default="Non-Compliant") # Compliant, Partially Compliant, Non-Compliant, Out Of Scope
    source_files          = Column(Text)
    created_at            = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    
    # Strict Forensic Auditor Fields
    standard              = Column(String(300), nullable=True)
    clause                = Column(String(300), nullable=True)
    evidence_quote        = Column(Text, nullable=True)
    evidence_location     = Column(Text, nullable=True)
    gap_description       = Column(Text, nullable=True)
    confidence            = Column(Integer, nullable=True)
    hallucination_check   = Column(String(50), nullable=True)
    document_type_match   = Column(Boolean, nullable=True)
    post_process_override = Column(String(10), nullable=True)
    requires_human_review = Column(Boolean, default=False)
    review_note           = Column(Text, nullable=True)
    human_verified        = Column(Boolean, default=False)
    verified_by           = Column(String(100), nullable=True)
    verified_date         = Column(DateTime, nullable=True)
    finding_is_final      = Column(Boolean, default=True)
    chunk_id              = Column(Integer, nullable=True)
    evidence_state        = Column(String(100), nullable=True)
    evidence_source_file  = Column(Text, nullable=True)
    evidence_source_type  = Column(String(100), nullable=True)
    evidence_page_number  = Column(Integer, nullable=True)
    evidence_row_number   = Column(Integer, nullable=True)
    evidence_slide_number = Column(Integer, nullable=True)
    evidence_image_id     = Column(String(200), nullable=True)

class AuditRecord(Base):
    """Auditor review log containing review outcomes and comments."""
    __tablename__ = "audit_records"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    report_id   = Column(Integer, index=True) # links to audit_reports.id
    auditor_id  = Column(Integer, nullable=True) # links to User.id
    status      = Column(String(50)) # Approved, Rejected, Reviewed
    comments    = Column(Text)
    reviewed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class ComplianceScore(Base):
    __tablename__ = "compliance_scores"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    report_id     = Column(Integer, index=True) # links to audit_reports.id
    framework     = Column(String(100))
    score_percent = Column(Integer)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

# ── BACKWARD COMPATIBILITY & UTILITY TABLES ──────────────────────────────────
class AuditCheckpoint(Base):
    """Mid-audit progress checkpoints for crash-resilience."""
    __tablename__ = "audit_checkpoints"
    id                   = Column(Integer, primary_key=True, autoincrement=True)
    session_id           = Column(String(100), index=True)
    bg_key               = Column(String(100))
    ai_model             = Column(String(200))
    selected_sls_json    = Column(Text)
    file_names_json      = Column(Text)
    context_text         = Column(Text)
    total_controls       = Column(Integer, default=0)
    completed_batches    = Column(Integer, default=0)
    batch_size           = Column(Integer, default=10)
    partial_results_json = Column(Text, default="[]")
    status               = Column(String(50), default="in_progress")
    created_at           = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at           = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class ChatMessage(Base):
    """General chat history for the AI Assistant view."""
    __tablename__ = "chat_messages"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    session_id    = Column(String(100))
    session_title = Column(String(300))
    role          = Column(String(50))
    content       = Column(Text)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class DocumentChunk(Base):
    """Stores text paragraph chunks of processed policies for RAG search."""
    __tablename__ = "document_chunks"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    filename      = Column(String(200), index=True)
    chunk_index   = Column(Integer)
    content       = Column(Text)
    metadata_json = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    # Production provenance columns (Phase 1 — multi-doc ingestion)
    source_file   = Column(Text, nullable=True)        # original upload filename
    source_type   = Column(String(50), nullable=True)  # pdf, docx, xlsx, csv, pptx, txt, png, jpg
    chunk_id      = Column(String(200), nullable=True) # unique chunk hash/id for dedup
    page_number   = Column(Integer, nullable=True)     # for PDF/PPTX
    row_number    = Column(Integer, nullable=True)     # for XLSX/CSV
    slide_number  = Column(Integer, nullable=True)     # for PPTX
    image_id      = Column(String(200), nullable=True) # for PNG/JPG
    section_heading = Column(String(500), nullable=True) # heading context

class AuditorFeedback(Base):
    """Stores auditor review decisions and overrides for in-context learning."""
    __tablename__ = "auditor_feedback"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    control_id       = Column(String(100), index=True)
    evidence_snippet = Column(Text, nullable=True)
    corrected_status = Column(String(50))
    finding          = Column(Text, nullable=True)
    recommendation   = Column(Text, nullable=True)
    auditor_comments = Column(Text, nullable=True)
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class AuditTrail(Base):
    __tablename__ = "audit_trail"
    id                    = Column(Integer, primary_key=True, autoincrement=True)
    audit_id              = Column(String(100), index=True)
    document_name         = Column(String(255))
    standard              = Column(String(50))
    model_used            = Column(String(100))
    run_date              = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    total_controls        = Column(Integer)
    grounded_compliant    = Column(Integer)
    correct_non_compliant = Column(Integer)
    hallucinated          = Column(Integer)
    real_accuracy         = Column(Integer)
    full_report           = Column(Text) # JSON serialized string
    is_deleted            = Column(Boolean, default=False)
    deleted_at            = Column(DateTime, nullable=True)


class SystemEvent(Base):
    """Privacy-safe system event log. Never stores company names, document content, or finding text."""
    __tablename__ = "system_events"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(100), nullable=False)
    # FORCE_SAVE, AUDIT_COMPLETE, AUDIT_CRASH, REPLICATION_ERROR,
    # DB_CONNECT_ERROR, OLLAMA_ERROR, FAILOVER, SCHEMA_ERROR, STATUS_CHANGE
    actor      = Column(String(100), nullable=False)   # username or "SYSTEM"
    session_id = Column(String(100), nullable=True)
    framework  = Column(String(100), nullable=True)    # ISO 27001, SOC 2, etc.
    meta       = Column(Text, nullable=True)           # JSON: counts + short error msg only
    severity   = Column(String(20), default="INFO")    # INFO | WARNING | ERROR | CRITICAL
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


def _log_db_event(event_type: str, meta: dict = None, severity: str = "ERROR"):
    """
    Write a SystemEvent directly using the master engine.
    Called from within database.py itself to avoid circular imports.
    Never stores company names, document content, or finding text.
    """
    import json as _json
    global engine_master, promoted_master_engine
    _engine = promoted_master_engine or engine_master
    if _engine is None:
        return  # DB not yet initialised — skip silently
    try:
        from sqlalchemy.orm import sessionmaker as _sm
        _Session = _sm(bind=_engine)
        _db = _Session()
        _db.add(SystemEvent(
            event_type=event_type,
            actor="SYSTEM",
            meta=_json.dumps(meta) if meta else None,
            severity=severity,
        ))
        _db.commit()
        _db.close()
    except Exception:
        pass  # Never crash on logging failure



# ── ROUTING CONTROLS ────────────────────────────────────────────────────────
_routing_state = threading.local()

@contextlib.contextmanager
def force_master():
    """Forces the active thread to route all database actions to the MASTER engine."""
    old = getattr(_routing_state, "force_master", False)
    _routing_state.force_master = True
    try:
        yield
    finally:
        _routing_state.force_master = old

# ── MASTER-SLAVE ENGINES & FAILOVER ──────────────────────────────────────────
engine_master = None
engine_slave1 = None
engine_slave2 = None
promoted_master_engine = None
db_label = "ShaktiDB"

# Slave health tracking for load balancing
slaves_health = {"Slave 1": True, "Slave 2": True}
slaves_health_lock = threading.Lock()

import queue
import time

_replication_queue = queue.Queue()
_replication_pending_flag = False
_replication_flag_lock = threading.Lock()

def _execute_replicate_changes():
    """Actual synchronous replication work to target engines."""
    global promoted_master_engine
    if engine_master is None or engine_slave1 is None or engine_slave2 is None:
        return

    # Determine source and target engines
    if promoted_master_engine is None:
        targets = [("Slave 1", engine_slave1), ("Slave 2", engine_slave2)]
        src_engine = engine_master
    else:
        # Slave 1 is promoted to master, replicate only to Slave 2
        targets = [("Slave 2", engine_slave2)]
        src_engine = engine_slave1

    import concurrent.futures

    replication_errors = {}

    def sync_to_target(target_name, target_engine):
        try:
            with target_engine.begin() as dest_conn:
                # Disable constraints and triggers on target
                dest_conn.execute(text("SET session_replication_role = 'replica';"))
                
                with src_engine.connect() as src_conn:
                    # Clean all existing rows on target in reverse-dependency order
                    # using DELETE FROM instead of TRUNCATE TABLE CASCADE to avoid AccessExclusiveLocks.
                    # This prevents deadlock conflicts with active reader transactions.
                    for table in reversed(Base.metadata.sorted_tables):
                        dest_conn.execute(text(f'DELETE FROM "{table.name}";'))
                        
                    for table in Base.metadata.sorted_tables:
                        table_name = table.name
                        # Read all rows from source
                        rows = src_conn.execute(text(f'SELECT * FROM "{table_name}"')).fetchall()
                        
                        if rows:
                            # Construct INSERT
                            columns = rows[0]._fields if hasattr(rows[0], '_fields') else list(rows[0].keys())
                            col_names = ", ".join(f'"{col}"' for col in columns)
                            placeholders = ", ".join(f":{col}" for col in columns)
                            insert_sql = text(f'INSERT INTO "{table_name}" ({col_names}) VALUES ({placeholders})')
                            
                            data = [dict(row._mapping) for row in rows]
                            dest_conn.execute(insert_sql, data)
                            
                            # Reset sequence if id column is present
                            if "id" in columns:
                                seq_sql = text(f"SELECT setval(pg_get_serial_sequence('\"{table_name}\"', 'id'), coalesce(max(id), 1)) FROM \"{table_name}\";")
                                dest_conn.execute(seq_sql)
                
                dest_conn.execute(text("SET session_replication_role = 'origin';"))
            print(f"[REPLICATION SUCCESS] Synced Master -> {target_name}")
            with slaves_health_lock:
                slaves_health[target_name] = True
        except Exception as e:
            print(f"[REPLICATION ERROR] Failed to sync to {target_name}: {e}")
            with slaves_health_lock:
                slaves_health[target_name] = False
            replication_errors[target_name] = str(e)
            _log_db_event(
                "REPLICATION_ERROR",
                meta={"target": target_name, "error": str(e)[:300]},
                severity="CRITICAL"
            )

    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as executor:
            futures = [executor.submit(sync_to_target, name, eng) for name, eng in targets]
            concurrent.futures.wait(futures)

    if replication_errors:
        raise RuntimeError(f"Replication failed on targets: {replication_errors}")


def _replication_worker_loop():
    global _replication_pending_flag
    while True:
        task = _replication_queue.get()
        if task is None:
            break
        
        # Debounce briefly to coalesce multiple rapid commits
        time.sleep(0.1)
        
        with _replication_flag_lock:
            _replication_pending_flag = False
            
        try:
            _execute_replicate_changes()
        except Exception as e:
            print(f"[ASYNC REPLICATION WARNING] Background replication task failed: {e}", flush=True)
            
        _replication_queue.task_done()

# Start background daemon thread
_replicate_worker = threading.Thread(target=_replication_worker_loop, daemon=True)
_replicate_worker.start()


def replicate_changes():
    """Asynchronously triggers database replication to slave engines."""
    global _replication_pending_flag
    with _replication_flag_lock:
        if _replication_pending_flag:
            return
        _replication_pending_flag = True
    
    _replication_queue.put(True)

def reconcile_schemas(engine):
    """
    Checks if existing tables match the required SQLAlchemy models.
    If a table is missing expected columns, it drops the table so create_all can recreate it correctly.
    """
    from sqlalchemy import inspect
    inspector = inspect(engine)
    tables_to_check = ["users", "audit_reports", "findings", "evidence_files", "audit_records", "compliance_scores", "document_chunks", "auditor_feedback", "audit_trail", "system_events"]
    
    # We want to check columns for each table
    for table_name in tables_to_check:
        if inspector.has_table(table_name):
            existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
            
            # Find the model class
            model_cls = None
            for mapper in Base.registry.mappers:
                if mapper.persist_selectable.name == table_name:
                    model_cls = mapper.class_
                    break
            
            if model_cls:
                # Get columns declared in model
                expected_cols = {col.name for col in model_cls.__table__.columns}
                migration_success = True  # default; only set False if ALTER TABLE fails
                
                # Check if all expected columns are in existing columns
                missing_cols = expected_cols - existing_cols
                if missing_cols:
                    print(f"[SCHEMA RECONCILIATION] Table '{table_name}' is missing columns {missing_cols}. Attempting safe migration (ALTER TABLE)...")
                    try:
                        with engine.begin() as conn:
                            for col_name in missing_cols:
                                col_obj = model_cls.__table__.columns[col_name]
                                type_str = str(col_obj.type)
                                if "VARCHAR" in type_str:
                                    type_str = "VARCHAR(300)" if "300" in type_str else ("VARCHAR(200)" if "200" in type_str else ("VARCHAR(100)" if "100" in type_str else "VARCHAR(50)"))
                                elif type_str == "INTEGER":
                                    type_str = "INTEGER"
                                elif type_str == "BOOLEAN":
                                    type_str = "BOOLEAN"
                                elif type_str == "TEXT":
                                    type_str = "TEXT"
                                elif "DATETIME" in type_str or "TIMESTAMP" in type_str:
                                    type_str = "TIMESTAMP"
                                
                                default_clause = ""
                                if col_obj.default is not None:
                                    if hasattr(col_obj.default, 'arg') and isinstance(col_obj.default.arg, bool):
                                        default_clause = f" DEFAULT {'TRUE' if col_obj.default.arg else 'FALSE'}"
                                
                                alter_sql = f'ALTER TABLE "{table_name}" ADD COLUMN "{col_name}" {type_str}{default_clause}'
                                print(f"[MIGRATION EXECUTE] {alter_sql}")
                                conn.execute(text(alter_sql))
                    except Exception as migrate_err:
                        print(f"[SCHEMA RECONCILIATION ERROR] ALTER TABLE migration failed for '{table_name}': {migrate_err}. Falling back to DROP/RECREATE...")
                        migration_success = False
                        
                # ── AUTO-WIDEN VARCHAR COLUMNS ──────────────────────────
                # Check if any existing VARCHAR columns need widening
                try:
                    with engine.begin() as conn:
                        for col_name in existing_cols & expected_cols:
                            col_obj = model_cls.__table__.columns.get(col_name)
                            if col_obj is None:
                                continue
                            model_type = col_obj.type
                            # Get current column info from inspector
                            db_col_info = None
                            for db_col in inspector.get_columns(table_name):
                                if db_col["name"] == col_name:
                                    db_col_info = db_col
                                    break
                            if db_col_info is None:
                                continue
                            db_type = db_col_info.get("type")
                            # Case 1: Model says Text but DB has VARCHAR → widen to TEXT
                            if isinstance(model_type, Text) and hasattr(db_type, 'length') and db_type.length is not None:
                                alter_sql = f'ALTER TABLE "{table_name}" ALTER COLUMN "{col_name}" TYPE TEXT'
                                print(f"[SCHEMA WIDEN] {alter_sql}")
                                conn.execute(text(alter_sql))
                            # Case 2: Model says String(N) and DB has VARCHAR(M) where M < N → widen
                            elif isinstance(model_type, String) and model_type.length is not None:
                                if hasattr(db_type, 'length') and db_type.length is not None:
                                    if db_type.length < model_type.length:
                                        alter_sql = f'ALTER TABLE "{table_name}" ALTER COLUMN "{col_name}" TYPE VARCHAR({model_type.length})'
                                        print(f"[SCHEMA WIDEN] {alter_sql}")
                                        conn.execute(text(alter_sql))
                except Exception as widen_err:
                    print(f"[SCHEMA WIDEN WARNING] Failed to widen columns for '{table_name}': {widen_err}")

                if not migration_success:
                    try:
                        with engine.begin() as conn:
                            if engine.dialect.name == "postgresql":
                                conn.execute(text(f"DROP TABLE IF EXISTS {table_name} CASCADE"))
                            else:
                                conn.execute(text(f"DROP TABLE IF EXISTS {table_name}"))
                    except Exception as drop_err:
                        print(f"[SCHEMA RECONCILIATION WARNING] Failed to drop table {table_name}: {drop_err}")

def init_db():
    global engine_master, engine_slave1, engine_slave2, db_label
    
    # Initialize connection engines for the master and slave databases first (lazy connections)
    eng_m = create_engine(
        "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb_master",
        connect_args={"connect_timeout": 3},
        pool_pre_ping=True
    )
    eng_s1 = create_engine(
        "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb_slave1",
        connect_args={"connect_timeout": 3},
        pool_pre_ping=True
    )
    eng_s2 = create_engine(
        "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb_slave2",
        connect_args={"connect_timeout": 3},
        pool_pre_ping=True
    )

    # Quick check if database and tables already exist and are initialized
    try:
        with eng_m.connect() as conn:
            conn.execute(text("SELECT 1 FROM users LIMIT 1"))
        # Database and tables exist, skip bootstrap and reconciliation
        engine_master = eng_m
        engine_slave1 = eng_s1
        engine_slave2 = eng_s2
        db_label = "ShaktiDB"
        return eng_m, "ShaktiDB"
    except Exception:
        pass

    # Fallback: Bootstrapping and schema creation
    # Connect to the default 'shakthidb' database on port 15234 to bootstrap databases if they do not exist
    try:
        bootstrap_eng = create_engine(
            "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb",
            connect_args={"connect_timeout": 3},
            pool_pre_ping=True
        )
        with bootstrap_eng.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
            for db_name in ["shakthidb_master", "shakthidb_slave1", "shakthidb_slave2"]:
                try:
                    c.execute(text(f"CREATE DATABASE {db_name}"))
                except Exception:
                    pass
        bootstrap_eng.dispose()
    except Exception as bootstrap_err:
        print(f"[DATABASE BOOTSTRAP WARNING] Could not bootstrap databases: {bootstrap_err}")
    
    # Reconcile schemas and create tables on all engines
    reconcile_schemas(eng_m)
    reconcile_schemas(eng_s1)
    reconcile_schemas(eng_s2)
    
    Base.metadata.create_all(bind=eng_m)
    Base.metadata.create_all(bind=eng_s1)
    Base.metadata.create_all(bind=eng_s2)
    
    engine_master = eng_m
    engine_slave1 = eng_s1
    engine_slave2 = eng_s2
    db_label = "ShaktiDB"
    
    # Run user role migration
    try:
        migrated = False
        with eng_m.begin() as conn:
            # Rename 'reviewer' role to 'auditee'
            res = conn.execute(text("SELECT count(*) FROM users WHERE role = 'reviewer'")).scalar()
            if res and res > 0:
                conn.execute(text("UPDATE users SET role = 'auditee' WHERE role = 'reviewer'"))
                migrated = True
        if migrated:
            replicate_changes()
    except Exception as e:
        print(f"[INIT DB MIGRATION WARNING] Failed to migrate user roles: {e}")
        
    # Seed default admin if missing or if totp_secret is empty
    try:
        import hashlib
        admin_pw_hash = hashlib.sha256(b"admin123").hexdigest()
        admin_seeded_or_updated = False
        with eng_m.begin() as conn:
            admin = conn.execute(text("SELECT id, totp_secret FROM users WHERE username = 'admin'")).first()
            if not admin:
                conn.execute(
                    text("INSERT INTO users (username, password_hash, role, totp_secret) VALUES ('admin', :pw_hash, 'admin', 'ADMI2FASHRDSECRT')"),
                    {"pw_hash": admin_pw_hash}
                )
                admin_seeded_or_updated = True
                print("[INIT DB] Seeded default admin user with TOTP secret.")
            elif not admin[1]:  # admin.totp_secret is index 1
                conn.execute(
                    text("UPDATE users SET totp_secret = 'ADMI2FASHRDSECRT' WHERE username = 'admin'")
                )
                admin_seeded_or_updated = True
                print("[INIT DB] Updated default admin user with TOTP secret.")
        if admin_seeded_or_updated:
            replicate_changes()
    except Exception as e:
        print(f"[INIT DB ADMIN SEEDING WARNING] Failed to seed default admin: {e}")
        
    return eng_m, "ShaktiDB"

# Initialize single global connection layout
engine, db_label = init_db()

# ── ROUTING SESSION & SYNCHRONOUS REPLICATION ────────────────────────────────
class RoutingSession(Session):
    def get_bind(self, mapper=None, clause=None, **kw):
        global promoted_master_engine
        
        # Identify if current statement is a WRITE operation
        is_write = False
        if self._flushing:
            is_write = True
        elif clause is not None:
            from sqlalchemy.sql.expression import Insert, Update, Delete
            if isinstance(clause, (Insert, Update, Delete)):
                is_write = True
                
        # Force MASTER routing on WRITE or explicit context flag
        if is_write or getattr(_routing_state, "force_master", False):
            if promoted_master_engine is not None:
                return promoted_master_engine
            return engine_master
            
        # READ operations: Load-balance across healthy active replicas
        with slaves_health_lock:
            healthy_slaves = []
            if promoted_master_engine is None:
                if slaves_health.get("Slave 1"):
                    healthy_slaves.append(engine_slave1)
                if slaves_health.get("Slave 2"):
                    healthy_slaves.append(engine_slave2)
            else:
                if slaves_health.get("Slave 2"):
                    healthy_slaves.append(engine_slave2)
                    
        # Fallback to master/active replica if all are marked unhealthy
        if not healthy_slaves:
            if promoted_master_engine is not None:
                return promoted_master_engine
            return engine_master
            
        return random.choice(healthy_slaves)

    def commit(self):
        global promoted_master_engine
        try:
            super().commit()
            replicate_changes()
        except Exception as e:
            # Automated Failover: If Master fails (not replication), promote Slave 1 to Master
            if "Replication failed" not in str(e):
                if promoted_master_engine is None:
                    print(f"[FAILOVER PROMOTION] Master database write failed: {e}. Promoting Slave 1 to Master...")
                    promoted_master_engine = engine_slave1
                    # Log the failover event
                    _log_db_event(
                        "FAILOVER",
                        meta={"error": str(e)[:300], "action": "Slave 1 promoted to Master"},
                        severity="CRITICAL"
                    )
                    try:
                        self.rollback()
                    except Exception:
                        pass
            raise e

SessionLocal = sessionmaker(class_=RoutingSession)


def get_db_session():
    """Returns a new RoutingSession instance bound to the active engine.
    Caller is responsible for session.close().
    Usage::
        session = get_db_session()
        try:
            ...do work...
            session.commit()
        finally:
            session.close()
    """
    session = SessionLocal()
    session.bind = engine
    return session


def purge_old_logs(days=90):
    """
    Purges SystemEvent rows older than `days` days from the database.
    """
    from datetime import datetime, timedelta
    cutoff = datetime.now() - timedelta(days=days)
    db = SessionLocal()
    try:
        with force_master():
            deleted_count = db.query(SystemEvent).filter(SystemEvent.created_at < cutoff).delete()
            db.commit()
            return deleted_count
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
