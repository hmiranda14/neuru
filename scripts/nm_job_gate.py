# NEURU — Python cron gate. Mirrors nm_jobs.php::nm_job_should_run so the "Scheduled Jobs" tab in
# net_mon_config.php controls the Python pollers too (enable/interval). FAIL-OPEN: any gate error
# returns True (a bookkeeping hiccup must never stop core monitoring). Uses the caller's cur/db and
# commits its own writes (pollers run autocommit=False).
def should_run(cur, db, job):
    try:
        cur.execute("""CREATE TABLE IF NOT EXISTS nm_job_schedule (
            job VARCHAR(64) NOT NULL PRIMARY KEY, enabled TINYINT(1) NOT NULL DEFAULT 1,
            interval_min INT NOT NULL DEFAULT 0, last_run DATETIME NULL, last_result VARCHAR(20) NULL,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        cur.execute("SELECT enabled, interval_min, last_run FROM nm_job_schedule WHERE job=%s LIMIT 1", (job,))
        row = cur.fetchone()
        if row is None:
            cur.execute("INSERT IGNORE INTO nm_job_schedule (job,enabled,interval_min,last_run,last_result) VALUES (%s,1,0,NOW(),'run')", (job,))
            db.commit(); return True
        enabled = int(row[0]); iv = int(row[1] or 0); last_run = row[2]
        if enabled != 1:
            cur.execute("UPDATE nm_job_schedule SET last_result='disabled' WHERE job=%s", (job,)); db.commit(); return False
        if iv > 0 and last_run is not None:
            cur.execute("SELECT 1 FROM nm_job_schedule WHERE job=%s AND last_run > (NOW() - INTERVAL " + str(iv) + " MINUTE) LIMIT 1", (job,))
            if cur.fetchone() is not None:
                return False
        cur.execute("UPDATE nm_job_schedule SET last_run=NOW(), last_result='run' WHERE job=%s", (job,)); db.commit(); return True
    except Exception:
        try: db.rollback()
        except Exception: pass
        return True
