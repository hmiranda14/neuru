# ─────────────────────────────────────────────────────────────────────────────
# NEURU — per-node MAINTENANCE filter for the Python collectors.
#
# A node in maintenance must NOT be polled (no data gathered). Every collector adds
# maint_clause(cur) to its node-selection WHERE so maintenance nodes are skipped.
# The clause is emitted ONLY when the `maintenance_until` column exists (older installs
# may not have migrated yet) → a collector never crashes on an un-migrated DB.
#
# PHP side / single source of truth: nm_maintenance.php.
# ─────────────────────────────────────────────────────────────────────────────

_MAINT_COL = None   # cached column-existence check (per process)


def maint_clause(cur, alias=''):
    """Return ' AND (<node not in maintenance>)' for use in a WHERE, or '' if the
    maintenance_until column doesn't exist yet. `alias` = the nm_nodes alias, if any."""
    global _MAINT_COL
    if _MAINT_COL is None:
        try:
            cur.execute("SELECT COUNT(*) FROM information_schema.COLUMNS "
                        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_nodes' "
                        "AND COLUMN_NAME='maintenance_until'")
            _MAINT_COL = bool(cur.fetchone()[0])
        except Exception:
            _MAINT_COL = False
    if not _MAINT_COL:
        return ''
    p = (alias + '.') if alias else ''
    return " AND ({0}maintenance_until IS NULL OR {0}maintenance_until <= NOW())".format(p)
