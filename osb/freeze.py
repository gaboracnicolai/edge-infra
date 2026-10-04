"""Provisioning freeze: one database flag the API and the worker both honour.

See osb/migrations/0004_freeze.sql for how an operator sets it and why it is a
database row rather than a replica count.
"""

from __future__ import annotations


async def is_frozen(conn, *, lock: bool = False) -> bool:
    """True while osb_freeze.frozen is set.

    ``lock=True`` reads the row FOR SHARE: run inside the worker's apply
    transaction it makes a concurrent freezing UPDATE wait for the apply to
    commit, and every apply that starts after the UPDATE commits sees it.
    """
    sql = "SELECT frozen FROM osb_freeze" + (" FOR SHARE" if lock else "")
    return await conn.fetchval(sql) is True
