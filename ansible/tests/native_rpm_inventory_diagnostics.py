#!/usr/bin/env python3
"""Read-only native RPM diagnostics; never an inventory acceptance substitute.

Capture physical database changes and all parsed package fields around actual
production queries, then repeat while observing SQLite commits on one read-only
connection. This helper neither repairs the database nor changes its journal
mode. The VM controller still rejects the original incomplete inventory.
"""
import hashlib
import importlib.util
import json
import os
import sqlite3
from datetime import datetime, timezone
from urllib.parse import quote


def main():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scripts", "hcp-package-inventory.py")
    spec = importlib.util.spec_from_file_location("native_package_diagnostics", path)
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    result = {"scope": "read-only diagnostics; not acceptance", "rpmVersion": collector.run(["rpm", "--version"]),
              "queries": [], "sqliteQueries": [], "sqliteErrors": []}
    try:
        database = collector.resolve_rpm_database()
        result["rpmDatabase"] = database
    except (OSError, ValueError) as exc:
        result["configurationError"] = str(exc)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return

    def database_paths():
        return [path for path in database["candidates"] if os.path.isfile(path)]

    def physical_snapshot():
        values = []
        for entry in database_paths():
            for path in (entry, entry + "-wal", entry + "-shm", entry + "-journal"):
                try:
                    stat = os.stat(path)
                    values.append({"path": path, "realpath": os.path.realpath(path), "dev": stat.st_dev,
                                   "ino": stat.st_ino, "size": stat.st_size, "mtimeNs": stat.st_mtime_ns,
                                   "ctimeNs": stat.st_ctime_ns})
                except FileNotFoundError:
                    values.append({"path": path, "missing": True})
        return values

    def package_processes():
        processes = []
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/" + pid + "/comm") as stream:
                    name = stream.read().strip()
                if name in ("rpm", "dnf", "yum", "packagekitd", "rpmdb"):
                    processes.append({"pid": int(pid), "comm": name})
            except OSError:
                pass
        return processes

    def query(observers=()):
        item = {"startedAt": datetime.now(timezone.utc).isoformat(), "before": physical_snapshot(),
                "processesBefore": package_processes(), "sqliteBefore": []}
        for path, connection in observers:
            item["sqliteBefore"].append({"path": path, "dataVersion": connection.execute("PRAGMA data_version").fetchone()[0]})
        packages, error = collector.rpm_packages(database)
        canonical = sorted(json.dumps(package, sort_keys=True, separators=(",", ":")) for package in packages)
        item.update({"packageCount": len(packages), "error": error,
                     "packagesSha256": hashlib.sha256("\n".join(canonical).encode("utf-8")).hexdigest(),
                     "after": physical_snapshot(), "processesAfter": package_processes(), "sqliteAfter": []})
        for path, connection in observers:
            item["sqliteAfter"].append({"path": path, "dataVersion": connection.execute("PRAGMA data_version").fetchone()[0]})
        item["finishedAt"] = datetime.now(timezone.utc).isoformat()
        return item

    result["queries"] = [query(), query()]
    observers = []
    try:
        for path in sorted(set(os.path.realpath(path) for path in database_paths() if path.endswith("rpmdb.sqlite"))):
            try:
                connection = sqlite3.connect("file:" + quote(path, safe="/") + "?mode=ro", uri=True, timeout=5, isolation_level=None)
                observers.append((path, connection))
            except sqlite3.Error as exc:
                result["sqliteErrors"].append({"path": path, "error": str(exc)})
        if observers:
            result["sqliteQueries"] = [query(observers), query(observers)]
    except sqlite3.Error as exc:
        result["sqliteErrors"].append({"error": str(exc)})
    finally:
        for path, connection in observers:
            connection.close()
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
