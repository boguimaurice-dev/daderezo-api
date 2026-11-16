"""Daily maintenance: python audit_maintenance.py --days 90"""
import argparse
import storage

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Purge audit entries older than the retention period")
    parser.add_argument("--days", type=int, default=90)
    args = parser.parse_args()
    storage.init_db()
    storage.purge_audit_logs(args.days)
