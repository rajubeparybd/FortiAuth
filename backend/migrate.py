from pathlib import Path
import sqlite3

from backend.config import load_config


def run_migrations() -> None:
    config = load_config()
    db_path = Path(config.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    migration_dir = Path(__file__).parent / "migrations"
    sql_files = sorted(migration_dir.glob("*.sql"))
    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.cursor()
        for sql_file in sql_files:
            script = sql_file.read_text(encoding="utf-8")
            cursor.executescript(script)
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    run_migrations()
    print("Migrations applied successfully.")
