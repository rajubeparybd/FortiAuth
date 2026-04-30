from pathlib import Path

from backend.config import load_config
from backend.models import initialize_schema


def main() -> None:
    config = load_config()
    db_file = Path(config.database_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    initialize_schema(config.database_path)
    print(f"Database initialized at {db_file}")


if __name__ == "__main__":
    main()
