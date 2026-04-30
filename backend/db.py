import sqlite3
from contextlib import contextmanager
from typing import Any, Generator


def _dict_factory(cursor: sqlite3.Cursor, row: tuple[Any, ...]) -> dict[str, Any]:
    return {column[0]: row[index] for index, column in enumerate(cursor.description)}


@contextmanager
def get_connection(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    connection = sqlite3.connect(db_path)
    connection.row_factory = _dict_factory
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
    finally:
        connection.close()


def execute_query(
    db_path: str,
    query: str,
    params: tuple[Any, ...] = (),
    fetchone: bool = False,
    fetchall: bool = False,
) -> Any:
    with get_connection(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute(query, params)
        result: Any = None
        if fetchone:
            result = cursor.fetchone()
        elif fetchall:
            result = cursor.fetchall()
        connection.commit()
        return result
