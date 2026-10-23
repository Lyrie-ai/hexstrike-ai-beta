"""SQLite transactions with deterministic connection cleanup."""
from contextlib import contextmanager
import sqlite3


@contextmanager
def database_connection(database, **options):
    connection = sqlite3.connect(database, **options)
    try:
        with connection:
            yield connection
    finally:
        connection.close()
