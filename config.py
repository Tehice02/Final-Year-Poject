import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(
    BASE_DIR, "database", "nids.db"
)

