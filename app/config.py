"""
Configuration classes for the NIDS application.
Supports different environments (development, testing, production).
"""

import os
from pathlib import Path
from datetime import timedelta


basedir = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration with common settings."""

    # Basic Flask config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production-2024'

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'sqlite:///{basedir / "database" / "nids.db"}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    # Session config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # No time limit for CSRF tokens

    # Rate Limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"

    # File Upload
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size
    UPLOAD_FOLDER = basedir / 'uploads'
    ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

    # ML Models - Using models_file directory
    MODEL_DIR = Path(os.environ.get('MODEL_DIR',
        basedir / 'models' / 'models_file'))
    MODEL_PATH = MODEL_DIR / 'xgboost_model.pkl'
    SCALER_PATH = MODEL_DIR / 'scaler.pkl'
    FEATURES_PATH = MODEL_DIR / 'features.pkl'

    # Packet Capture
    DEFAULT_INTERFACE = os.environ.get('DEFAULT_INTERFACE', 'eth0')
    PACKET_QUEUE_SIZE = 5000
    FLOW_TIMEOUT_SECONDS = 2.0
    FLOW_CLEAN_INTERVAL = 2.0
    MAX_TRACKED_FLOWS = 100000

    # SocketIO
    SOCKETIO_CORS_ALLOWED_ORIGINS = '*'
    SOCKETIO_ASYNC_MODE = 'threading'
    STATS_UPDATE_INTERVAL = 3.0

    # Logging
    LOG_DIR = basedir / 'logs'
    LOG_FILE = LOG_DIR / 'app.log'
    SECURITY_LOG_FILE = LOG_DIR / 'security.log'
    ML_LOG_FILE = LOG_DIR / 'ml.log'
    NETWORK_LOG_FILE = LOG_DIR / 'network.log'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5

    # Export
    EXPORT_DIR = basedir / 'exports'

    # Security
    BCRYPT_LOG_ROUNDS = 12
    PASSWORD_MIN_LENGTH = 8
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=30)

    # Pagination
    ALERTS_PER_PAGE = 50
    USERS_PER_PAGE = 20

    @staticmethod
    def init_app(app):
        """Initialize application-specific configuration."""
        # Create required directories
        for directory in [
            Config.UPLOAD_FOLDER,
            Config.LOG_DIR,
            Config.EXPORT_DIR,
            basedir / 'database'
        ]:
            Path(directory).mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    TESTING = False
    WTF_CSRF_ENABLED = False  # Disable CSRF in development for easier testing


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    BCRYPT_LOG_ROUNDS = 4  # Faster password hashing in tests


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    TESTING = False

    # Stricter security in production
    SESSION_COOKIE_SECURE = True  # Requires HTTPS
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = True

    # Use stronger password hashing
    BCRYPT_LOG_ROUNDS = 14

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # Log to syslog in production (optional)
        import logging
        from logging.handlers import SysLogHandler
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
