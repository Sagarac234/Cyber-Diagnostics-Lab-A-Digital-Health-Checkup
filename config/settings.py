"""
Configuration for Web Security Scanner
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration"""
    
    # API Settings
    API_HOST = '0.0.0.0'
    API_PORT = 5000
    API_DEBUG = False
    
    # Database Settings
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'scans.db')
    DATABASE_BACKUP_PATH = os.path.join(BASE_DIR, 'database', 'scans_backup.db')
    
    # Scanner Settings
    SCANNER_TIMEOUT = 30
    SCANNER_MAX_CONCURRENT = 5
    SCANNER_VERIFY_SSL = False
    
    # API Keys
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    NVD_API_KEY = os.getenv('NVD_API_KEY')
    
    # Retention Policy
    SCAN_RETENTION_DAYS = 90
    AUTO_CLEANUP = True

    # Email Settings (SMTP)
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')


class DevelopmentConfig(Config):
    """Development configuration"""
    API_DEBUG = True


class ProductionConfig(Config):
    """Production configuration"""
    API_DEBUG = False
    SCANNER_VERIFY_SSL = True


class TestingConfig(Config):
    """Testing configuration"""
    DATABASE_PATH = ':memory:'
    API_DEBUG = True
