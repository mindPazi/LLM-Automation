import os
import json
import requests
from datetime import datetime

API_KEY = "sk-proj-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"
GITHUB_TOKEN = "ghp_16CharacterGitHubToken1234567890ABCDEF"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

TEST_API_KEY = "test-api-key-123"
EXAMPLE_TOKEN = "your-token-here"
PLACEHOLDER_SECRET = "INSERT_YOUR_SECRET_HERE"
DEMO_PASSWORD = "demo123"

DATABASE_URL = "postgresql://user:RealPassword123!@localhost:5432/mydb"
MONGODB_URI = "mongodb://admin:AdminPass456$@cluster0.mongodb.net/mydb"
MYSQL_CONN = "mysql://root:MyS3cur3P@ss!@localhost:3306/database"
REDIS_URL = "redis://:Redis2025Password!@redis-server:6379/0"

TEST_DB_URL = "postgresql://test:test@localhost/testdb"
DEV_DATABASE = "mongodb://dev:password@localhost/devdb"
EXAMPLE_CONNECTION = "mysql://user:password123@localhost/db"
LOCAL_REDIS = "redis://localhost:6379"

STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcTYooMQauvdEDq54"
PAYPAL_CLIENT_SECRET = "EBWKjlELKMYqRNQ6sYvFo64FtaRLRR5BdHEESmha49TM"
SENDGRID_API_KEY = "SG.actual_sendgrid_key_with_lots_of_characters_1234567890"
TWILIO_AUTH_TOKEN = "actual_twilio_auth_token_32_chars_long_12345678"

STRIPE_TEST_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
SAMPLE_API_KEY = "sample-key-12345"
MOCK_TOKEN = "mock_token_for_testing"
FAKE_SECRET = "fake_secret_value"

def configure_production():
    os.environ['JWT_SECRET'] = "jwt_secret_key_f47ac10b_58cc_4372_a567_0e02b2c3d479"
    os.environ['ENCRYPTION_KEY'] = "aes256key_32bytes_long_key_here12345678"
    os.environ['ADMIN_PASSWORD'] = "Admin@2025!SuperSecure"
    os.environ['MASTER_KEY'] = "master_key_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"

def configure_testing():
    os.environ['JWT_SECRET'] = "test_jwt_secret"
    os.environ['ENCRYPTION_KEY'] = "test_encryption_key"
    os.environ['ADMIN_PASSWORD'] = "test123"
    os.environ['MASTER_KEY'] = "test_master_key"

private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmno
-----END RSA PRIVATE KEY-----"""

test_cert = """-----BEGIN CERTIFICATE-----
TEST CERTIFICATE DATA
-----END CERTIFICATE-----"""

config = {
    "production": {
        "api_key": "prod_api_key_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z",
        "secret": "prod_secret_7f4df045_b3a7_4298_9f3e_8c5d6e7f8a9b",
        "password": "ProdPassword2025!Secure",
        "db_password": "PostgresAdmin2025!@#"
    },
    "development": {
        "api_key": "dev-api-key",
        "secret": "dev-secret",
        "password": "devpassword",
        "db_password": "password123"
    },
    "test": {
        "api_key": "test-key",
        "secret": "test-secret",
        "password": "test",
        "db_password": "test"
    }
}

BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
BASIC_AUTH = "Basic YWRtaW46UGFzc3dvcmQxMjMh"
API_HEADER = "X-API-Key: actual_api_key_x9y8z7w6v5u4t3s2r1q0p9o8"

TEST_BEARER = "Bearer test-token"
EXAMPLE_AUTH = "Basic dXNlcjpwYXNzd29yZA=="
SAMPLE_HEADER = "X-API-Key: sample-key"

def get_credentials():
    return {
        "facebook_app_secret": "fb_secret_key_a1b2c3d4e5f6g7h8i9j0k1l2m3n4",
        "google_client_secret": "GOCSPX-1234567890abcdefghijklmnop",
        "twitter_api_secret": "twitter_secret_key_50_chars_long_1234567890abcdef",
        "instagram_access_token": "IGQVJYeUk0123456789abcdefghijklmnopqrstuvwxyz"
    }

def get_test_credentials():
    return {
        "facebook_app_secret": "test_facebook_secret",
        "google_client_secret": "test_google_secret",
        "twitter_api_secret": "test_twitter_secret",
        "instagram_access_token": "test_instagram_token"
    }

PASSWORD_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
SALT_VALUE = "random_salt_value_12345"
IV_VALUE = "1234567890123456"

TEST_HASH = "098f6bcd4621d373cade4e832627b4f6"
TEST_SALT = "salt123"
TEST_IV = "0000000000000000"

FINAL_PRODUCTION_SECRET = "this_is_the_final_production_key_abc123def456"
FINAL_TEST_SECRET = "this_is_a_test_secret"
