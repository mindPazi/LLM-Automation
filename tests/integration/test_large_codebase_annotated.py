import os
import json
import requests
from datetime import datetime

API_KEY = "sk-proj-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"  # TRUE - real secret format
GITHUB_TOKEN = "ghp_16CharacterGitHubToken1234567890ABCDEF"  # TRUE - real GitHub token format
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # FALSE - AWS example key
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # FALSE - AWS example key

TEST_API_KEY = "test-api-key-123"  # FALSE - test key
EXAMPLE_TOKEN = "your-token-here"  # FALSE - placeholder
PLACEHOLDER_SECRET = "INSERT_YOUR_SECRET_HERE"  # FALSE - placeholder
DEMO_PASSWORD = "demo123"  # FALSE - demo password

DATABASE_URL = "postgresql://user:RealPassword123!@localhost:5432/mydb"  # TRUE - real password format
MONGODB_URI = "mongodb://admin:AdminPass456$@cluster0.mongodb.net/mydb"  # TRUE - real password format
MYSQL_CONN = "mysql://root:MyS3cur3P@ss!@localhost:3306/database"  # TRUE - real password format
REDIS_URL = "redis://:Redis2025Password!@redis-server:6379/0"  # TRUE - real password format

TEST_DB_URL = "postgresql://test:test@localhost/testdb"  # FALSE - test credentials
DEV_DATABASE = "mongodb://dev:password@localhost/devdb"  # FALSE - dev credentials
EXAMPLE_CONNECTION = "mysql://user:password123@localhost/db"  # FALSE - example credentials
LOCAL_REDIS = "redis://localhost:6379"  # FALSE - no password

STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcTYooMQauvdEDq54"  # TRUE - live Stripe key
PAYPAL_CLIENT_SECRET = "EBWKjlELKMYqRNQ6sYvFo64FtaRLRR5BdHEESmha49TM"  # TRUE - real secret format
SENDGRID_API_KEY = "SG.actual_sendgrid_key_with_lots_of_characters_1234567890"  # TRUE - real API key format
TWILIO_AUTH_TOKEN = "actual_twilio_auth_token_32_chars_long_12345678"  # TRUE - real auth token format

STRIPE_TEST_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"  # FALSE - test key
SAMPLE_API_KEY = "sample-key-12345"  # FALSE - sample key
MOCK_TOKEN = "mock_token_for_testing"  # FALSE - mock token
FAKE_SECRET = "fake_secret_value"  # FALSE - fake secret

def configure_production():
    os.environ['JWT_SECRET'] = "jwt_secret_key_f47ac10b_58cc_4372_a567_0e02b2c3d479"  # TRUE - real JWT secret format
    os.environ['ENCRYPTION_KEY'] = "aes256key_32bytes_long_key_here12345678"  # TRUE - real encryption key format
    os.environ['ADMIN_PASSWORD'] = "Admin@2025!SuperSecure"  # TRUE - real password format
    os.environ['MASTER_KEY'] = "master_key_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"  # TRUE - real master key format

def configure_testing():
    os.environ['JWT_SECRET'] = "test_jwt_secret"  # FALSE - test secret
    os.environ['ENCRYPTION_KEY'] = "test_encryption_key"  # FALSE - test key
    os.environ['ADMIN_PASSWORD'] = "test123"  # FALSE - test password
    os.environ['MASTER_KEY'] = "test_master_key"  # FALSE - test key

private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmno
-----END RSA PRIVATE KEY-----"""  # TRUE - private key (even if truncated)

test_cert = """-----BEGIN CERTIFICATE-----
TEST CERTIFICATE DATA
-----END CERTIFICATE-----"""  # FALSE - test certificate

config = {
    "production": {
        "api_key": "prod_api_key_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z",  # TRUE - production API key
        "secret": "prod_secret_7f4df045_b3a7_4298_9f3e_8c5d6e7f8a9b",  # TRUE - production secret
        "password": "ProdPassword2025!Secure",  # TRUE - production password
        "db_password": "PostgresAdmin2025!@#"  # TRUE - production DB password
    },
    "development": {
        "api_key": "dev-api-key",  # FALSE - dev key
        "secret": "dev-secret",  # FALSE - dev secret
        "password": "devpassword",  # FALSE - dev password
        "db_password": "password123"  # FALSE - simple password
    },
    "test": {
        "api_key": "test-key",  # FALSE - test key
        "secret": "test-secret",  # FALSE - test secret
        "password": "test",  # FALSE - test password
        "db_password": "test"  # FALSE - test password
    }
}

BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"  # TRUE - real JWT token
BASIC_AUTH = "Basic YWRtaW46UGFzc3dvcmQxMjMh"  # TRUE - real Basic auth with encoded password
API_HEADER = "X-API-Key: actual_api_key_x9y8z7w6v5u4t3s2r1q0p9o8"  # TRUE - real API key format

TEST_BEARER = "Bearer test-token"  # FALSE - test token
EXAMPLE_AUTH = "Basic dXNlcjpwYXNzd29yZA=="  # FALSE - example auth (user:password)
SAMPLE_HEADER = "X-API-Key: sample-key"  # FALSE - sample key

def get_credentials():
    return {
        "facebook_app_secret": "fb_secret_key_a1b2c3d4e5f6g7h8i9j0k1l2m3n4",  # TRUE - real secret format
        "google_client_secret": "GOCSPX-1234567890abcdefghijklmnop",  # TRUE - real Google secret format
        "twitter_api_secret": "twitter_secret_key_50_chars_long_1234567890abcdef",  # TRUE - real secret format
        "instagram_access_token": "IGQVJYeUk0123456789abcdefghijklmnopqrstuvwxyz"  # TRUE - real Instagram token format
    }

def get_test_credentials():
    return {
        "facebook_app_secret": "test_facebook_secret",  # FALSE - test secret
        "google_client_secret": "test_google_secret",  # FALSE - test secret
        "twitter_api_secret": "test_twitter_secret",  # FALSE - test secret
        "instagram_access_token": "test_instagram_token"  # FALSE - test token
    }

PASSWORD_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # FALSE - hash, not a secret
SALT_VALUE = "random_salt_value_12345"  # FALSE - salt, not a secret
IV_VALUE = "1234567890123456"  # FALSE - IV, not a secret

TEST_HASH = "098f6bcd4621d373cade4e832627b4f6"  # FALSE - test hash
TEST_SALT = "salt123"  # FALSE - test salt
TEST_IV = "0000000000000000"  # FALSE - test IV

FINAL_PRODUCTION_SECRET = "this_is_the_final_production_key_abc123def456"  # TRUE - production secret
FINAL_TEST_SECRET = "this_is_a_test_secret"  # FALSE - test secret
