"""
Large test file with mixed secrets and false positives for testing secret detection.
This file contains various patterns to test both detection and filtering capabilities.
Author: Test Suite
Date: 2025-01-28
"""

import os
import requests
import json
import base64
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import hashlib
import hmac

# ============= CONFIGURATION SECTION =============
# Real secrets that should be detected
PRODUCTION_DATABASE_URL = "postgresql://prod_user:SuperSecret123!@db.production.com:5432/maindb"
STAGING_DB_PASSWORD = "St@g1ng_P@ssw0rd_2025!"

# API Keys - these should definitely be caught
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcTYooMQauvdEDq54"
GITHUB_TOKEN = "ghp_16CharacterGitHubToken1234567890ABCDEF"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# OAuth tokens
GOOGLE_CLIENT_SECRET = "GOCSPX-1234567890abcdefghijklmnop"
FACEBOOK_APP_SECRET = "fb_secret_key_a1b2c3d4e5f6g7h8i9j0k1l2m3n4"

# Private keys (should be detected)
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop
qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ==
-----END RSA PRIVATE KEY-----"""

# ============= FALSE POSITIVES SECTION =============
# These should NOT be detected as real secrets

# Test values (should be filtered)
TEST_API_KEY = "test_api_key_12345"
DEMO_PASSWORD = "demo_password_here"
SAMPLE_TOKEN = "sample_token_value"
EXAMPLE_SECRET = "example_secret_123"
MOCK_API_KEY = "mock_api_key_for_testing"

# Placeholder values
API_KEY_PLACEHOLDER = "your_api_key_here"
SECRET_PLACEHOLDER = "<YOUR_SECRET_HERE>"
TOKEN_PLACEHOLDER = "xxx_replace_this_xxx"
PASSWORD_PLACEHOLDER = "changeme"

# Common words that might trigger false positives
api_documentation = "This is documentation about API keys and how to use them"
password_requirements = "Password must be at least 8 characters, including uppercase, lowercase, and numbers"
secret_sauce = "The secret sauce of our application is the algorithm"
token_bucket = "We use a token bucket algorithm for rate limiting"

# Configuration with environment variables (not secrets)
DATABASE_URL = "${DATABASE_URL}"
API_KEY = "%(API_KEY)s"
SECRET_KEY = "{{SECRET_KEY}}"

# ============= MIXED CONTEXT SECTION =============
class UserAuthentication:
    """User authentication handler with various credential types"""
    
    def __init__(self):
        # Real secret embedded in code
        self.admin_password = "Admin@2025!SuperSecure#Pass"
        self.jwt_secret = "jwt_secret_key_f47ac10b_58cc_4372_a567_0e02b2c3d479"
        
        # False positives - test values
        self.test_user_password = "test_password_123"
        self.demo_api_key = "demo_key_for_testing"
        
        # Environment-based (should not be detected)
        self.db_password = os.environ.get('DB_PASSWORD', 'default_password')
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user with credentials"""
        # Hardcoded credentials (bad practice, should be detected)
        if username == "admin" and password == "P@ssw0rd2025!Admin":
            return True
        
        # Another real secret
        master_key = "master_key_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
        
        # False positive - it's a hash, not a secret
        password_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        
        # Comparison with test values (false positive)
        if password == "test" or password == "demo" or password == "example":
            return False
        
        return self._verify_password(password, password_hash)
    
    def _verify_password(self, password: str, hash_value: str) -> bool:
        """Verify password against hash"""
        # This is a salt, not a secret
        salt = "random_salt_value_12345"
        return hashlib.sha256((password + salt).encode()).hexdigest() == hash_value

# ============= API CLIENT SECTION =============
class APIClient:
    """API client with various authentication methods"""
    
    # Class-level secrets (should be detected)
    MAILGUN_API_KEY = "key-3ax6xnjp29jd6fds4gc373sgvjxteol0"
    SENDGRID_API_KEY = "SG.actual_sendgrid_key_with_lots_of_characters_1234567890"
    TWILIO_AUTH_TOKEN = "actual_twilio_auth_token_32_chars_long_12345678"
    
    def __init__(self):
        # Mixed real and fake secrets
        self.endpoints = {
            'production': {
                'url': 'https://api.production.com',
                'key': 'prod_api_key_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z',  # Real
                'secret': 'prod_secret_7f4df045_b3a7_4298_9f3e_8c5d6e7f8a9b'  # Real
            },
            'staging': {
                'url': 'https://api.staging.com',
                'key': 'staging_test_key_not_real',  # Fake - contains "test"
                'secret': 'staging_demo_secret_value'  # Fake - contains "demo"
            },
            'development': {
                'url': 'http://localhost:8000',
                'key': 'dev_key_example_123',  # Fake - contains "example"
                'secret': 'dev_secret_sample_456'  # Fake - contains "sample"
            }
        }
        
        # Bearer tokens
        self.bearer_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        
        # API keys with specific patterns
        self.slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
        self.discord_webhook = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz1234567890"

    def make_request(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make API request with authentication"""
        headers = {
            'Authorization': f'Bearer {self.bearer_token}',
            'X-API-Key': 'actual_api_key_x9y8z7w6v5u4t3s2r1q0p9o8',  # Real secret
            'X-Client-Secret': 'client_secret_m7n8b9v0c1x2z3a4s5d6f7g8h9j0'  # Real secret
        }
        
        # Database connection strings (real secrets)
        mysql_conn = "mysql://root:MySecurePassword123!@localhost:3306/myapp"
        mongo_conn = "mongodb://admin:AdminPass456$@cluster0.mongodb.net/mydb"
        redis_conn = "redis://:MyRedisPassword789@redis-server:6379/0"
        
        # False positives - URLs without credentials
        public_api = "https://api.publicservice.com/v1/data"
        webhook_url = "https://example.com/webhook/callback"
        
        return {'status': 'success'}

# ============= CONFIGURATION FILES SECTION =============
# Simulating various config file formats

# JSON-like configuration
json_config = '''
{
    "database": {
        "host": "db.example.com",
        "username": "db_user",
        "password": "ActualDBPassword2025!@#",
        "port": 5432
    },
    "api_keys": {
        "stripe": "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
        "sendgrid": "SG.real_sendgrid_api_key_with_many_characters",
        "aws_access": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "test_config": {
        "test_key": "test_value_123",
        "demo_secret": "demo_secret_value",
        "example_token": "example_token_here"
    }
}
'''

# YAML-like configuration
yaml_config = """
production:
  database:
    password: ProdPassword2025!Secure
  api:
    key: prod_api_key_aB3dE5fG7hI9jK1lM3nO5pQ7rS9t
    secret: prod_secret_xY9zA1bC2dE3fG4hI5jK6lM7nO8p
  
development:
  database:
    password: test_password_not_real
  api:
    key: dev_test_key_example
    secret: dev_demo_secret_sample
"""

# ============= CRYPTOGRAPHIC OPERATIONS =============
class CryptoHandler:
    """Handle cryptographic operations"""
    
    # Encryption keys (should be detected)
    AES_KEY = "aes256key_32bytes_long_key_here12345678"
    HMAC_SECRET = "hmac_secret_key_for_signing_tokens_abc123"
    
    # Initialization vectors and salts (might be false positives)
    IV = "1234567890123456"  # 16 bytes IV
    SALT = "salt_value_for_hashing"
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        # Real encryption key
        encryption_key = "encryption_master_key_256_bits_long_abc123def456"
        
        # These are algorithms names, not secrets
        cipher_suite = "AES-256-GCM"
        hash_algorithm = "SHA-256"
        
        # Nonce (not really a secret)
        nonce = "unique_nonce_12345"
        
        return base64.b64encode(data.encode()).decode()
    
    def sign_token(self, payload: Dict[str, Any]) -> str:
        """Sign JWT token"""
        # Real JWT secret
        jwt_secret = "super_secret_jwt_key_for_signing_tokens_2025"
        
        # Algorithm identifier (not a secret)
        algorithm = "HS256"
        
        # Token header (not a secret)
        header = {"alg": algorithm, "typ": "JWT"}
        
        return "signed.jwt.token"

# ============= DATABASE OPERATIONS =============
class DatabaseManager:
    """Database connection manager"""
    
    def __init__(self):
        # Real database credentials
        self.connections = {
            'postgres': {
                'host': 'postgres.prod.example.com',
                'user': 'postgres_admin',
                'password': 'PostgresAdmin2025!@#$',
                'database': 'production_db'
            },
            'mysql': {
                'host': 'mysql.prod.example.com',
                'user': 'mysql_root',
                'password': 'MySQLRoot2025!@#$%',
                'database': 'app_database'
            },
            'mongodb': {
                'uri': 'mongodb://mongouser:MongoPass2025!@mongodb.example.com:27017/appdb'
            }
        }
        
        # Connection strings with embedded credentials
        self.conn_strings = [
            "postgresql://user:Pass123!@localhost/db",
            "mysql://admin:AdminPass456$@mysql-server/appdb",
            "redis://:RedisPassword789@redis-cluster:6379/0",
            "mongodb+srv://user:UserPass2025@cluster.mongodb.net/mydb"
        ]
        
        # False positives - template strings
        self.template_conn = "postgresql://username:password@host:port/database"
        self.example_conn = "mysql://example_user:example_pass@example.com/example_db"
    
    def get_connection(self, db_type: str):
        """Get database connection"""
        if db_type == 'production':
            # Hardcoded production password (bad!)
            return self._connect("prod_host", "prod_user", "ProdPassword2025!@#$%^&*")
        elif db_type == 'test':
            # Test environment (false positive)
            return self._connect("test_host", "test_user", "test_password_123")
        
    def _connect(self, host: str, user: str, password: str):
        """Internal connection method"""
        pass

# ============= THIRD-PARTY INTEGRATIONS =============
class ThirdPartyIntegrations:
    """Various third-party service integrations"""
    
    # Payment providers
    STRIPE_SECRET_KEY = "sk_live_51HqmkK2eZvKYlo2C0123456789abcdefghijklmnop"
    PAYPAL_CLIENT_SECRET = "EBWKjlELKMYqRNQ6sYvFo64FtaRLRR5BdHEESmha49TM"
    SQUARE_ACCESS_TOKEN = "sq0atp-ABCDEFGHIJKLMNOPQRSTUVWXYZ123"
    
    # Cloud providers
    AZURE_CLIENT_SECRET = "azure_client_secret_8f7g6h5j4k3l2m1n0p9q8r7s"
    GCP_SERVICE_ACCOUNT_KEY = '''
    {
        "type": "service_account",
        "project_id": "my-project",
        "private_key_id": "key123",
        "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC12345\\n-----END PRIVATE KEY-----\\n",
        "client_email": "service@project.iam.gserviceaccount.com"
    }
    '''
    
    # Communication services
    TWILIO_ACCOUNT_SID = "ACa1234567890abcdef1234567890abcd"
    TWILIO_AUTH_TOKEN = "auth_token_32_characters_long_12345"
    SENDGRID_API_KEY = "SG.actualSendGridAPIKeyWithManyChars1234567890"
    MAILCHIMP_API_KEY = "abcdef1234567890abcdef1234567890-us1"
    
    # Social media
    TWITTER_API_KEY = "twitter_api_key_25_chars_long_12345"
    TWITTER_API_SECRET = "twitter_api_secret_50_characters_long_1234567890abc"
    FACEBOOK_ACCESS_TOKEN = "EAACEdEose0cBAGlBb8ZATJ1r8UblZBQ123456789"
    INSTAGRAM_ACCESS_TOKEN = "IGQVJYeUk0123456789abcdefghijklmnopqrstuvwxyz"
    
    # Analytics and monitoring
    GOOGLE_ANALYTICS_KEY = "UA-123456789-1"
    MIXPANEL_TOKEN = "mixpanel_project_token_32_chars_long"
    DATADOG_API_KEY = "datadog_api_key_32_characters_long_"
    DATADOG_APP_KEY = "datadog_app_key_40_characters_long_12345"
    
    # False positives - documentation and examples
    api_docs = """
    To use our API, you need to obtain an API key from the dashboard.
    The API key format is: 'api_key_' followed by 32 random characters.
    Example: api_key_abcdefghijklmnopqrstuvwxyz123456
    
    Never share your secret keys. Keep them secure.
    Rotate your passwords regularly.
    Use environment variables for sensitive tokens.
    """
    
    # Test and development keys (false positives)
    test_stripe_key = "sk_test_1234567890abcdefghijklmnop"
    dev_api_key = "dev_api_key_for_testing_only"
    localhost_secret = "localhost_secret_not_for_production"
    dummy_token = "dummy_token_1234567890"
    fake_password = "fake_password_for_documentation"

# ============= LOGGING AND DEBUGGING =============
def debug_function():
    """Function with debug information"""
    
    # Debug logs that might contain secrets
    print(f"Connecting with password: ActualPassword123!")  # Bad practice
    
    # Logging configuration
    log_config = {
        'api_key': 'logging_api_key_abc123def456ghi789jkl',  # Real
        'endpoint': 'https://logs.example.com',
        'debug_mode': True,
        'test_key': 'test_logging_key_not_real'  # False positive
    }
    
    # Debug variables (mixed)
    debug_vars = {
        'real_token': 'debug_token_aB3dE5fG7hI9jK1lM3nO5pQ7',
        'test_token': 'test_debug_token_123',
        'example_key': 'example_debug_key_456'
    }
    
    # SQL queries with embedded passwords (bad!)
    sql_query = "SELECT * FROM users WHERE password = 'HardcodedPass2025!'"
    connection_string = "Server=myServer;Database=myDB;User Id=sa;Password=MyPass@word1;"

# ============= ENVIRONMENT CONFIGURATION =============
# Simulating .env file content
env_content = """
# Production environment variables
DATABASE_URL=postgresql://prod_user:ProdPassword2025!@db.example.com:5432/proddb
REDIS_URL=redis://:RedisPass2025!@redis.example.com:6379/0
SECRET_KEY=production_secret_key_very_long_and_secure_abc123def456
API_KEY=prod_api_key_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v

# Development environment (false positives)
DEV_DATABASE_URL=postgresql://dev:dev_password@localhost:5432/devdb
TEST_API_KEY=test_api_key_not_real
DEMO_SECRET=demo_secret_for_testing
EXAMPLE_TOKEN=example_token_value

# Third-party services
STRIPE_KEY=sk_live_actualStripeKeyWith43Characters1234567
GITHUB_TOKEN=ghp_actualGitHubTokenWith40CharactersLong123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Comments and documentation (should not be detected)
# The format for API keys is: api_key_[32 random characters]
# Password must contain uppercase, lowercase, numbers and special characters
# Never commit real secrets to version control
"""

# ============= FINAL MIXED SECTION =============
# Random code with various patterns

def process_payment(amount: float, card_number: str):
    """Process payment with Stripe"""
    stripe_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dcTYooMQauvdEDq"  # Real
    
    # Card processing (PCI compliance - these might be sensitive)
    card_data = {
        'number': '4111111111111111',  # Test card number
        'exp_month': 12,
        'exp_year': 2025,
        'cvc': '123'  # Test CVC
    }
    
    # Merchant credentials
    merchant_id = "merchant_1234567890"
    merchant_secret = "merchant_secret_key_abc123def456ghi789"  # Real
    
    return {'success': True}

# Configuration dictionary with mixed content
config = {
    'production': {
        'debug': False,
        'secret_key': 'prod_secret_key_50_characters_long_with_random_',  # Real
        'database': {
            'password': 'ProdDBPassword2025!@#$%',  # Real
            'connection_pool': 10
        }
    },
    'testing': {
        'debug': True,
        'secret_key': 'test_secret_key_not_real',  # False positive
        'database': {
            'password': 'test_db_password',  # False positive
            'connection_pool': 5
        }
    },
    'api_endpoints': {
        'auth': 'https://api.example.com/auth',
        'data': 'https://api.example.com/data'
    },
    'credentials': {
        'admin': {
            'username': 'admin',
            'password': 'AdminPassword2025!@#$',  # Real
            'api_key': 'admin_api_key_abc123def456ghi789jkl012'  # Real
        },
        'test_user': {
            'username': 'test',
            'password': 'test_password_123',  # False positive
            'api_key': 'test_api_key_example'  # False positive
        }
    }
}

# List of various tokens and keys
tokens_list = [
    "real_token_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3x",  # Real
    "test_token_not_real_123",  # False positive
    "demo_token_example_456",  # False positive
    "actual_production_token_with_high_entropy_xyz789",  # Real
    "sample_token_for_documentation",  # False positive
    "jwt.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",  # Real JWT
    "mock_jwt_token_for_testing",  # False positive
]

# Dictionary comprehension with secrets
api_keys = {
    service: f"api_key_{service}_{os.urandom(16).hex()}"
    for service in ['stripe', 'paypal', 'square']
}

# Lambda functions with embedded secrets
get_password = lambda env: "ProdPass2025!" if env == "prod" else "test_pass"
get_api_key = lambda: "real_api_key_aB3dE5fG7hI9jK1lM3nO5pQ7rS9t"

# Final constants
FINAL_SECRET = "this_is_the_final_secret_key_with_high_entropy_abc123"
FINAL_PASSWORD = "FinalPassword2025!@#$%^&*()"
FINAL_TOKEN = "final_bearer_token_with_sufficient_length_and_entropy"

# Comments that should not trigger detection
"""
Documentation:
- API keys should be stored in environment variables
- Passwords must be hashed before storage
- Tokens should be rotated regularly
- Secrets should never be committed to git
- Use secret management services in production
- Test with fake_password and example_token values
- Never use real credentials in demo or sample code
"""

# End of test file
print("Test file loaded successfully")
