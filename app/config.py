# config.py
import os
import secrets

class Config:
    SECRET_KEY = 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///project.db'  # Change the database name here
    WTF_CSRF_SECRET_KEY = secrets.token_hex(16)   # Generate a 32-character (16 bytes) random key
     # Google OAuth2 credentials
    GOOGLE_CLIENT_ID = "999580736360-5dhtpti24rdful6tooq3nprj1eppvq2p.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET = "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"
    


    # Token expiration time (in seconds). Adjust according to your requirements.
    JWT_ACCESS_TOKEN_EXPIRES = 3600 
 
