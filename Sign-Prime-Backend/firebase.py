import os
import firebase_admin
from firebase_admin import credentials, firestore, storage
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Prevent duplicate initialization
if not firebase_admin._apps:

    cred = credentials.Certificate({
        "type": "service_account",
        "project_id": os.getenv("FIREBASE_PROJECT_ID"),
        "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
        "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
        "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
        "client_id": os.getenv("FIREBASE_CLIENT_ID"),
        "token_uri": "https://oauth2.googleapis.com/token",
    })

    firebase_admin.initialize_app(cred, {
        "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET")
    })

# Firestore Database
db = firestore.client()

# Firebase Storage Bucket
bucket = storage.bucket()