from os import getenv
from typing import Optional

from bson import ObjectId
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pymongo import MongoClient, IndexModel
from datetime import datetime, timedelta
from dotenv import load_dotenv

from crypto import encrypt, decrypt

app = FastAPI()

# Load environment variables from .env file
load_dotenv()

# Read MongoDB connection details from environment variables
MONGODB_HOST = getenv('MONGODB_HOST', 'localhost')
MONGODB_PORT = getenv('MONGODB_PORT', '27017')
MONGODB_DATABASE = getenv('MONGODB_DATABASE', 'onetime_secrets')

# MongoDB setup
mongo_client = MongoClient(
    f"mongodb://{MONGODB_HOST}:{MONGODB_PORT}/",
    username=getenv('MONGODB_USERNAME'),
    password=getenv('MONGODB_PASSWORD'),
)
db = mongo_client[MONGODB_DATABASE]
db_col = db['secrets']

# Create a TTL indexes with the desired expiration time
ttl_index = IndexModel([("expiration_time", 1)], expireAfterSeconds=0)
db_col.create_indexes([ttl_index])


class SecretGenerateRequest(BaseModel):
    """Model for request body."""
    secret: str
    pass_phrase: str
    expiration_minutes: Optional[int] = None


class SecretResponse(BaseModel):
    secret_key: str


class SecretRetrieveRequest(BaseModel):
    pass_phrase: str


@app.post('/generate', response_model=SecretResponse)
async def generate_secret(request: SecretGenerateRequest):
    """Route to save a secret and generate a secret key."""

    # Store secret with expiration time (30 minutes in this example)
    expiration_time = datetime.utcnow() + timedelta(minutes=30)
    secret_data = {
        'secret': encrypt(request.secret, getenv('ENCRYPTION_KEY')),
        'pass_phrase': encrypt(request.pass_phrase, getenv('ENCRYPTION_KEY')),
    }
    if request.expiration_minutes:
        secret_data['expiration_time'] = datetime.utcnow() + timedelta(minutes=request.expiration_minutes)
    result = db_col.insert_one(secret_data)

    # Return secret key
    secret_key = str(result.inserted_id)
    return {'secret_key': secret_key}


@app.post('/secrets/{secret_key}', response_model=dict)
async def retrieve_secret(secret_key: str, request: SecretRetrieveRequest):
    """Route to retrieve a secret using a secret key"""

    # Retrieve secret from the database
    secret_data = db_col.find_one({'_id': ObjectId(secret_key)})
    if secret_data is None:
        raise HTTPException(status_code=404, detail='Secret not found')

    # Check expiration time
    expiration_time = secret_data.get('expiration_time')
    if expiration_time and expiration_time < datetime.utcnow():
        raise HTTPException(status_code=404, detail='Secret has expired')

    # Check pass phrase
    if request.pass_phrase != decrypt(secret_data['pass_phrase'], getenv('ENCRYPTION_KEY')):
        raise HTTPException(status_code=403, detail='Invalid pass phrase')

    decrypted_secret = decrypt(secret_data['secret'], getenv('ENCRYPTION_KEY'))
    db_col.delete_one({'_id': ObjectId(secret_key)})
    return {'secret': decrypted_secret}
