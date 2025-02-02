from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from pymongo import MongoClient
import bcrypt
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to MongoDB
MONGO_URI = "mongodb://localhost:27017"
client = MongoClient(MONGO_URI)
db = client["user_password"]
collection = db["users"]  # Store user information

# Retrieve stored SERVER_KEY hash value
SERVER_KEY_HASH = os.getenv("SERVER_KEY_HASH")


# Request data model
class PasswordRequest(BaseModel):
    uuid: str
    password: str

class uuidRequest(BaseModel):
    uuid: str

# Dependency: Check API key
def check_auth(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=403, detail="Missing Authorization header")

    # Validate hashed API key
    if not bcrypt.checkpw(authorization.encode(), SERVER_KEY_HASH.encode()):
        raise HTTPException(status_code=403, detail="Unauthorized")


# FastAPI instance
app = FastAPI()


# **Set Password**
@app.post("/v1/setpasswd")
def set_password(request: PasswordRequest, auth: str = Depends(check_auth)):
    uuid = request.uuid
    password = request.password

    # Generate hashed password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    # Check if the device already exists
    existing_user = collection.find_one({"uuid": uuid})

    if existing_user:
        # Update password
        collection.update_one({"uuid": uuid}, {"$set": {"password": hashed_password}})
    else:
        # Insert new record
        collection.insert_one({"uuid": uuid, "password": hashed_password, "timer": 0})

    return {"message": "Password set successfully"}


# **Validate Password**
@app.post("/v1/valpasswd")
def validate_password(request: PasswordRequest, auth: str = Depends(check_auth)):
    uuid = request.uuid
    password = request.password

    # Find device
    user = collection.find_one({"uuid": uuid})

    if not user:
        raise HTTPException(status_code=404, detail="UUID not found")

    # Verify password
    if bcrypt.checkpw(password.encode(), user["password"]):
        # Update timer
        collection.update_one({"uuid": uuid}, {"$set": {"timer": 0}})
        return {"message": "Password validated successfully"}
    else:
        raise HTTPException(status_code=401, detail="Invalid password")

# **Timeout Timer**
@app.post("/v1/timeout_start")
def timeout_start(request: uuidRequest, auth: str = Depends(check_auth)):
    uuid = request.uuid

    # Find device
    user = collection.find_one({"uuid": uuid})

    if not user:
        raise HTTPException(status_code=404, detail="UUID not found")
    else:
        collection.update_one({"uuid": uuid}, {"$set": {"timer": 1}})
        return {"message": "Timer started successfully"}

# **Check Timer**
@app.post("/v1/timeout_check")
def timeout_check(request: uuidRequest, auth: str = Depends(check_auth)):
    uuid = request.uuid

    # Find device
    user = collection.find_one({"uuid": uuid})

    if not user:
        raise HTTPException(status_code=404, detail="UUID not found")
    else:
        return {"timer": user["timer"]}
    
# Run the service (local debugging)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
