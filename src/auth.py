import os
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)
x_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

API_KEY = os.getenv("API_KEY", "default-dev-key") # Default key for local dev if not set

async def verify_api_key(
    api_key_header: str = Security(api_key_header),
    x_api_key_header: str = Security(x_api_key_header),
):
    if api_key_header:
        # Check standard Authorization: Bearer <token>
        token = api_key_header.replace("Bearer ", "")
        if token == API_KEY:
            return token
            
    if x_api_key_header == API_KEY:
        return x_api_key_header
        
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )