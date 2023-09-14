from fastapi import FastAPI, Depends

from hashers import PBKDF2PasswordHasher
from models import EncodedPasswordModel, VerifiedPasswordModel, SafeSummaryModel, ErrorResponseModel
from validators import encoded_validator

app = FastAPI()

HASH_ROUTE = "/hash/"
VERIFY_ROUTE = "/verify/"
SAFE_SUMMARY_ROUTE = "/safe-summary/"


@app.post(HASH_ROUTE, response_model=EncodedPasswordModel, responses={400: {"model": ErrorResponseModel}})
async def hash_password(
        password: str):
    """Hash provided password, return django like encoded hash"""
    hasher = PBKDF2PasswordHasher()
    salt = hasher.salt()
    return {"encoded": f"{hasher.encode(password, salt)}"}


@app.post(VERIFY_ROUTE, response_model=VerifiedPasswordModel, responses={400: {"model": ErrorResponseModel}})
async def verify_password(
        password: str,
        encoded: str = Depends(encoded_validator)):
    """Verify encoded password with raw one"""
    hasher = PBKDF2PasswordHasher()
    a = hasher.safe_summary(encoded)
    return {"verified": hasher.verify(password=password, encoded=encoded)}


@app.get(SAFE_SUMMARY_ROUTE, response_model=SafeSummaryModel, responses={400: {"model": ErrorResponseModel}})
async def safe_summary(
        encoded: str = Depends(encoded_validator)):
    """Return password summary"""
    hasher = PBKDF2PasswordHasher()
    return hasher.safe_summary(encoded)
