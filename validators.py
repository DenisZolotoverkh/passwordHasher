import re

from fastapi import HTTPException


ENCODED_REGEX = re.compile(r"^(pbkdf2_sha256\$[0-9]+\$.+\$.+)$")


def encoded_validator(encoded: str):
    if not ENCODED_REGEX.match(encoded):
        raise HTTPException(
            status_code=400,
            detail="Not valid encoded password is provided"
        )
    return encoded
