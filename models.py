from pydantic import BaseModel


class ErrorResponseModel(BaseModel):
    detail: str


class EncodedPasswordModel(BaseModel):
    encoded: str


class VerifiedPasswordModel(BaseModel):
    verified: bool


class SafeSummaryModel(BaseModel):
    algorithm: str
    iterations: int
    salt: str
    hash: str
