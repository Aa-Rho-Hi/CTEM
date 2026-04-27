from fastapi import HTTPException

from app.schemas.common import ErrorResponse


STANDARD_ERROR_RESPONSES = {
    400: {"model": ErrorResponse},
    401: {"model": ErrorResponse},
    403: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    503: {"model": ErrorResponse},
}


def bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail)


def not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


def conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=409, detail=detail)
