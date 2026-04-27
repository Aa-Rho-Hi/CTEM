from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.application.auth.use_cases import (
    AuthConflictError,
    AuthUnauthorizedError,
    AuthValidationError,
    LoginUseCase,
    RegisterUserUseCase,
    SignupTenantUseCase,
)
from app.core.security import create_access_token, require_roles
from app.dependencies import get_db_session
from app.routes._shared import STANDARD_ERROR_RESPONSES, bad_request, conflict, unauthorized
from app.schemas.auth import LoginRequest, RegisterRequest, TenantSignupRequest, TokenResponse
from app.infrastructure.persistence.auth_repository import AuthRepository
from app.services.auth_service import build_user, verify_user_credentials

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterResponse(BaseModel):
    id: str
    email: str
    role: str


@router.post("/register", status_code=201, response_model=RegisterResponse, responses=STANDARD_ERROR_RESPONSES)
async def register(
    payload: RegisterRequest,
    session=Depends(get_db_session),
    _=Depends(require_roles("super_admin", "platform_admin")),
):
    use_case = RegisterUserUseCase(AuthRepository(session), build_user=build_user)
    try:
        result = await use_case.execute(
            email=payload.email,
            password=payload.password,
            role=payload.role,
            tenant_id=payload.tenant_id,
        )
    except AuthConflictError as exc:
        raise conflict(str(exc)) from exc
    except AuthValidationError as exc:
        raise bad_request(str(exc)) from exc
    return {"id": result.id, "email": result.email, "role": result.role}


@router.post("/login", response_model=TokenResponse, responses=STANDARD_ERROR_RESPONSES)
async def login(payload: LoginRequest, session=Depends(get_db_session)) -> TokenResponse:
    use_case = LoginUseCase(
        AuthRepository(session),
        verify_user_credentials=verify_user_credentials,
        create_access_token=create_access_token,
    )
    try:
        result = await use_case.execute(email=payload.email, password=payload.password)
    except AuthUnauthorizedError as exc:
        raise unauthorized(str(exc)) from exc
    return TokenResponse(access_token=result.access_token, tenant_id=result.tenant_id)


@router.post("/signup", response_model=TokenResponse, responses=STANDARD_ERROR_RESPONSES)
async def signup(payload: TenantSignupRequest, session=Depends(get_db_session)) -> TokenResponse:
    use_case = SignupTenantUseCase(
        AuthRepository(session),
        build_user=build_user,
        create_access_token=create_access_token,
    )
    try:
        result = await use_case.execute(
            organization_name=payload.organization_name,
            email=payload.email,
            password=payload.password,
            confirm_password=payload.confirm_password,
        )
    except AuthConflictError as exc:
        raise conflict(str(exc)) from exc
    except AuthValidationError as exc:
        raise bad_request(str(exc)) from exc
    return TokenResponse(access_token=result.access_token, tenant_id=result.tenant_id)
