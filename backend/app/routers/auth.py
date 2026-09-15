#Authentication routes: login, token management

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.user import Token, TokenData, UserCreate, UserResponse
from app.services.audit import log_action


router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


#bcrypt only uses the first 72 bytes; truncate to avoid errors on long inputs
def _bcrypt_truncate(password: str) -> str:
    encoded = password.encode("utf-8")
    if len(encoded) > 72:
        return encoded[:72].decode("utf-8", errors="ignore")
    return password


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(_bcrypt_truncate(plain_password), hashed_password)

def get_password_hash(password: str)-> str:
    return pwd_context.hash(_bcrypt_truncate(password))


def create_access_token(data: dict, expires_delta: timedelta | None=None)-> str:
    to_encode=data.copy()
    expire=datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


#role-based access
def require_role(*roles):
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker


#login route
@router.post("/login", response_model=Token)
async def login (
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)

):

    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect Username or password",
        )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),

    )

    #auditlogging via audit service
    log_action(db, action="login", resource_type="user", user_id=user.id, details=f"User {user.username} logged in")

    return Token(
        access_token=access_token, role=user.role, username=user.username
    )


#register route (admin only)
@router.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    
    current_user: User = Depends(require_role("admin")),
):
    existing = db.query(User).filter(
        (User.username==user_data.username) | (User.email==user_data.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="User or email already exisits ")

    user=User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    #auditlogging via audit service
    log_action(db, action="create", resource_type="user", user_id=current_user.id, resource_id=user.id, details=f"Createed user {user.username} with role {user.role}")

    return user


#me the logged in user route
@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user