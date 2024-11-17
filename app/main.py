from collections.abc import Generator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Annotated, Self
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel, SecretStr, ValidationError, UUID4
from pydantic.types import StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlmodel import Field, Session, SQLModel, create_engine, select
from sqlalchemy.engine.base import Engine
from sqlalchemy.exc import IntegrityError


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    secret_key: Annotated[SecretStr, StringConstraints(min_length=64, max_length=64)]
    jwt_signing_algorithm: str
    access_token_expire_minutes: timedelta
    pwd_hash_scheme: str
    db_url: str
    debug: bool


@lru_cache
def _get_settings() -> Settings:
    return Settings()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_ctx = CryptContext(schemes=[_get_settings().pwd_hash_scheme])

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserBase(SQLModel):
    username: str = Field(unique=True, min_length=1)
    password: str


class Blob(SQLModel):
    blob_id: UUID4 = Field(primary_key=True, default_factory=uuid4)
    blob: bytes | None = None


class User(UserBase, Blob, table=True):
    pass


class UserCreate(UserBase):
    pass


class UserGet(BaseModel):
    username: str
    blob_id: UUID4


class JWTSub(BaseModel):
    username: str
    blob_id: UUID4

    def __str__(self) -> str:
        return f"username:{self.username} blob_id:{str(self.blob_id)}"

    @classmethod
    def from_str(cls, sub_string: str) -> Self:
        """
        Parse the 'sub' value of a JWT.

        Our JWT's have a 'sub' key with a value that is a string formatted like
        'username:<username> blob_id:<blob_id>'.
        """
        assert "username:" in sub_string
        assert "blob_id:" in sub_string
        items = sub_string.split()
        assert len(items) == 2
        sub_dict = {}
        for item in items:
            subs = item.split(":")
            sub_dict[subs[0]] = subs[1]
        return cls(username=sub_dict["username"], blob_id=UUID4(sub_dict["blob_id"]))


def _get_session() -> Generator[Session]:
    with Session(engine) as session:
        yield session


def _create_db_and_tables(engine: Engine) -> None:
    SQLModel.metadata.create_all(engine)


engine: Engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    settings = _get_settings()
    engine = create_engine(settings.db_url, echo=settings.debug)
    _create_db_and_tables(engine)
    yield
    engine.dispose()


app = FastAPI(lifespan=lifespan)


def _get_user(username: str, session: Session) -> User | None:
    return session.exec(select(User).where(User.username == username)).first()


def _add_user(user: User, session: Session) -> User:
    session.add(user)
    session.commit()
    return user


def _update_user_blob(user: User, blob: Blob, session: Session) -> None:
    user.blob = blob.blob
    session.add(user)
    session.commit()
    return


async def _get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    settings: Annotated[Settings, Depends(_get_settings)],
    session: Annotated[Session, Depends(_get_session)],
) -> User:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[settings.jwt_signing_algorithm],
        )
        sub_string = payload.get("sub")
        if sub_string is None:
            raise credentials_exception
        sub = JWTSub.from_str(sub_string)
        if sub.username == "":
            raise credentials_exception
    except (AssertionError, InvalidTokenError, ValidationError, ValueError):
        raise credentials_exception
    user = _get_user(sub.username, session)
    if user is None or user.blob_id != sub.blob_id:
        raise credentials_exception
    return user


def _create_access_token(
    *,
    data: dict,
    settings: Settings,
    expires_delta: timedelta | None = None,
) -> str:
    if expires_delta is None:
        expires_delta = settings.access_token_expire_minutes
    data = data.copy()
    exp = datetime.now(timezone.utc) + expires_delta
    data.update({"exp": exp})
    encoded_jwt = jwt.encode(
        data,
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_signing_algorithm,
    )
    return encoded_jwt


def _authenticate_user(username: str, password: str, session: Session) -> User | None:
    user = _get_user(username, session)
    if user is None:
        return None
    if not pwd_ctx.verify(password, user.password):
        return None
    return user


@app.post("/token", status_code=status.HTTP_200_OK, response_model=Token)
async def token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(_get_settings)],
    session: Annotated[Session, Depends(_get_session)],
) -> Token:
    user = _authenticate_user(form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = _create_access_token(
        data={"sub": str(JWTSub(username=user.username, blob_id=user.blob_id))},
        settings=settings,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/user", status_code=status.HTTP_200_OK, response_model=UserGet)
async def get_user(user: Annotated[User, Depends(_get_current_user)]) -> UserGet:
    return UserGet(username=user.username, blob_id=user.blob_id)


@app.post("/user", status_code=status.HTTP_201_CREATED, response_model=Token)
async def post_user(
    new_user: UserCreate,
    settings: Annotated[Settings, Depends(_get_settings)],
    session: Annotated[Session, Depends(_get_session)],
) -> Token:
    hashed_password = pwd_ctx.hash(new_user.password)
    try:
        user = _add_user(
            User(username=new_user.username, password=hashed_password), session
        )
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )
    access_token = _create_access_token(
        data={"sub": str(JWTSub(username=user.username, blob_id=user.blob_id))},
        settings=settings,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/blob/{blob_id}", status_code=status.HTTP_200_OK, response_model=Blob)
async def get_blob(
    blob_id: UUID4, user: Annotated[User, Depends(_get_current_user)]
) -> Blob:
    if blob_id != user.blob_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Blob does not match User's blob",
            headers={"WWW-Authenticate": "Bearer"},
        )
    blob = Blob(blob_id=user.blob_id, blob=user.blob)
    return blob


@app.put("/blob/{blob_id}", status_code=status.HTTP_204_NO_CONTENT)
async def put_blob(
    blob_id: UUID4,
    blob: Blob,
    user: Annotated[User, Depends(_get_current_user)],
    session: Annotated[Session, Depends(_get_session)],
):
    if blob_id != user.blob_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Blob does not match User's blob",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _update_user_blob(user, blob, session)
