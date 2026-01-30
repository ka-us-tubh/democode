import base64
import os
from pathlib import Path
from datetime import datetime
from typing import Generator, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import DateTime, Integer, String, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from sqlalchemy_encryption_decorator import (
    encrypt_columns,
    generate_key,
    hash_columns,
    verify_object,
)
from sqlalchemy_encryption_decorator.errors import DecryptionError


def _load_fernet_key() -> str:
    key = os.getenv("DEMO_FERNET_KEY")
    if key:
        return key

    key_file = Path(__file__).with_name(".demo_fernet_key")
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()

    generated = base64.urlsafe_b64encode(generate_key("aes")).decode("ascii")
    key_file.write_text(generated, encoding="utf-8")
    print(
        "DEMO_FERNET_KEY was not set. Generated and persisted a demo key to "
        f"{key_file}. For production, set DEMO_FERNET_KEY instead.\n"
        f"DEMO_FERNET_KEY={generated}"
    )
    return generated


def _load_pepper() -> bytes:
    return os.getenv("DEMO_PEPPER", "dev-pepper").encode("utf-8")


FERNET_KEY = _load_fernet_key()
PEPPER = _load_pepper()


class Base(DeclarativeBase):
    pass


@encrypt_columns(
    columns={"ssn", "private_notes"},
    default_algorithm="aes",
    default_key=FERNET_KEY,
)
@hash_columns(
    columns={"password"},
    default_algorithm="pbkdf2_sha256",
    default_pepper=PEPPER,
)
class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    password: Mapped[str] = mapped_column(String(512),nullable=False)

    ssn: Mapped[str] = mapped_column(String(32))
    private_notes: Mapped[str] = mapped_column(String(2048))

    display_name: Mapped[str] = mapped_column(String(255))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


engine = create_engine(
    os.getenv("DEMO_DB_URL", "sqlite:///./demo_fastapi.db"),
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class CustomerCreate(BaseModel):
    email: str
    password: str
    ssn: str
    private_notes: str = ""
    display_name: str


class CustomerUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    ssn: Optional[str] = None
    private_notes: Optional[str] = None
    display_name: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "password": "new-password",
                "private_notes": "updated notes",
            }
        }
    }


class CustomerOut(BaseModel):
    id: int
    email: str
    ssn: str
    private_notes: str
    display_name: str
    created_at: datetime


class VerifyPasswordRequest(BaseModel):
    password: str


class VerifyPasswordResponse(BaseModel):
    ok: bool


class RawStoredResponse(BaseModel):
    id: int
    password_hash: str
    ssn_ciphertext_b64: str
    private_notes_ciphertext_b64: str


app = FastAPI(title="sqlalchemy_encryption_decorator demo")


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/customers", response_model=CustomerOut)
def create_customer(payload: CustomerCreate, db: Session = Depends(get_db)) -> Customer:
    existing = db.query(Customer).filter(Customer.email == payload.email).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="email already exists")

    obj = Customer(
        email=payload.email,
        password=payload.password,
        ssn=payload.ssn,
        private_notes=payload.private_notes,
        display_name=payload.display_name,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@app.get("/customers/{customer_id}", response_model=CustomerOut)
def get_customer(customer_id: int, db: Session = Depends(get_db)) -> Customer:
    try:
        obj = db.query(Customer).filter(Customer.id == customer_id).first()
    except DecryptionError as e:
        raise HTTPException(
            status_code=500,
            detail=(
                "Decryption failed. Your DEMO_FERNET_KEY does not match the key that was used to encrypt "
                "existing rows. Set DEMO_FERNET_KEY to a stable value (or delete demo.db to start fresh)."
            ),
        ) from e
    if obj is None:
        raise HTTPException(status_code=404, detail="not found")
    return obj


@app.patch("/customers/{customer_id}", response_model=CustomerOut)
def update_customer(customer_id: int, payload: CustomerUpdate, db: Session = Depends(get_db)) -> Customer:
    try:
        obj = db.query(Customer).filter(Customer.id == customer_id).first()
    except DecryptionError as e:
        raise HTTPException(
            status_code=500,
            detail=(
                "Decryption failed. Your DEMO_FERNET_KEY does not match the key that was used to encrypt "
                "existing rows. Set DEMO_FERNET_KEY to a stable value (or delete demo.db to start fresh)."
            ),
        ) from e
    if obj is None:
        raise HTTPException(status_code=404, detail="not found")

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields provided")

    for key, value in updates.items():
        setattr(obj, key, value)

    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@app.delete("/customers/{customer_id}")
def delete_customer(customer_id: int, db: Session = Depends(get_db)) -> dict:
    try:
        obj = db.query(Customer).filter(Customer.id == customer_id).first()
    except DecryptionError as e:
        raise HTTPException(
            status_code=500,
            detail=(
                "Decryption failed. Your DEMO_FERNET_KEY does not match the key that was used to encrypt "
                "existing rows. Set DEMO_FERNET_KEY to a stable value (or delete demo.db to start fresh)."
            ),
        ) from e
    if obj is None:
        raise HTTPException(status_code=404, detail="not found")

    db.delete(obj)
    db.commit()
    return {"deleted": True}


@app.post("/customers/{customer_id}/verify-password", response_model=VerifyPasswordResponse)
def verify_password(customer_id: int, payload: VerifyPasswordRequest, db: Session = Depends(get_db)) -> VerifyPasswordResponse:
    row = db.query(Customer.id, Customer.password).filter(Customer.id == customer_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")

    ok = verify_object(payload.password, row.password, pepper=PEPPER)
    return VerifyPasswordResponse(ok=ok)


@app.get("/debug/raw/{customer_id}", response_model=RawStoredResponse)
def raw_stored(customer_id: int, db: Session = Depends(get_db)) -> RawStoredResponse:
    row = db.execute(
        text(
            "SELECT id, password, ssn, private_notes "
            "FROM customers "
            "WHERE id = :id"
        ),
        {"id": customer_id},
    ).one_or_none()

    if row is None:
        raise HTTPException(status_code=404, detail="not found")

    ssn_raw = row.ssn
    notes_raw = row.private_notes

    if isinstance(ssn_raw, (bytes, bytearray, memoryview)):
        ssn_ciphertext_b64 = base64.b64encode(bytes(ssn_raw)).decode("ascii")
    else:
        ssn_ciphertext_b64 = str(ssn_raw)

    if isinstance(notes_raw, (bytes, bytearray, memoryview)):
        private_notes_ciphertext_b64 = base64.b64encode(bytes(notes_raw)).decode("ascii")
    else:
        private_notes_ciphertext_b64 = str(notes_raw)

    return RawStoredResponse(
        id=row.id,
        password_hash=row.password,
        ssn_ciphertext_b64=ssn_ciphertext_b64,
        private_notes_ciphertext_b64=private_notes_ciphertext_b64,
    )
