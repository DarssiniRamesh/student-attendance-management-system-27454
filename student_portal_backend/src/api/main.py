from datetime import datetime, timedelta
from typing import Optional, List, Any
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlmodel import Session, SQLModel, create_engine, select, Field, Relationship
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

# =================== CONFIG =====================
SECRET_KEY = "your-very-secret-key"  # TODO: Move to env file for real deployments
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

DATABASE_URL = "sqlite:///./student_portal.db"
engine = create_engine(DATABASE_URL, echo=False)

# JWT Auth Setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =================== MODELS =====================

class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True, nullable=False, description="User email address")
    full_name: str = Field(max_length=100, nullable=False, description="Full name of the user")
    role: str = Field(max_length=16, description="Role: student / teacher / admin")

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str = Field(nullable=False)
    is_active: bool = Field(default=True)
    # Use list of Attendance, and handle forward refs below with model_rebuild()
    attendances: list["Attendance"] = Relationship(back_populates="user")

class UserCreate(UserBase):
    password: str

class UserRead(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool

    class Config:
        orm_mode = True

class UserUpdate(BaseModel):
    full_name: Optional[str]
    password: Optional[str]

class AttendanceBase(SQLModel):
    date: datetime = Field(description="Date of the attendance entry")
    status: str = Field(description="Attendance status: present/absent/late/excused")
    remarks: Optional[str]

class Attendance(AttendanceBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    user: Optional["User"] = Relationship(back_populates="attendances")

class AttendanceCreate(BaseModel):
    user_id: int
    date: datetime
    status: str
    remarks: Optional[str]

class AttendanceUpdate(BaseModel):
    status: Optional[str]
    remarks: Optional[str]

class AttendanceRead(BaseModel):
    id: int
    user_id: int
    date: datetime
    status: str
    remarks: Optional[str]
    user_name: str

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserRead

class TokenData(BaseModel):
    user_id: Optional[int] = None
    role: Optional[str] = None

# =================== UTILS =====================

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(session: Session = Depends(get_session), token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise credentials_exception
    return user

def get_current_active_user(
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_current_role(required_role: str):
    def role_dependency(user: User = Depends(get_current_active_user)):
        if user.role != required_role and user.role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return user
    return role_dependency

# =================== INIT APP =====================

app = FastAPI(
    title="Student Portal Backend",
    description="Backend API for Student Attendance Management System (Student, Teacher, Admin, Attendance, Auth, Analytics)",
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "User registration, login, logout, profile"},
        {"name": "Users", "description": "User CRUD and search"},
        {"name": "Attendance", "description": "Attendance marking and retrieval"},
        {"name": "Analytics", "description": "Attendance summary and analytics"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In prod, restrict this!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# =================== AUTH ROUTES =====================

# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=UserRead, tags=["Auth"], summary="Register new user", status_code=201)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    """Register a new user as student, teacher, or admin. Email must be unique. Returns the created user (minus password)."""
    db_user = session.exec(select(User).where(User.email == user_in.email)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(user_in.password)
    user = User(email=user_in.email, full_name=user_in.full_name, hashed_password=hashed_pw, role=user_in.role)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, tags=["Auth"], summary="User login and JWT token", status_code=200)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    """
    Authenticate user and get JWT token. Form fields: username (email), password.
    """
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": str(user.id), "role": user.role})
    return Token(access_token=access_token, token_type="bearer", user=UserRead.from_orm(user))

# PUBLIC_INTERFACE
@app.get("/auth/me", response_model=UserRead, tags=["Auth"], summary="Get own profile")
def read_profile(current_user: User = Depends(get_current_active_user)):
    """Get details of the currently authenticated user."""
    return current_user

# PUBLIC_INTERFACE
@app.put("/auth/me", response_model=UserRead, tags=["Auth"], summary="Update own profile")
def update_profile(
    user_update: UserUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user)
):
    """Update your own profile: full name and/or password."""
    changed = False
    if user_update.full_name:
        current_user.full_name = user_update.full_name
        changed = True
    if user_update.password:
        current_user.hashed_password = get_password_hash(user_update.password)
        changed = True
    if changed:
        session.add(current_user)
        session.commit()
        session.refresh(current_user)
    return current_user

# =================== USER ROUTES =====================

# PUBLIC_INTERFACE
@app.get("/users/", response_model=List[UserRead], tags=["Users"], summary="List/search users")
def list_users(
    role: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 20,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_role("admin"))
):
    """
    List all users. Filter by role or search in email/full_name. Only admin/manager can use this.
    """
    q = select(User)
    if role:
        q = q.where(User.role == role)
    if search:
        q = q.where((User.email.contains(search)) | (User.full_name.contains(search)))
    users = session.exec(q.offset(skip).limit(limit)).all()
    return users

# PUBLIC_INTERFACE
@app.get("/users/{user_id}", response_model=UserRead, tags=["Users"], summary="Get user details")
def get_user(user_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_role("admin"))):
    """Get information about a specific user (admin only)."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# PUBLIC_INTERFACE
@app.delete("/users/{user_id}", response_model=Any, tags=["Users"], summary="Delete a user (admin)")
def delete_user(user_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_role("admin"))):
    """Delete a user (admin only)."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"ok": True}

# =================== ATTENDANCE ROUTES =====================

# PUBLIC_INTERFACE
@app.post("/attendance/", response_model=AttendanceRead, tags=["Attendance"], summary="Mark attendance")
def mark_attendance(
    att: AttendanceCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user)
):
    """
    Mark attendance for a user. Teachers can mark for others; students can mark only for themselves.
    """
    if current_user.role == "student" and current_user.id != att.user_id:
        raise HTTPException(status_code=403, detail="Students can only mark their own attendance.")
    if current_user.role == "teacher" and current_user.id != att.user_id:
        # Optionally restrict so that teachers can only mark for their assigned students
        pass
    db_user = session.get(User, att.user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    # Prevent duplicate attendance for same user & date
    exists = session.exec(
        select(Attendance).where(Attendance.user_id == att.user_id, Attendance.date == att.date)
    ).first()
    if exists:
        raise HTTPException(status_code=400, detail="Attendance already marked for this date")
    attendance = Attendance(user_id=att.user_id, date=att.date, status=att.status, remarks=att.remarks)
    session.add(attendance)
    session.commit()
    session.refresh(attendance)
    return AttendanceRead(id=attendance.id, user_id=db_user.id, user_name=db_user.full_name, date=attendance.date, status=attendance.status, remarks=attendance.remarks)

# PUBLIC_INTERFACE
@app.get("/attendance/", response_model=List[AttendanceRead], tags=["Attendance"], summary="View/search attendance")
def view_attendance(
    user_id: Optional[int] = None,
    status: Optional[str] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 20,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user)
):
    """
    View attendance entries. Teachers/admin can view all, students only their own.
    Filter by user, status, date.
    """
    q = select(Attendance, User).join(User, Attendance.user_id == User.id)
    if current_user.role == "student":
        q = q.where(Attendance.user_id == current_user.id)
    else:
        if user_id:
            q = q.where(Attendance.user_id == user_id)
        if search:
            q = q.where(User.full_name.contains(search) | User.email.contains(search))
    if status:
        q = q.where(Attendance.status == status)
    if from_date:
        q = q.where(Attendance.date >= from_date)
    if to_date:
        q = q.where(Attendance.date <= to_date)
    q = q.order_by(Attendance.date.desc()).offset(skip).limit(limit)
    results = session.exec(q).all()
    out: List[AttendanceRead] = []
    for (attendance, user) in results:
        out.append(AttendanceRead(
            id=attendance.id, user_id=user.id, user_name=user.full_name,
            date=attendance.date, status=attendance.status, remarks=attendance.remarks
        ))
    return out

# PUBLIC_INTERFACE
@app.put("/attendance/{att_id}", response_model=AttendanceRead, tags=["Attendance"], summary="Update attendance entry")
def update_attendance(
    att_id: int,
    att_update: AttendanceUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_role("teacher")),
):
    """
    Teachers (and admins) can update attendance status/remarks for any attendance record.
    """
    att = session.get(Attendance, att_id)
    if not att:
        raise HTTPException(status_code=404, detail="Attendance not found")
    if att_update.status:
        att.status = att_update.status
    if att_update.remarks is not None:
        att.remarks = att_update.remarks
    session.add(att)
    session.commit()
    session.refresh(att)
    db_user = session.get(User, att.user_id)
    return AttendanceRead(id=att.id, user_id=db_user.id, user_name=db_user.full_name, date=att.date, status=att.status, remarks=att.remarks)

# PUBLIC_INTERFACE
@app.delete("/attendance/{att_id}", response_model=Any, tags=["Attendance"], summary="Delete attendance entry")
def delete_attendance(att_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_role("admin"))):
    """Admins can delete attendance records."""
    att = session.get(Attendance, att_id)
    if not att:
        raise HTTPException(status_code=404, detail="Attendance not found")
    session.delete(att)
    session.commit()
    return {"ok": True}

# =================== ANALYTICS ROUTES =====================

# PUBLIC_INTERFACE
@app.get("/analytics/user/{user_id}", tags=["Analytics"], summary="User attendance summary")
def user_attendance_summary(user_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_active_user)):
    """
    Returns the attendance summary for a user: present, absent, late, excused, total.
    Students can only see their own summary; teachers/admins can view any summary.
    """
    if current_user.role == "student" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Students can only view their own summary.")
    counts = {}
    for status_ in ["present", "absent", "late", "excused"]:
        cnt = session.exec(select(Attendance).where(Attendance.user_id == user_id, Attendance.status == status_)).count()
        counts[status_] = cnt
    total = session.exec(select(Attendance).where(Attendance.user_id == user_id)).count()
    return {**counts, "total": total}

# PUBLIC_INTERFACE
@app.get("/analytics/overall", tags=["Analytics"], summary="Overall attendance analytics")
def overall_attendance_analytics(session: Session = Depends(get_session), current_user: User = Depends(get_current_role("admin"))):
    """
    Returns summary analytics for the portal: students, attendance stats, etc (admin only).
    """
    res = {}
    roles = ["student", "teacher", "admin"]
    for r in roles:
        res[f"{r}_count"] = session.exec(select(User).where(User.role == r)).count()
    present = session.exec(select(Attendance).where(Attendance.status == 'present')).count()
    absent = session.exec(select(Attendance).where(Attendance.status == 'absent')).count()
    late = session.exec(select(Attendance).where(Attendance.status == 'late')).count()
    excused = session.exec(select(Attendance).where(Attendance.status == 'excused')).count()
    res["attendance"] = {"present": present, "absent": absent, "late": late, "excused": excused}
    return res

# =================== HEALTH ROUTE =====================
@app.get("/", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# ================= Swagger & OpenAPI customization ===================

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Patch: Rebuild SQLModel models to handle forward refs (required for List["Attendance"]/user: "User" fields)
SQLModel.model_rebuild()
