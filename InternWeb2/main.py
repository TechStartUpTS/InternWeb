#tabish
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, Literal, List
from pymongo import MongoClient, ASCENDING
import certifi
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from fastapi_sso.sso.google import GoogleSSO
from fastapi_sso.sso.github import GithubSSO
from fastapi_sso.sso.linkedin import LinkedInSSO
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse, JSONResponse
from dotenv import load_dotenv
from functools import wraps

# Load environment variables
load_dotenv()

# Configuration settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

# MongoDB setup with connection pooling
client = MongoClient(
    os.getenv("MONGODB_URL"),
    tlsCAFile=certifi.where(),
    maxPoolSize=50,
    waitQueueTimeoutMS=2000,
    connectTimeoutMS=2000,
    socketTimeoutMS=2000
)
db = client["startup_intern_db"]
users_collection = db["users"]

# Create indexes for better query performance
users_collection.create_index([("email", ASCENDING)], unique=True)
users_collection.create_index([("role", ASCENDING)])

# Security contexts
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI app setup
app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files with caching
app.mount("/static", StaticFiles(directory="static", html=True), name="static")

# OAuth configurations
google_sso = GoogleSSO(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/google/callback",
    allow_insecure_http=False,
)

github_sso = GithubSSO(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/github/callback",
    allow_insecure_http=False,
)

linkedin_sso = LinkedInSSO(
    client_id=os.getenv("LINKEDIN_CLIENT_ID"),
    client_secret=os.getenv("LINKEDIN_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/linkedin/callback",
    allow_insecure_http=False,
)

# --------------------- Models ---------------------

class UserBase(BaseModel):
    email: EmailStr
    name: Optional[str] = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str
    created_at: datetime
    is_active: bool = True
    auth_provider: str = "email"
    role: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class RoleSelection(BaseModel):
    role: Literal["intern", "startup"]

# --------------------- Helper Functions ---------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    user = users_collection.find_one(
        {"email": email},
        {"_id": 0}
    )
    return User(**user) if user else None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Try to get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        # Try to get token from query parameters
        token = request.query_params.get("access_token")
        if not token:
            raise credentials_exception
    else:
        token = auth_header.split(" ")[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user(email)
    if user is None:
        raise credentials_exception
    return user

# --------------------- Routes ---------------------

@app.get("/")
async def read_index():
    return FileResponse("static/index.html")

@app.get("/select_role")
async def select_role_page(request: Request):
    try:
        current_user = await get_current_user(request)
        if current_user.role:
            return RedirectResponse(url="/home", status_code=303)
        return FileResponse("static/select_role.html")
    except HTTPException as e:
        if e.status_code == 401:
            return RedirectResponse(url="/", status_code=303)
        raise e

@app.post("/api/set_role")
async def set_role(
    role_data: RoleSelection,
    request: Request
):
    current_user = await get_current_user(request)
    
    if current_user.role:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already set"
        )
    
    users_collection.update_one(
        {"email": current_user.email},
        {"$set": {"role": role_data.role}}
    )
    
    return {"next": f"/{role_data.role}_profile"}

@app.get("/intern_profile")
async def intern_profile_page(request: Request):
    current_user = await get_current_user(request)
    if current_user.role != "intern":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    return FileResponse("static/intern_profile.html")

@app.get("/startup_profile")
async def startup_profile_page(request: Request):
    current_user = await get_current_user(request)
    if current_user.role != "startup":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    return FileResponse("static/startup_profile.html")

@app.get("/home")
async def home_page(request: Request):
    current_user = await get_current_user(request)
    if not current_user.role:
        return RedirectResponse(url="/select_role", status_code=303)
    return HTMLResponse(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Welcome - EASIFY</title>
            <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
            <style>
                body {
                    font-family: 'Poppins', sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <h1>Welcome to EASIFY</h1>
        </body>
        </html>
        """
    )

# --------------------- Authentication Routes ---------------------

@app.post("/signup")
async def signup(user: UserCreate):
    if get_user(email=user.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_dict = {
        "email": user.email,
        "name": user.name,
        "password": get_password_hash(user.password),
        "id": str(datetime.utcnow().timestamp()),
        "created_at": datetime.utcnow(),
        "auth_provider": "email",
        "role": None
    }

    users_collection.insert_one(user_dict)
    
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {"access_token": access_token, "token_type": "bearer", "redirect_url": "/select_role"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = users_collection.find_one(
        {"email": form_data.username},
        {"password": 1, "auth_provider": 1, "role": 1}
    )
    
    if not user_dict or user_dict["auth_provider"] != "email" or \
       not verify_password(form_data.password, user_dict["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    redirect_url = "/home" if user_dict.get("role") else "/select_role"
    return {"access_token": access_token, "token_type": "bearer", "redirect_url": redirect_url}

# OAuth handlers
async def handle_oauth_callback(request: Request, user_info, provider: str):
    try:
        db_user = get_user(email=user_info.email)
        
        if not db_user:
            user_data = {
                "email": user_info.email,
                "name": user_info.display_name,
                "id": str(datetime.utcnow().timestamp()),
                "created_at": datetime.utcnow(),
                "auth_provider": provider,
                "role": None
            }
            users_collection.insert_one(user_data)
            redirect_url = "/select_role"
        else:
            redirect_url = "/home" if db_user.role else "/select_role"
        
        access_token = create_access_token(
            data={"sub": user_info.email},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return {"access_token": access_token, "token_type": "bearer", "redirect_url": redirect_url}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Authentication failed: {str(e)}"
        )

@app.get("/auth/google/login")
async def google_login():
    return await google_sso.get_login_redirect()

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    user = await google_sso.verify_and_process(request)
    result = await handle_oauth_callback(request, user, "google")
    return RedirectResponse(
        url=f"{result['redirect_url']}?access_token={result['access_token']}&token_type={result['token_type']}",
        status_code=303
    )

@app.get("/auth/github/login")
async def github_login():
    return await github_sso.get_login_redirect()

@app.get("/auth/github/callback")
async def github_callback(request: Request):
    user = await github_sso.verify_and_process(request)
    result = await handle_oauth_callback(request, user, "github")
    return RedirectResponse(
        url=f"{result['redirect_url']}?access_token={result['access_token']}&token_type={result['token_type']}",
        status_code=303
    )

@app.get("/auth/linkedin/login")
async def linkedin_login():
    return await linkedin_sso.get_login_redirect()

@app.get("/auth/linkedin/callback")
async def linkedin_callback(request: Request):
    user = await linkedin_sso.verify_and_process(request)
    result = await handle_oauth_callback(request, user, "linkedin")
    return RedirectResponse(
        url=f"{result['redirect_url']}?access_token={result['access_token']}&token_type={result['token_type']}",
        status_code=303
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        workers=4,
        proxy_headers=True,
        forwarded_allow_ips="*"
    )
