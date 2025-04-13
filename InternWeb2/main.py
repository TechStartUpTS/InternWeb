from fastapi import FastAPI, Depends, HTTPException, status, Cookie, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
from pymongo import MongoClient
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from fastapi_sso.sso.google import GoogleSSO
from fastapi_sso.sso.github import GithubSSO
from fastapi_sso.sso.linkedin import LinkedInSSO
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration settings: secret key, algorithm and token expiration
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

# MongoDB Connection using the environment variable (MONGODB_URL)
client = MongoClient(os.getenv("MONGODB_URL"))
db = client["startup_intern_db"]
users_collection = db["users"]

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Create FastAPI app instance
app = FastAPI()

# CORS middleware configuration for production domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://internweb.onrender.com"],  # Change as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve the main page
@app.get("/")
async def read_index():
    return FileResponse("static/index.html")

# Serve the authentication (login/signup) page
@app.get("/auth.html")
async def get_auth_html():
    return FileResponse("static/auth.html")


# ---------------- Social OAuth Configurations ----------------

# For Google OAuth, using production redirect URI and secure setting
google_sso = GoogleSSO(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/google/callback",  # Production URL
    allow_insecure_http=False,
)

# For GitHub OAuth, using production redirect URI and secure setting
github_sso = GithubSSO(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/github/callback",  # Production URL
    allow_insecure_http=False,
)

# For LinkedIn OAuth, using production redirect URI and secure setting
linkedin_sso = LinkedInSSO(
    client_id=os.getenv("LINKEDIN_CLIENT_ID"),
    client_secret=os.getenv("LINKEDIN_CLIENT_SECRET"),
    redirect_uri="https://internweb.onrender.com/auth/linkedin/callback",  # Production URL
    allow_insecure_http=False,
)


# --------------------- Models ---------------------

# Base user model containing email and optional name
class UserBase(BaseModel):
    email: EmailStr
    name: Optional[str] = None

# Model used when creating a new user (includes password)
class UserCreate(UserBase):
    password: str

# User model to return to client without the password
class User(UserBase):
    id: str
    created_at: datetime
    is_active: bool = True
    auth_provider: str = "email"  # Could be email, google, github, or linkedin

# Token response model
class Token(BaseModel):
    access_token: str
    token_type: str

# Model for token data stored in JWT
class TokenData(BaseModel):
    email: Optional[str] = None


# --------------------- Helper Functions ---------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    user = users_collection.find_one({"email": email})
    if user:
        return User(**user)
    return None

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    # Only email based login is supported here
    if user.auth_provider != "email":
        return False
    # Retrieve the full user object from the database to check password
    user_dict = users_collection.find_one({"email": email})
    if not verify_password(password, user_dict["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to extract the current user based on the token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


# --------------------- Routes ---------------------

# Signup endpoint for creating a new user using email and password
@app.post("/signup", response_model=User)
async def signup(user: UserCreate, response: Response):
    db_user = get_user(email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    # Convert the user model to dict and add extra fields
    user_dict = user.dict()
    user_dict.pop("password")
    user_dict.update({
        "password": hashed_password,
        "id": str(datetime.utcnow().timestamp()),
        "created_at": datetime.utcnow(),
        "auth_provider": "email"
    })

    users_collection.insert_one(user_dict)

    # Create access token and set it as an HTTP-only cookie
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
    )

    return User(**user_dict)


# Login endpoint for email based authentication
@app.post("/token", response_model=Token)
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email}, 
            expires_delta=access_token_expires
        )

        response.set_cookie(
            key="access_token",
            value=f"Bearer {access_token}",
            httponly=True,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            samesite="lax",
        )

        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal Server Error: {str(e)}"
        )


# Endpoint to return the logged in user's information
@app.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# Cookie-based login checking endpoint
@app.get("/auth/cookie-login")
async def cookie_login(response: Response, access_token: Optional[str] = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        token = access_token.split(" ")[1] if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = get_user(email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {"message": "Logged in successfully", "user": user}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


# --------------------- Social Login Routes ---------------------

# Google OAuth callback endpoint
@app.get("/auth/google/callback")
async def google_callback(response: Response):
    user = await google_sso.verify_and_process()

    # Check if user already exists; if not, create a new user record
    db_user = get_user(email=user.email)
    if not db_user:
        user_data = {
            "email": user.email,
            "name": user.display_name,
            "id": str(datetime.utcnow().timestamp()),
            "created_at": datetime.utcnow(),
            "auth_provider": "google"
        }
        users_collection.insert_one(user_data)
    else:
        # Update last login information if needed
        users_collection.update_one(
            {"email": user.email},
            {"$set": {"last_login": datetime.utcnow()}}
        )

    # Create token and set cookie for the user
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
    )

    return RedirectResponse(url="https://internweb.onrender.com/dashboard")


# GitHub OAuth callback endpoint
@app.get("/auth/github/callback")
async def github_callback(response: Response):
    user = await github_sso.verify_and_process()
    db_user = get_user(email=user.email)
    if not db_user:
        # Ensure the auth_provider is set to "github" (not "google")
        user_data = {
            "email": user.email,
            "name": user.display_name,
            "id": str(datetime.utcnow().timestamp()),
            "created_at": datetime.utcnow(),
            "auth_provider": "github"
        }
        users_collection.insert_one(user_data)
    else:
        users_collection.update_one(
            {"email": user.email},
            {"$set": {"last_login": datetime.utcnow()}}
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
    )

    return RedirectResponse(url="https://internweb.onrender.com/dashboard")


# LinkedIn OAuth callback endpoint
@app.get("/auth/linkedin/callback")
async def linkedin_callback(response: Response):
    user = await linkedin_sso.verify_and_process()
    db_user = get_user(email=user.email)
    if not db_user:
        # Ensure the auth_provider is set to "linkedin" (not "google")
        user_data = {
            "email": user.email,
            "name": user.display_name,
            "id": str(datetime.utcnow().timestamp()),
            "created_at": datetime.utcnow(),
            "auth_provider": "linkedin"
        }
        users_collection.insert_one(user_data)
    else:
        users_collection.update_one(
            {"email": user.email},
            {"$set": {"last_login": datetime.utcnow()}}
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
    )

    return RedirectResponse(url="https://internweb.onrender.com/dashboard")


# Logout endpoint to remove the cookie
@app.get("/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"message": "Successfully logged out"}


# --------------------- Run the App ---------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
