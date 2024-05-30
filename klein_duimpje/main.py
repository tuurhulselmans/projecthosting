from fastapi import Depends, FastAPI, HTTPException, Depends, status
from fastapi import UploadFile, File
from fastapi import Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List
from pathlib import Path
from jose import JWTError, jwt
import secrets
import paramiko
import os
from auth import get_current_user
import auth
import crud
import models
import schemas
from schemas import VMCreate, WebsiteCreate
from models import Website
from database import SessionLocal, engine
from auth import get_password_hash
from crud import deploy_vm_template


print("We are in the main.......")
if not os.path.exists('.\sqlitedb'):
    print("Making folder.......")
    os.makedirs('.\sqlitedb')

print("Creating tables.......")
models.Base.metadata.create_all(bind=engine)
print("Tables created.......")

app = FastAPI()



# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

user_files = {}


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


#Authenticatie
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(
        data={"sub": user.email}
    )
    return {"access_token": access_token, "token_type": "bearer"}


#USERS
@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    # if db_user:
    #     raise HTTPException(status_code=400, detail="Email already registered")
    db_user = crud.create_user(db=db, user=user)
    
    token = secrets.token_hex(16)  # generates a random token
    db_user.token = token
    db.add(db_user)
    db.commit()
    db.refresh(db_user)


    return db_user


@app.get("/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/me", response_model=schemas.User)
def read_users_me(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = auth.get_current_active_user(db, token)
    return current_user


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.post("/users/{user_id}/vms/", response_model=schemas.VM)
def create_vm_for_user(user_id: int, vm: schemas.VMCreate, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    return crud.create_user_vm(db=db, vm=vm, user_id=user_id)

@app.get("/vms/", response_model=List[schemas.VM])
def read_vms(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    vms = crud.get_vms(db, skip=skip, limit=limit)
    return vms
@app.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserUpdate, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    updated_user = crud.update_user(db=db, user=user, db_user=db_user)
    return updated_user


# Endpoint to deploy a VM using the logged-in user's name
@app.get("/get_vm")
async def deploy_vm(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):

    result = crud.get_vm()
    if "error" in result:
        raise HTTPException(status_code=400, detail=result['error'])
    return {"message": "VM deployment initiated successfully", "details": result}



@app.post("/deploy_vm")
async def deploy_vm(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = auth.get_current_active_user(db, token)
    vm_name = current_user.email.split('@')[0]  # Use the part of the email before '@' as the VM name
    user_id = current_user.id

    result = deploy_vm_template(db, vm_name, user_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result['error'])
    return {"message": "VM deployment initiated successfully", "user": result}

@app.delete("/users/{user_id}/", response_model=schemas.User)
def delete_user(user_id: int, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    crud.delete_user(db=db, user_id=user_id)
    return db_user


@app.post("/websites/", response_model=schemas.Website)
def create_website_for_user(website: schemas.WebsiteCreate, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = auth.get_current_active_user(db, token)
    return crud.create_website(db=db, website=website, user_id=current_user.id)


