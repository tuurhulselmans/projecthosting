from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import secrets
import requests
import json
import base64
import time

import auth
import models
import schemas


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    # Generate a random token
    token = secrets.token_hex(16)  # generates a random token
    db_user.token = token
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_vms(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.VM).offset(skip).limit(limit).all()

def create_user_vm(db: Session, vm: schemas.VMCreate, user_id: int):
    db_vm = models.VM(**vm.dict(), owner_id=user_id)
    db.add(db_vm)
    db.commit()
    db.refresh(db_vm)
    return db_vm

def update_user(db: Session, user: schemas.UserUpdate, db_user: models.User) -> models.User:
    db_user.email = user.email or db_user.email
    db_user.full_name = user.full_name or db_user.full_name
    db_user.disabled = user.disabled or db_user.disabled
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def delete_user(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    db.delete(db_user)
    db.commit()
    return db_user



def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_dir(db: Session, email: str) -> str:
    user = get_user_by_email(db, email)
    return f'/home/{user.email}/files'  # update this to reflect your directory structure


session_id = None
def get_session_id():
    global session_id
    # Credentials
    username = "administrator@vsphere.local"
    password = "Admin123!"
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('ascii')).decode('ascii')
    # URLs and headers
    url1 = "https://10.0.250.201/rest/com/vmware/cis/session"
    headers1 = {
        "Authorization": f"Basic {encoded_credentials}"
    }
    response1 = requests.post(url1, headers=headers1, verify=False)  # Typically a POST request for session creation
    if response1.status_code == 200:
        session_id = response1.json()['value']
        print(f"Session ID: {session_id}")
        return session_id
    else:
        print(f"Failed to get session ID: {response1.status_code}, {response1.text}")
        return None
def get_vm():
    global session_id
    if session_id is None:
        session_id = get_session_id()
        if session_id is None:
            return {'error': 'Failed to obtain session ID'}

    url = 'http://10.0.250.201/rest/vcenter/vm/'
    headers = {
        'AuthKey': session_id,
        'Content-Type': 'application/json'
    }
    cookies = {
        'vmware-api-session-id': session_id
    }

    try:
        response = requests.get(url, headers=headers, cookies=cookies, verify=False)  # For development only
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError as e:
        return {'error': f'SSL Error: {e}'}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request failed: {e}'}


def deploy_vm_template(db: Session, vm_name: str, user_id: int):
    global session_id
    if session_id is None:
        session_id = get_session_id()
        if session_id is None:
            return {'error': 'Failed to obtain session ID'}

    url = 'https://10.0.250.201/rest/vcenter/vm-template/library-items/32e1598f-93eb-42f3-b8fa-9082a567ad4e?action=deploy'
    headers = {
        'vmware-api-session-id': session_id,
        'Content-Type': 'application/json'
    }
    body = {
        "spec": {
            "description": "TemplateVM",
            "disk_storage": {
                "datastore": "datastore-19",
                "storage_policy": {
                    "policy": "4d5f673c-536f-11e6-beb8-9e71128cae77",
                    "type": "USE_SPECIFIED_POLICY"
                }
            },
            "hardware_customization": {
                "cpu_update": {
                    "num_cores_per_socket": 1,
                    "num_cpus": 1
                },
                "memory_update": {
                    "memory": 4096
                }

            },
            "name": vm_name,
            "placement": {
                "cluster": "domain-c7",
                "folder": "group-v3",
                "resource_pool": "resgroup-44"
            },
            "powered_on": True,
            "vm_home_storage": {
                "datastore": "datastore-19",
                "storage_policy": {
                    "policy": "4d5f673c-536f-11e6-beb8-9e71128cae77",
                    "type": "USE_SPECIFIED_POLICY"
                }
            }
        }
    }

    cookies = {
        'vmware-api-session-id': session_id
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(body), verify=False)
        response.raise_for_status()
        response_data = response.json()
        vm_value = response_data.get('value')
        time.sleep(69)
        url_ip = 'https://10.0.250.201/rest/vcenter/vm/'+vm_value+'/guest/identity'
        response_ip_helemaal = requests.get(url_ip, headers=headers, cookies=cookies, verify=False)
        print(response_ip_helemaal)
        response_ip_json = response_ip_helemaal.json()
        ip_address = response_ip_json.get('value', {}).get('ip_address')

        print(ip_address)

        vm = schemas.VMCreate(name=vm_name, VM_id=vm_value, ip=ip_address)
        db_vm = create_user_vm(db, vm, user_id)

        return {'success': True, 'vm': db_vm}
    except requests.exceptions.SSLError as e:
        return {'error': f'SSL Error: {e}'}
    except requests.exceptions.RequestException as e:
        return {'error': f'Request failed: {e}'}


def create_website(db: Session, website: schemas.WebsiteCreate, user_id: int):
    db_website = models.Website(**website.dict(), owner_id=user_id)
    db.add(db_website)
    db.commit()
    db.refresh(db_website)
    return db_website

def get_websites(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Website).offset(skip).limit(limit).all()


