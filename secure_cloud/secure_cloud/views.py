from django.shortcuts import render, redirect
from django.utils.datastructures import MultiValueDictKeyError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import dropbox
import json
import os
from base64 import b64encode, b64decode
from secure_cloud.utils import crypto


def landing_page(request):
    return render(request, "secure_cloud/index.html")


def owner_landing_page(request):
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])
    _, k = dbx.files_download('/keys.json')

    pending_list = []
    approved_list = []
    keys = json.loads(k.content)
    for key in keys:
        if not keys[key]["approved"]:
            pending_list.append(key)
        else:
            if not keys[key]["owner"]:
                approved_list.append(key)
            else:
                username = key
    context = {"approved": approved_list,
               "pending": pending_list,
               "username": username}

    return render(request, "secure_cloud/owner_landing.html", context)


def guest_login(request):
    try:
        guest_name = request.POST['guest_name'].lower()

        with open("secure_cloud/config/config.json", "r") as f:
            data = json.load(f)
        dbx = dropbox.Dropbox(data["access"])
        _, k = dbx.files_download('/keys.json')

        keys = json.loads(k.content)
        if guest_name in keys:
            if keys[guest_name]["approved"]:
                return redirect("view_files", guest_name)
            else:
                context = {"name": guest_name,
                           "requesting": False,
                           "pending": True}
                return render(request, "secure_cloud/guest_login.html", context)
        else:
            context = {"name": guest_name,
                       "requesting": True,
                       "pending": False}
            return render(request, "secure_cloud/guest_login.html", context)
    except MultiValueDictKeyError:
        context = {"requesting": False}

    return render(request, "secure_cloud/guest_login.html", context)


def request_access(request):
    guest_name = request.POST['guest_name'].lower()

    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])
    _, k = dbx.files_download('/keys.json')

    keys = json.loads(k.content)
    private_key, public_key = crypto.generate_keypair()

    info = {"public": b64encode(public_key).decode(),
            "symmetric": '',
            "owner": False,
            "approved": False}
    keys[guest_name] = info
    keys = json.dumps(keys)

    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    return redirect("landing_page")


def grant_access(request, guest_name):
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])
    _, k = dbx.files_download('/keys.json')

    keys = json.loads(k.content)
    for key in keys:
        if keys[key]["owner"]:
            owner_name = key

    encrypted_sym_key = b64decode(keys[owner_name]["symmetric"].encode())
    with open("secure_cloud/keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
    sym_key = crypto.decrypt_sym_key(private_key, encrypted_sym_key)

    public_key = b64decode(keys[guest_name]["public"].encode())
    encrypted_sym_key = crypto.encrypt_sym_key(public_key, sym_key)

    info = {"public": b64encode(public_key).decode(),
            "symmetric": encrypted_sym_key,
            "owner": False,
            "approved": True}
    keys[guest_name] = info
    keys = json.dumps(keys)

    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    return redirect("owner_landing")


def revoke_access(request, guest_name):
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])
    _, k = dbx.files_download('/keys.json')

    keys = json.loads(k.content)
    keys.pop(guest_name, None)

    keys = json.dumps(keys)

    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    return redirect("owner_landing")


def initialise(request):
    name = request.POST['owner_name'].lower()
    private_key, public_key = crypto.generate_keypair()

    key_length = 32
    # generate symmetric key using cryptographically secure pseudo-random number generator
    symmetric_key = os.urandom(key_length)

    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    keys = {}
    encrypted_sym_key = crypto.encrypt_sym_key(public_key, symmetric_key)

    info = {"public": b64encode(public_key).decode(),
            "symmetric": encrypted_sym_key,
            "owner": True,
            "approved": True}
    keys[name] = info
    keys = json.dumps(keys)

    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    return redirect("owner_landing")
