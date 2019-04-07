from django.shortcuts import render, redirect
from django.utils.datastructures import MultiValueDictKeyError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import dropbox
import json
from base64 import b64encode, b64decode
from secure_cloud.utils import crypto


def landing_page(request):
    # initial landing page
    return render(request, "secure_cloud/index.html")


def owner_landing_page(request):
    # create Dropbox object for interfacing with remote folder
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    # retrieve keys.json from Dropbox
    _, k = dbx.files_download('/keys.json')

    pending_list = []
    approved_list = []

    # load keys.json into a dict
    keys = json.loads(k.content)
    # iterate through names in keys.json and add accordingly to list of approved and pending requests, ignoring
    # the owner's name
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

    # return owner landing page with lists of approved users and pending requests
    return render(request, "secure_cloud/owner_landing.html", context)


def guest_login(request):
    # if the guest has entered a name, the try will succeed
    try:
        # retrieve guest name from text input box
        guest_name = request.POST['guest_name'].lower()

        # create Dropbox object for interfacing with remote folder
        with open("secure_cloud/config/config.json", "r") as f:
            data = json.load(f)
        dbx = dropbox.Dropbox(data["access"])

        # retrieve keys.json from Dropbox
        _, k = dbx.files_download('/keys.json')

        # load keys.json into a dict
        keys = json.loads(k.content)
        if guest_name in keys:
            # if guest is already approved, redirect to files list
            if keys[guest_name]["approved"]:
                return redirect("files:view_files", guest_name)
            # if request is pending, update context
            else:
                context = {"name": guest_name,
                           "requesting": False,
                           "pending": True}
                return render(request, "secure_cloud/guest_landing.html", context)
        else:
            # if guest has no entry in keys.json, update context
            context = {"name": guest_name,
                       "requesting": True,
                       "pending": False}
            return render(request, "secure_cloud/guest_landing.html", context)
    # if no name entered in text box, or first time loading this page
    except MultiValueDictKeyError:
        context = {"requesting": False}

    # return the guest landing, if requesting is True then asks if the guest wants to request access,
    # if pending is True then tells user their request is pending, if neither then presents the input
    # text box
    return render(request, "secure_cloud/guest_landing.html", context)


def request_access(request):
    # retrieve guest name from text input box
    guest_name = request.POST['guest_name'].lower()

    # create Dropbox object for interfacing with remote folder
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    # retrieve keys.json from Dropbox
    _, k = dbx.files_download('/keys.json')

    # load keys.json into a dict
    keys = json.loads(k.content)

    # use crypto utils to generate RSA key pair
    private_key, public_key = crypto.generate_key_pair()

    # prepare new entry for guest in keys.json
    info = {"public": b64encode(public_key).decode(),
            "symmetric": '',
            "owner": False,
            "approved": False}
    keys[guest_name] = info

    # recreate the json object
    keys = json.dumps(keys)

    # replace the keys.json on Dropbox with updated version
    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    # redirect to initial landing page
    return redirect("landing_page")


def grant_access(request, guest_name):
    # create Dropbox object for interfacing with remote folder
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    # retrieve keys.json from Dropbox
    _, k = dbx.files_download('/keys.json')

    # load keys.json into a dict and establish the owner's name
    keys = json.loads(k.content)
    for key in keys:
        if keys[key]["owner"]:
            owner_name = key

    # retrieve the owner's encrypted sym key from keys.json
    encrypted_sym_key = b64decode(keys[owner_name]["symmetric"].encode())
    # use the owner's private key to decrypt the sym key
    with open("secure_cloud/keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())
    sym_key = crypto.decrypt_sym_key(private_key, encrypted_sym_key)

    # retrieve the guest's public key and use it to encrypt sym key
    public_key = b64decode(keys[guest_name]["public"].encode())
    encrypted_sym_key = crypto.encrypt_sym_key(public_key, sym_key)

    # create new entry for guest in keys.json and replace old
    info = {"public": b64encode(public_key).decode(),
            "symmetric": encrypted_sym_key,
            "owner": False,
            "approved": True}
    keys[guest_name] = info

    # recreate the json object
    keys = json.dumps(keys)

    # replace the keys.json on Dropbox with updated version
    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    # redirect to owner landing page
    return redirect("owner_landing")


def revoke_access(request, guest_name):
    # create Dropbox object for interfacing with remote folder
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    # retrieve keys.json from Dropbox
    _, k = dbx.files_download('/keys.json')

    # load keys.json into a dict
    keys = json.loads(k.content)
    # delete the guest's entry from keys
    keys.pop(guest_name, None)

    # recreate the json object
    keys = json.dumps(keys)

    # replace the keys.json on Dropbox with updated version
    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    # redirect to owner landing page
    return redirect("owner_landing")


def initialise(request):
    # retrieve owner name from text input box
    name = request.POST['owner_name'].lower()
    # use crypto utils to generate RSA key pair
    private_key, public_key = crypto.generate_key_pair()

    symmetric_key = crypto.generate_symmetric_key()

    # create Dropbox object for interfacing with remote folder
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    keys = {}

    # use crypto utils to generate symmetric key
    encrypted_sym_key = crypto.encrypt_sym_key(public_key, symmetric_key)

    # prepare the owner's keys.json entry
    info = {"public": b64encode(public_key).decode(),
            "symmetric": encrypted_sym_key,
            "owner": True,
            "approved": True}
    keys[name] = info

    # create json object from keys dict
    keys = json.dumps(keys)

    # delete any existing keys.json and replace with new
    dbx.files_delete('/keys.json')
    dbx.files_upload(keys.encode(), '/keys.json')

    # redirect to owner_landing_page
    return redirect("owner_landing")
