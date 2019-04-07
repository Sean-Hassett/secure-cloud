from django.shortcuts import render, redirect
from django.http import HttpResponse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import dropbox
import json
from base64 import b64decode
from secure_cloud.utils import crypto


def view_files(request, username):
    def process_folder_entries(current_state, entries):
        for entry in entries:
            if isinstance(entry, dropbox.files.FileMetadata):
                current_state[entry.path_lower] = entry
            elif isinstance(entry, dropbox.files.DeletedMetadata):
                current_state.pop(entry.path_lower, None)
        return current_state

    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)

    dbx = dropbox.Dropbox(data["access"])
    result = dbx.files_list_folder(path="")
    files = process_folder_entries({}, result.entries)

    # check for and collect any additional entries
    while result.has_more:
        result = dbx.files_list_folder_continue(result.cursor)
        files = process_folder_entries(files, result.entries)

    filenames = []
    for filename in sorted(files):
        if filename != "/keys.json":
            filenames.append(filename[1:])

    context = {"filenames": filenames,
               "username": username}

    return render(request, "files/files_list.html", context)


def download_file(request, filename, username):
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    with open("secure_cloud/keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())

    _, k = dbx.files_download('/keys.json')
    keys = json.loads(k.content)
    encrypted_sym_key = b64decode(keys[username]["symmetric"].encode())
    sym_key = crypto.decrypt_sym_key(private_key, encrypted_sym_key)

    _, f = dbx.files_download('/' + filename)
    decrypted_file_contents = crypto.decrypt_file(sym_key, f.content)

    response = HttpResponse(decrypted_file_contents)
    response['content_type'] = ''
    response['Content-Disposition'] = 'attachment;filename={}'.format(filename[:-len(".encrypted")])

    return response


def upload_file(request, username):
    if request.method == 'POST' and request.FILES['upfile']:
        up_file = request.FILES['upfile']

        with open("secure_cloud/config/config.json", "r") as f:
            data = json.load(f)
        dbx = dropbox.Dropbox(data["access"])

        with open("secure_cloud/keys/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())

        _, k = dbx.files_download('/keys.json')
        keys = json.loads(k.content)
        encrypted_sym_key = b64decode(keys[username]["symmetric"].encode())
        sym_key = crypto.decrypt_sym_key(private_key, encrypted_sym_key)

        encrypted_file_contents = crypto.encrypt_file(sym_key, up_file.file)
        encrypted_file_name = "/{}.encrypted".format(up_file.name)
        dbx.files_upload(encrypted_file_contents, encrypted_file_name)

    return redirect("files:view_files", username)
