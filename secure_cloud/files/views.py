from django.shortcuts import render, redirect
from django.http import HttpResponse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import dropbox
import json
from base64 import b64decode
from secure_cloud.utils import crypto


def view_files(request, username):
    # helper function for processing files, taken from Dropbox documentation
    # https://www.dropbox.com/developers/reference/getting-started#writing%20a%20script
    def process_folder_entries(current_state, entries):
        for entry in entries:
            if isinstance(entry, dropbox.files.FileMetadata):
                current_state[entry.path_lower] = entry
            elif isinstance(entry, dropbox.files.DeletedMetadata):
                current_state.pop(entry.path_lower, None)
        return current_state

    # create Dropbox object for interfacing with remote folder
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    # build list of files from remote folder
    result = dbx.files_list_folder(path="")
    files = process_folder_entries({}, result.entries)

    # check for and collect any additional entries
    while result.has_more:
        result = dbx.files_list_folder_continue(result.cursor)
        files = process_folder_entries(files, result.entries)

    # create list of only the file names, ignoring the keys.json file
    filenames = []
    for filename in sorted(files):
        if filename != "/keys.json":
            filenames.append(filename[1:])

    context = {"filenames": filenames,
               "username": username}

    # return the files list template with the list of file names
    return render(request, "files/files_list.html", context)


def download_file(request, filename, username):
    # create Dropbox object for interfacing with remote folder
    with open("secure_cloud/config/config.json", "r") as f:
        data = json.load(f)
    dbx = dropbox.Dropbox(data["access"])

    # load the active user's private key
    with open("secure_cloud/keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())

    # retrieve keys.json from Dropbox
    _, k = dbx.files_download('/keys.json')
    # load keys.json into a dict
    keys = json.loads(k.content)

    # load encrypted sym_key from user's entry in keys.json and user private key to decrypt
    encrypted_sym_key = b64decode(keys[username]["symmetric"].encode())
    sym_key = crypto.decrypt_sym_key(private_key, encrypted_sym_key)

    # use Dropbox object to download the requested file
    _, f = dbx.files_download('/' + filename)
    # use symmetric key to decrypt the downloaded contents
    decrypted_file_contents = crypto.decrypt_file(sym_key, f.content)

    # build HTTP attachment response with decrypted file contents as payload
    response = HttpResponse(decrypted_file_contents)
    response['content_type'] = ''
    response['Content-Disposition'] = 'attachment;filename={}'.format(filename[:-len(".encrypted")])

    return response


def upload_file(request, username):
    if request.method == 'POST' and request.FILES['upfile']:
        # read the uploaded file via the POST request
        up_file = request.FILES['upfile']

        # create Dropbox object for interfacing with remote folder
        with open("secure_cloud/config/config.json", "r") as f:
            data = json.load(f)
        dbx = dropbox.Dropbox(data["access"])

        # load the active user's private key
        with open("secure_cloud/keys/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())

        # retrieve keys.json from Dropbox
        _, k = dbx.files_download('/keys.json')
        # load keys.json into a dict
        keys = json.loads(k.content)

        # load encrypted sym_key from user's entry in keys.json and user private key to decrypt
        encrypted_sym_key = b64decode(keys[username]["symmetric"].encode())
        sym_key = crypto.decrypt_sym_key(private_key, encrypted_sym_key)

        # use symmetric key to encrypt the file contents
        encrypted_file_contents = crypto.encrypt_file(sym_key, up_file.file)
        # append .encrypted extetion to file name and use Dropbox object to upload
        encrypted_file_name = "/{}.encrypted".format(up_file.name)
        dbx.files_upload(encrypted_file_contents, encrypted_file_name)

    # redirect back to the files list view
    return redirect("files:view_files", username)
