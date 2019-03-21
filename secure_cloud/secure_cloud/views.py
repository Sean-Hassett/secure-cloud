from django.shortcuts import render, redirect
from django.http import HttpResponse
import dropbox
import json


def landing_page(request):
    return render(request, "secure_cloud/index.html")


def view_files(request):
    def process_folder_entries(current_state, entries):
        for entry in entries:
            if isinstance(entry, dropbox.files.FileMetadata):
                current_state[entry.path_lower] = entry
            elif isinstance(entry, dropbox.files.DeletedMetadata):
                current_state.pop(entry.path_lower, None)
        return current_state

    with open("secure_cloud/config.json") as f:
        data = json.load(f)

    dbx = dropbox.Dropbox(data["access"])
    result = dbx.files_list_folder(path="")

    files = process_folder_entries({}, result.entries)

    # check for and collect any additional entries
    while result.has_more:
        result = dbx.files_list_folder_continue(result.cursor)
        files = process_folder_entries(files, result.entries)

    filenames = [[file[1:]] for file in sorted(files)]
    for filename in filenames:
        filename.append("/files/download/" + filename[0])

    context = {"filenames": filenames}

    return render(request, "secure_cloud/files_list.html", context)


def download_file(request, filename):
    with open("secure_cloud/config.json") as f:
        data = json.load(f)

    dbx = dropbox.Dropbox(data["access"])
    metadata, f = dbx.files_download('/' + filename)
    print(f.content)

    response = HttpResponse(f.content)
    response['content_type'] = ''
    response['Content-Disposition'] = 'attachment;filename={}'.format(filename)
    return response
