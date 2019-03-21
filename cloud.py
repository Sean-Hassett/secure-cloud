# https://www.dropbox.com/developers/reference/getting-started#writing%20a%20script

import dropbox
import json


def process_folder_entries(current_state, entries):
    for entry in entries:
        if isinstance(entry, dropbox.files.FileMetadata):
            current_state[entry.path_lower] = entry
        elif isinstance(entry, dropbox.files.DeletedMetadata):
            current_state.pop(entry.path_lower, None)  # ignore KeyError if missing
    return current_state


with open("config.json") as f:
    data = json.load(f)

dbx = dropbox.Dropbox(data["access"])
result = dbx.files_list_folder(path="")


files = process_folder_entries({}, result.entries)

print(files)

# check for and collect any additional entries
while result.has_more:
    result = dbx.files_list_folder_continue(result.cursor)
    files = process_folder_entries(files, result.entries)

print(files)
