import json
import urllib.parse
import os
import sys
from datetime import datetime
from login import etl_login

sess = etl_login()
csrf = sess.cookies.get('_csrf_token')
CSRF = urllib.parse.unquote(csrf)

auth = { "X-CSRF-Token": CSRF }

API = "https://myetl.snu.ac.kr/api"

def parse_while(t):
    t = t.replace("while(1);", "")
    return json.loads(t)


def rget(url, headers={}):
    resp = sess.get(url, headers=auth | headers)
    if resp.status_code != 200:
        print(resp.status_code, resp.text)
        sys.exit()
    return parse_while(resp.text)


def get_subpath(dir, parent = []):
    files = []
    depth = len(parent)
    resp = rget(f"{API}/v1/folders/{dir}/files?include%5B%5D=user&include%5B%5D=usage_rights&include%5B%5D=enhanced_preview_url&include%5B%5D=context_asset_string&per_page=200&sort=&order=")
    for file in resp:
        info = {
            'id': file['id'],
            'path': [i for i in parent],
            'name': urllib.parse.unquote(file['filename']),
            'display_name': urllib.parse.unquote(file['display_name']),
            'size': file['size'],
            'mt': datetime.strptime(file['modified_at'], "%Y-%m-%dT%H:%M:%SZ").timestamp(),
            'url': file['url']
        }
        files.append(info)

        print("   " * depth + f"|- {info['id']:<7} {info['display_name']:<48} {info['size']}    {file['modified_at']}")

    resp = rget(f"{API}/v1/folders/{dir}/folders?include%5B%5D=user&include%5B%5D=usage_rights&include%5B%5D=enhanced_preview_url&include%5B%5D=context_asset_string&per_page=200&sort=&order=")
    for folder in resp:
        print("   " * depth + f"|- {folder['id']:<7} {folder['name']:<48}")
        files += get_subpath(folder["id"], parent + [folder['name']])

    return files



def sync_etl(lecture, name = ""):
    basepath = "./"
    root = rget(f"{API}/v1/courses/{lecture}/folders/root")
    print()
    print(f"{root['id']} {root['full_name']}")
    files = get_subpath(root["id"], [f"{name or lecture}"])
    print()

    for file in files:
        local_dir = "/".join([i.replace(" ","_") for i in [i for i in file['path'] if i != "unfiled"]])
        if basepath:
            local_dir = os.path.join(basepath, local_dir)
        local_path = os.path.join(local_dir, file['display_name'])
        
        if not os.path.exists(local_dir):
            os.makedirs(local_dir, exist_ok=True)
        
        if os.path.exists(local_path):
            local_mtime = os.path.getmtime(local_path)
            local_size = os.path.getsize(local_path)
            if file['mt'] <= local_mtime and file['size'] == local_size:
                # print(f"- Skipping {local_path}")
                continue

        print(f"- Download {local_path}")
        try:
            resp = sess.get(file['url'], headers=auth)
            with open(local_path, 'wb') as f:
                f.write(resp.content)
            
            os.utime(local_path, (file['mt'], file['mt']))
            
        except Exception as e:
            print(f"- Failed {local_path}: {str(e)}")
            if os.path.exists(local_path):
                os.remove(local_path)
