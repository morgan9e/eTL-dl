import json
import urllib.parse
import os
import sys
from datetime import datetime
from bs4 import BeautifulSoup as bs
import requests

SNU_NM = ""
SNU_PW = ""

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
API = "https://myetl.snu.ac.kr/api"

class Session(requests.Session):
    def rget(self, url, headers=None):
        csrf = self.cookies.get('_csrf_token')
        csrf = urllib.parse.unquote(csrf) if csrf else ""

        defaults = {
            "user-agent": UA,
            "X-CSRF-Token": csrf,
            "accept": "application/json",
        }
        merged_headers = {**defaults, **(headers or {})}

        resp = self.get(url, headers=merged_headers)
        if resp.status_code != 200:
            raise requests.HTTPError(f"{resp.status_code}: {resp.text}", response=resp)
        return resp.json()


def etl_login():
    sess = Session()
    resp = sess.get("https://myetl.snu.ac.kr/login/canvas")
    soup = bs(resp.text, 'html.parser')
    form = soup.find('form', {'id': 'login_form'})
    inputs = form.find_all('input')
    payload = {inp.get('name'): inp.get('value', '') for inp in inputs}
    payload["pseudonym_session[unique_id]"] = SNU_NM
    payload["pseudonym_session[password]"] = SNU_PW
    resp = sess.post("https://myetl.snu.ac.kr/login/canvas", data=payload, headers={"referer": "https://myetl.snu.ac.kr/login/canvas"})
    return sess


def sync_etl(sess, lecture, name = ""):
    basepath = "./download"
    root = sess.rget(f"{API}/v1/courses/{lecture}/folders/root")
    print(f"{root['id']} {root['full_name']}")

    def get_subpath(dir, parent = []):
        files = []
        depth = len(parent)
        resp = sess.rget(f"{API}/v1/folders/{dir}/files?include%5B%5D=user&include%5B%5D=usage_rights&include%5B%5D=enhanced_preview_url&include%5B%5D=context_asset_string&per_page=200&sort=&order=")
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

        resp = sess.rget(f"{API}/v1/folders/{dir}/folders?include%5B%5D=user&include%5B%5D=usage_rights&include%5B%5D=enhanced_preview_url&include%5B%5D=context_asset_string&per_page=200&sort=&order=")
        for folder in resp:
            print("   " * depth + f"|- {folder['id']:<7} {folder['name']:<48}")
            files += get_subpath(folder["id"], parent + [folder['name']])

        return files

    files = get_subpath(root["id"], [f"{name or lecture}"])
    print()

    for file in files:
        local_dir = "/".join([i.replace(" ","_") for i in [i for i in file['path'] if i != "unfiled"]])
        if basepath:
            local_dir = os.path.join(basepath, local_dir)
        local_path = os.path.join(local_dir, file['display_name'].replace(" ","+"))
        
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
            resp = sess.rget(file['url'])
            with open(local_path, 'wb') as f:
                f.write(resp.content)
            
            os.utime(local_path, (file['mt'], file['mt']))
            
        except Exception as e:
            print(f"- Failed {local_path}: {str(e)}")
            if os.path.exists(local_path):
                os.remove(local_path)
        

def list_courses(sess):
    db_crcs = sess.rget("https://myetl.snu.ac.kr/api/v1/dashboard/dashboard_cards")
    return db_crcs
    # courses = sess.rget(f"{API}/v1/courses?per_page=200")
    # courses.sort(key = lambda x: x['id'])
    # latest_term = courses[-1]['enrollment_term_id']
    # return [i for i in courses if i.get('enrollment_term_id') == latest_term]


def main():
    sess = etl_login()
    courses = list_courses(sess)
    print()
    print(f"== Found {len(courses)} lectures ==")
    for c in courses:
        print(f"{c['id']} - {c['courseCode']}")
    print()
    print("== Downloading ==")
    for c in courses:
        sync_etl(sess, c['id'])

if __name__=="__main__":
    main()