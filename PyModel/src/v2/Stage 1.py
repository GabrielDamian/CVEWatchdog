#Collect GitHub commits

import os
from dotenv import load_dotenv
import requests
import json
import time
from datetime import datetime, timedelta

def append_to_json_file(obj_array, file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
    else:
        data = []

    data.extend(obj_array)

    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)
def append_to_file(text, cve_code, file_name):
    path = "./Stage 1/" + cve_code
    if not os.path.exists(path):
        os.makedirs(path)
        print("Folderul", path, "a fost creat cu succes.")
    else:
        print("Folderul", path, "există deja.")

    full_path = path +"/"+ file_name
    try:
        with open(full_path, 'a') as file:
            file.write(text)
            file.write('\n')
    except FileNotFoundError:
        print("Fișierul", file_name, "nu a fost găsit.")
    except Exception as e:
        print("A apărut o eroare în timpul adăugării textului în fișier:", str(e))
def search_github_pull_requests(query, token, per_page, page, path_to_save,search_date_str ):
    time.sleep(1)
    url = 'https://api.github.com/search/issues'
    params = {'q': query, 'type': 'pr', 'per_page': per_page, 'page': page}
    params = {'q': f'{query} updated:{search_date_str}', 'type': 'pr', 'per_page': per_page, 'page': page}

    print("params check:", params)
    headers = {'Authorization': f'token {token}'}

    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        data = response.json()
        pull_requests = data.get('items', [])
        print(f"new: page={page} items={len(pull_requests)}")
        filter_prs = list(filter(lambda x: 'pull_request' in x, pull_requests))

        if len(filter_prs) > 0:
            #extract only desired keys
            str_ = ""
            for i, a in enumerate(filter_prs):
                str_ += a['pull_request']["diff_url"]
                if i != len(filter_prs) - 1:  # Verificăm dacă nu suntem la ultimul element
                    str_ += "\n"

            #save
            append_to_file(str_, query, path_to_save)

        return len(pull_requests)

    else:
        print("Error occurred while fetching pull requests:", response.text)
        return 0

def main():
    load_dotenv()
    token = os.getenv('GITHUB_TOKEN')  # citește token-ul din variabila de mediu

    per_page = 100
    max_pages_per_day = 10
    days_to_search = 30 #behind the current day

    #TODO: collect the next CVE codes list from the next link: https://www.cvedetails.com/vulnerability-list/vendor_id-12113/Nodejs.html
    #TODO: try also commits api, not only issues (pr) api

    cve_codes = [
        'CVE-2024-3566',
        'CVE-2024-27983',
        'CVE-2024-30260',
        'CVE-2024-30261',
        'CVE-2024-22025',
        'CVE-2024-22017',
        'CVE-2024-22019',
        'CVE-2024-21896',
        'CVE-2024-21892',
        'CVE-2024-21890',
    ]

    current_date = datetime.now().date()
    skip_remaining_pages = False

    for cve_code in cve_codes:
        for i in range(days_to_search):
            search_date = current_date - timedelta(days=i)
            search_date_str = search_date.strftime('%Y-%m-%d')

            skip_remaining_pages = False
            for page_index in range(1, max_pages_per_day + 1) :
                if skip_remaining_pages == False:
                    print(f"Searching for CVE={cve_code}  DATE={search_date_str} PAGE={page_index}")
                    path_to_save = f"date={search_date_str}.txt"
                    items_len = search_github_pull_requests(query=cve_code, token=token, per_page=per_page, page=page_index, path_to_save=path_to_save,search_date_str=search_date_str )
                    if items_len == 0:
                        skip_remaining_pages = True

if __name__ == "__main__":
    main()
