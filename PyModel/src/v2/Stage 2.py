import os
import git
import base64
import shutil
import difflib
import requests
from git import Repo
from io import StringIO
from difflib import unified_diff

def get_files_after_pr(pr_url):
    parts = pr_url.split('/')
    username = parts[-4]
    repo_name = parts[-3]

    pr_number = parts[-1]

    diff_url = f"https://api.github.com/repos/{username}/{repo_name}/pulls/{pr_number}/files"

    response_diff = requests.get(diff_url)
    diff_details = response_diff.json()

    files_after_pr = []

    for file in diff_details:
        file_name = file['filename']
        response_file = requests.get(file['raw_url'])
        content = response_file.text
        files_after_pr.append({
            'file_name': file_name,
            'content': content
        })

    return files_after_pr
def clear_folder(folder_path):
    try:
        if os.path.exists(folder_path):
            for file in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            print("Folderul a fost golit cu succes!" +folder_path)
        else:
            os.makedirs(folder_path)
            print("Folderul a fost creat cu succes! " +folder_path)
    except Exception as e:
        print(f"Eroare în timpul procesării folderului: {e}")

def write_to_file_in_folder(folder_path, file_name, content):
    try:
        file_path = folder_path + "/" + file_name
        with open(file_path, 'w') as file:
            file.write(content)
    except Exception as e:
        print(f"Eroare la scrierea in fisier: {e}")
def get_diff_content(diff_url):
    try:
        response = requests.get(diff_url)

        if response.status_code == 200:
            return response.text
        else:
            print(f"Eroare la cererea GET: Cod de stare {response.status_code}")
            return None
    except Exception as e:
        print(f"GET error: {e}")
        return None

def revert_changes(diff_file_path, folder_path):
    repo = git.Repo.init(folder_path)
    repo.git.apply('--reverse', diff_file_path)
def diff_root_parser(diff_content):
    lines = diff_content.split("\n")
    refactor_lines = ""
    for line in lines:
        if len(line) > 3 and line[:3] == "---":
            line_tokens = line.split("/")
            new_line = f"--- a/{line_tokens[-1]}"
            refactor_lines += new_line + "\n"
        elif len(line) > 3 and line[:3] == "+++":
            line_tokens = line.split("/")
            new_line = f"+++ b/{line_tokens[-1]}"
            refactor_lines += new_line + "\n"

        else:
            refactor_lines += line + "\n"

    return refactor_lines
def pull_request_extractor(cve_code,pr_url):
    files_after_pr = get_files_after_pr(pr_url)
    pr_links_tokens = pr_url.split("/")
    result_folder_name = pr_links_tokens[3] + "__" + pr_links_tokens[4] + "__" + pr_links_tokens[6]

    clear_folder("./Stage 2")
    clear_folder(f"./Stage 2/${cve_code}")
    clear_folder(f"./Stage 2/{cve_code}/{result_folder_name}")

    before_path =f"./Stage 2/{cve_code}/{result_folder_name}/after"
    after_path = f"./Stage 2/{cve_code}/{result_folder_name}/before"

    clear_folder(before_path)
    clear_folder(after_path)

    for file in files_after_pr:
        file_name =file['file_name']
        content = file['content']
        pure_file_name = file_name.split("/")[-1]
        write_to_file_in_folder(before_path, pure_file_name, content)
        write_to_file_in_folder(after_path, pure_file_name, content)

    diff_link = f"{pr_url}.diff"
    diff_content = get_diff_content(diff_link)
    diff_content = diff_root_parser(diff_content)

    write_to_file_in_folder(after_path,"magic.diff", diff_content)
    revert_changes("magic.diff",after_path)

    return  "<key>:<value>"

def scrie_text_in_fisier(text, nume_fisier, cve_folder):
    folder = "./Stage 2"
    try:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print("Folderul", folder, "a fost creat cu succes.")

        folder   = folder + "/" + cve_folder
        if not os.path.exists(folder):
            os.makedirs(folder)
            print("Folderul", folder, "a fost creat cu succes.")

        cale_fisier = os.path.join(folder, nume_fisier)

        with open(cale_fisier, 'w') as fisier:
            fisier.write(text)

        print("Text scris cu succes in ", cale_fisier)
    except Exception as e:
        print("Eroare la scrierea in fisier:", str(e))
def open_files_for_cve(cve_code):
    folder = f"./Stage 1/{cve_code}"

    if not os.path.exists(folder):
        return []

    lista_fisiere = os.listdir(folder)

    for nume_fisier in lista_fisiere:
        cale_fisier = os.path.join(folder, nume_fisier)

        if os.path.isfile(cale_fisier):
            with open(cale_fisier, 'r') as fisier:
                continut = fisier.read()
                lines = continut.split("\n")

                parsed_diffs =""
                for diff_link in lines:
                    raw_pr_link =  diff_link[:-5]
                    vulnerable_depencies_str = None

                    try:
                        #TODO: write extracted vulnerable dependecies into a dedicate file to this specific CVE
                        vulnerable_depencies_str = pull_request_extractor(cve_code, raw_pr_link)
                    except Exception as e:
                        print("Failed link:", e)
                    if vulnerable_depencies_str is not None:
                        parsed_diffs += vulnerable_depencies_str

                # if len(parsed_diffs) > 0:
                #     scrie_text_in_fisier(parsed_diffs, nume_fisier, cve_code)

if __name__ == "__main__":
    cve_codes = [
        'CVE-2024-3566',
        'CVE-2024-27983',
        'CVE-2024-30260',
        # 'CVE-2024-30261',
        # 'CVE-2024-22025',
        # 'CVE-2024-22017',
        # 'CVE-2024-22019',
        # 'CVE-2024-21896',
        # 'CVE-2024-21892',
        # 'CVE-2024-21890',
    ]

    for cve_code in cve_codes:
        open_files_for_cve(cve_code)



