import os
from dotenv import load_dotenv
import requests


def search_github_pull_requests(query, token):
    url = 'https://api.github.com/search/issues?q=is:pr'
    params = {'q': query, 'type': 'pr'}
    headers = {'Authorization': f'token {token}'}

    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        data = response.json()
        pull_requests = data.get('items', [])
        for pr in pull_requests:
            yield pr
    else:
        print("Error occurred while fetching pull requests:", response.text)


def get_pr_files(pr_files_url, token):
    headers = {'Authorization': f'token {token}'}
    response = requests.get(pr_files_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        files = [{'filename': file['filename'], 'status': file['status'], 'patch': file['patch']} for file in data]
        return files
    else:
        print("Error occurred while fetching pull request files:", response.text)
        return None


def main():
    load_dotenv()  # încarcă variabilele de mediu din fișierul .env
    query = 'expressjs'
    token = os.getenv('GITHUB_TOKEN')  # citește token-ul din variabila de mediu

    for index, pr in enumerate(search_github_pull_requests(query, token), start=1):
        print("PR:", pr)


if __name__ == "__main__":
    main()
