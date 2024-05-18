import os
import json

#Identify project type (receive a folder and return the project type and target deps file )
def check_node_project(file_path):
    #file_path este fisierul package.json

    if not os.path.isfile(file_path):
        # print(f"Fișierul '{file_path}' nu există.")
        return False

    if os.path.basename(file_path) == 'package.json':
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                if 'name' in data and 'dependencies' in data:
                    # print(f"Fișierul '{file_path}' este un fișier 'package.json' pentru un proiect Node.js.")
                    return True
                else:
                    # print(f"Fișierul '{file_path}' este un fișier 'package.json', dar nu conține informații complete pentru un proiect Node.js.")
                    return False
        except json.JSONDecodeError:
            # print(f"Eroare la decodarea fișierului JSON '{file_path}'.")
            return False
    else:
        # print(f"Fișierul '{file_path}' nu este un fișier 'package.json'.")
        return False

#Extractors (returns updated deps and versions)
def NODE_extractor(pull_request_folder):
    #compare content from:
    #{pull_request_folder}/before/package.json
    #{pull_request_folder}/after/package.json

    #return deleted dependencies as (one per line)
    #<name>:<version>:<project_type>

    before_path = f"{pull_request_folder}/before/package.json"
    after_path = f"{pull_request_folder}/after/package.json"

    packageBefore =  readJsonFile(before_path)
    packageAfter =  readJsonFile(after_path)

    #failed to parse package.json
    if packageBefore == None or packageAfter == None:
        return None

    depsBefore = packageBefore["dependencies"]
    depsAfter = packageAfter["dependencies"]

    removedDeps = ""
    for beforeDepKey in depsBefore.keys():
        clearBeforeDepValue = depsBefore[beforeDepKey].replace("^","").replace("~","")
        depsExists = False
        for afterDepKey in depsAfter.keys():
            clearAfterDepValue = depsAfter[afterDepKey].replace("^","").replace("~","")
            if beforeDepKey == afterDepKey and clearBeforeDepValue == clearAfterDepValue:
                depsExists = True

        if depsExists == False:
            removedDeps +=f"{beforeDepKey}<|>{clearBeforeDepValue}<|>\n"

    return removedDeps


def SPRING_extractor():
    print("SPRING_extractor")

def RUBY_extractor():
    print("RUBY_extractor")

def PODS_extractor():
    print("CocoaPods_extractor")

EXTRACTOR ={
    'NODE': NODE_extractor,
    'SPRING': SPRING_extractor,
    'RUBY': RUBY_extractor,
    'PODS': PODS_extractor
}

def who_is_my_extractor(pull_request_folder):
    #pull_request_folder is a folder that contains:
    #before folder
    #after folder

    #TODO:
    #1 - enter any of the folders
    #2 - try to identify a specific dependecy file (package.json, ruby, pods)
    #3 - return key for that specific project type
    #4 - return None is can't identify project type/extractor

    if check_node_project(f"{pull_request_folder}/before/package.json") == True:
        return  "NODE"

    return  None


def check_folder_existence(folder):
    if not os.path.isdir(folder):
        try:
            os.makedirs(folder)
            # print(f"Folderul a fost create: '{folder}'")
        except OSError as e:
            # print(f"Eroare creare folder:'{folder}': {e}")
            pass
    else:
        # print(f"Folderul exista deja:'{folder}'")
        pass

def append_to_file(file_path, text):
    if not os.path.isfile(file_path):
        try:
            with open(file_path, 'w'):
                pass  # Creăm fișierul gol
        except OSError as e:
            pass
            # print(f"Eroare creare fisier'{file_path}': {e}")

    try:
        with open(file_path, 'a') as f:
            f.write(text)
    except OSError as e:
        pass
        # print(f"Eroare la adaugarea textului in fisier:'{file_path}': {e}")

def readJsonFile(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data
    except json.JSONDecodeError:
        return None

def folder_iterator(cve_code):

    folder = f"./Stage 2/{cve_code}"
    check_folder_existence("./Stage 3")


    if not os.path.exists(folder):
        return []

    pull_requests_folders = os.listdir(folder)

    for pull_request_item in pull_requests_folders:
        this_pr_extractor = who_is_my_extractor(f"./Stage 2/{cve_code}/{pull_request_item}")
        if this_pr_extractor is not None:
            this_pr_vuln_dependencies =EXTRACTOR[this_pr_extractor](f"./Stage 2/{cve_code}/{pull_request_item}") #returns string (one deps per line)
            print("this_pr_vuln_dependencies:",this_pr_vuln_dependencies)
            if this_pr_vuln_dependencies != None and len(this_pr_vuln_dependencies) > 0:
                print(f"FINAL OK:{cve_code}", this_pr_vuln_dependencies)
                append_to_file(f"./Stage 3/{cve_code}.txt",this_pr_vuln_dependencies)


if __name__ == "__main__":

    cve_codes = [
        'CVE-2024-3566',
        'CVE-2024-27983',
        # 'CVE-2024-30260',
        # 'CVE-2024-30261',
        # 'CVE-2024-22025',
        # 'CVE-2024-22017',
        # 'CVE-2024-22019',
        # 'CVE-2024-21896',
        # 'CVE-2024-21892',
        # 'CVE-2024-21890',
    ]

    for cve_code in cve_codes:
        folder_iterator(cve_code)

    #FROM Stage 2
    #--/Stage 2/cveCODE
    #--/Stage 2/cveCODE/pr_name
    #--/--/--before & after

    #for each CVE CODE create a file that contains per line one dependecy that is vulnerable
    #for each cve, for each pull request, use before and after inside the COMPARATOR
    #COMPARATOR => vulnerable dependecies and their version
    #<name>:<version>:<project_type> (where project type will be local defined into this app (example: react, node, spring boot, etc))
    # (one per line)(write those line under the CVE CODE file)


