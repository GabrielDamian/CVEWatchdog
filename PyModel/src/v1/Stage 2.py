#Open text files
#For each object, GET .diff file
#Filter .diff files
#-keep only .diff files that have < 500 lines
                #-there must be < 5 files modified
            #-each file must have maximum 10 modifications (10 groups of '-')
            #-each modification must be < 10 lines
#- ???? keep only .js files (to be tested)

#Parse into tokens
#if the modification is < 50 chars and have 1 single line, also use as a single block
#else
#break the modification at: [" ", ",", ".", ":", "(", ")", "[", "]"]
#remove white spaces the the ends of each slice
#write tokens into a single line, separated by white space (" ")
#write tokens into files (maxim 1000 lines per file)
#each CVE code have it's own folder that contains the token files

#Create dictionary
#For each line(token), start mapping and clustering
import os
import re
import requests
def tokenize_complex_string(sir, separatori):

    tokens = []  # Lista pentru a stoca token-urile rezultate
    start = 0  # Variabila pentru a urmări începutul fiecărui slice

    for i, caracter in enumerate(sir):
        if caracter in separatori:
            # Dacă întâlnim un separator, adăugăm slice-ul de la start până la indexul actual în lista de token-uri
            tokens.append(sir[start:i])
            start = i + 1  # Actualizăm startul pentru următorul slice

    # Adăugăm ultimul slice, dacă există
    if start < len(sir):
        tokens.append(sir[start:])

    return tokens

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

def get_diff_content(link_diff):
    try:
        response = requests.get(link_diff)
        if response.status_code == 200:
            return response.text
        else:
            print("Can't GET", link_diff, "error:", response.status_code)
            return None
    except Exception as e:
        print("Error while GET diff link:",e)
        return None

def extract_diff_extensions(continut_diff):
    for linie in continut_diff.splitlines():
        if linie.startswith("--- a/"):
            cale = linie[6:]
            if '.' in cale:
                extensie = cale.split('.')[-1]
                return extensie
            else:
                return None
    # Dacă nu s-a găsit nicio linie care începe cu "--- a/", returnează mesaj de eroare
    return None

def parse_diff_content(diff_content):
    diff_file_extensions = extract_diff_extensions(diff_content)
    print("ext:",diff_file_extensions)

    allowed_ext = ['js', 'ts','json','yaml','xml','nvmrc',]
    if diff_file_extensions is None:
        return None
    if diff_file_extensions not in allowed_ext:
        return  None

    lines = diff_content.split("\n")
    groups = [] #each element (string) from this groups is a core input to our model
    current_group = ""

    for line in lines:
        if len(line) > 2 and line[0] == "-" and line[1] != "-":
            #item start with "-", so add it to the current group
            current_group   += line +"\n"
        else:
            #non group item, break pattern
            #restart current group
            if len(current_group) > 0:
                #need to create a new group
                groups.append(current_group)
                current_group = ""
            else:
                continue

#PARSE EACH GROUP
    #remove "-" from [0] specific to github and trim text
    #remove white spaces from both sides
    #TODO: filter by number of lines and group str len
        #split into tokens

    total_tokens = ""
    for a in groups:
        if len(a) > 5  and len(a) < 20:
            #include small tokens as block
            tokens_as_line = a[1:].strip()
            total_tokens +=  tokens_as_line + "\n"

        elif len(a) < 100:
            parsed_group = ""
            group_lines = a.split("\n")

            for b in group_lines: #b is a single line from a group
                new_line = b[1:].strip()
                parsed_group += new_line  +"\n"

            # separators = [' ', '(', ')', ',', '.', ':', '=', '+', '-', '*', '/', '"', "'", '//', '/*', '*/', "\n"]
            separators = [' ', "\n"]

            tokens_for_current_group = tokenize_complex_string(parsed_group, separators)
            #filter tokens len
            tokens_for_current_group = list(filter(lambda x: len(x) < 20, tokens_for_current_group))

            tokens_as_line = ""
            for token in tokens_for_current_group:
                tokens_as_line += token +" "
            total_tokens += tokens_as_line +"\n"

    return  total_tokens

def open_files_for_cve(cve_code):
    folder = f"./Stage 1/{cve_code}"

    if not os.path.exists(folder):
        return []

    lista_fisiere = os.listdir(folder)

    # open each file from folder
    for nume_fisier in lista_fisiere:
        # calea completa catre fisier
        cale_fisier = os.path.join(folder, nume_fisier)

        # Check if file exists
        if os.path.isfile(cale_fisier):
            with open(cale_fisier, 'r') as fisier:
                continut = fisier.read()
                lines = continut.split("\n")

                parsed_diffs =""

                print("to iterate:", len(lines))
                i = 0
                for diff_link in lines:
                    print(i)
                    i+=1

                    diff_content = get_diff_content(diff_link)
                    if diff_content is not None:
                        parsed_diff = parse_diff_content(diff_content)

                        if parsed_diff is not None:
                            print(" len parsed_diff:", len(parsed_diff))
                            parsed_diffs += parsed_diff

                print("-----parsed_diffs:",len(parsed_diffs))

                if len(parsed_diffs) > 0:
                    scrie_text_in_fisier(parsed_diffs, nume_fisier, cve_code)


if __name__ == "__main__":
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

    for cve_code in cve_codes:
        open_files_for_cve(cve_code)





