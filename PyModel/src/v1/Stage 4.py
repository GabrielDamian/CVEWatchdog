#util to collect sorted token keys and values

def read_file_content(path):
    try:
        with open(path, 'r') as fisier:
            continut = fisier.read()
        return continut
    except FileNotFoundError:
        return "Fisierul nu a fost gasit."
    except Exception as e:
        return f"A intervenit o eroare: {str(e)}"

def parse_file_and_sort(content):
    lines = content.split("\n")
    parsed = []
    for a in lines:
        try:
            element  = a.split(" ")
            value = element[0]
            frec = int(element[1])
            parsed.append([value, frec])
        except:
            continue
    parsed.sort(key=lambda x: x[1], reverse=True)
    return parsed

if __name__ == "__main__":
    groups = {}

    cve_codes = [
        'CVE-2024-3566',
        'CVE-2024-27983',
        'CVE-2024-30260',
    ]

    for a in cve_codes:
        # file_name = './Stage 3/CVE-2024-3566.txt'
        file_name = f'./Stage 3/{a}.txt'
        content = read_file_content(file_name)
        sorted = parse_file_and_sort(content)
        groups[a] = sorted

    excluded_groups = {}

    for a in groups:
        excluded_groups[a] = []
        #for the current CVE code [a], keep the element only if they exists only in a key
        for token in groups[a]:
            unique_to_group_A = True
            for b in groups:
                if b != a: #ignore the current group
                    for possible_duplicated_token in groups[b]:
                        if possible_duplicated_token[0] == token[0]:
                            unique_to_group_A = False
                            break
            if unique_to_group_A == True:
                excluded_groups[a].append(token)


    for a in excluded_groups:
        print(a)
        for b in excluded_groups[a]:
            print(b)
