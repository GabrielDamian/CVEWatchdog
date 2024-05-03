#Create dictionary for each CVE folder
#Create a CVE_x_dict.txt for each CVE

#Iterate Stage 2 folder for each CVE
#Open CVE_x_dict.txt as string and split into lines
#For each file (day), read content
#for each line, for each token, try to find token in dict
#if exists, then +1 counter
#else, create and init with 1
import os
def add_to_dict(cuvant,cve_code):
    nume_fisier = f"./Stage 3/{cve_code}.txt"

    if not os.path.exists("./Stage 3"):
        os.makedirs("./Stage 3")

    try:
        # Deschide fișierul în modul de citire și scriere
        with open(nume_fisier, 'r+') as fisier:
            linii = fisier.readlines()
            gasit = False
            for index, linie in enumerate(linii):
                cuvant_linie, frecventa = linie.strip().split(' ')
                if cuvant_linie == cuvant:
                    # Găsește cuvântul, actualizează frecvența
                    linii[index] = f"{cuvant} {int(frecventa) + 1}\n"
                    gasit = True
                    break
            if not gasit:
                # Cuvântul nu a fost găsit, adaugă-l cu frecvența 1
                linii.append(f"{cuvant} 1\n")
            # Rescrie întregul conținut al fișierului
            fisier.seek(0)
            fisier.writelines(linii)
            fisier.truncate()
        print(f"Vectorul de frecvență a fost actualizat pentru cuvantul '{cuvant}'.")
    except FileNotFoundError:
        print("Fișierul nu există, va fi creat.")
        # Crează fișierul și adaugă cuvântul cu frecvența 1
        with open(nume_fisier, 'w') as fisier:
            fisier.write(f"{cuvant} 1\n")
        print(f"Fișierul '{nume_fisier}' a fost creat și inițializat cu cuvantul '{cuvant}'.")

def iterate_stage_2_tokens(cve_folder):

    folder = f"./Stage 2/{cve_code}"
    if not os.path.exists(folder): return

    lista_fisiere = os.listdir(folder)

    for nume_fisier in lista_fisiere:
        cale_fisier = os.path.join(folder, nume_fisier)

        if os.path.isfile(cale_fisier):
            with open(cale_fisier, 'r') as fisier:
                continut = fisier.read()
                lines = continut.split("\n")
                for line in lines:
                    current_line_items = line.split(" ")
                    for token in current_line_items:
                        if len(token) > 0:
                            add_to_dict(token, cve_folder)


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
        iterate_stage_2_tokens(cve_code)

