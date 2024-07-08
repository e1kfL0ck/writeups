# Initialiser x à 0
x = 0

file_path = '/home/e1k/Downloads/bytes.txt'
with open(file_path, 'rb') as file:
    input_bytes = file.read()

    for byte in input_bytes:
        x = x - byte - 1

# Afficher le résultat
print(f"Le résultat final de x est : {x}")
