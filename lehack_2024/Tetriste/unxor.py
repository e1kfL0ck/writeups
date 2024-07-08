# Read the content of the file as binary
file_path = '/home/e1k/Documents/Cyber/CTFs/writeup/lehack_2024/Tetriste/bits_logo.txt'
with open(file_path, 'rb') as file:
    input_bytes = file.read()

# Define the capital letters A-Z in bytes
capital_letters = [ord(letter) for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]

# Function to convert bytes to UTF-8 characters, handling errors
def bytes_to_utf8(byte_list):
    return bytes(byte_list).decode('utf-8', errors='replace')

# Perform XOR operation between the table of bytes and each capital letter
resulting_tables = {}
for letter in capital_letters:
    resulting_table = [byte ^ letter for byte in input_bytes]
    resulting_tables[chr(letter)] = bytes_to_utf8(resulting_table)


# Print the resulting tables
for letter, result in resulting_tables.items():
    print(f"Resulting table after XOR with '{letter}': {result}")
