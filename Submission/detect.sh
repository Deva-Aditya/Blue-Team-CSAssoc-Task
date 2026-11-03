#!/usr/bin/env python3

import sys

def decrypt_line(text, key):
    def udeshift(char, key):
        a = ord(char) - ord("A")
        b = (a - ord(key) + ord("A"))%26
        return(chr(b + ord("A")))

    def ldeshift(char, key):
        a = ord(char) - ord("a")
        b = (a - ord(key) + ord("a"))%26
        return(chr(b + ord("a")))

    length = len(key)
    lkey = key.lower()
    decrypt = ""
    k = 0

    for i in range (0, len(text)):
        if text[i].isalpha():
            if text[i].isupper():
                decrypt += udeshift(text[i], key[k%length])

            else:
                
                decrypt += ldeshift(text[i], lkey[k%length])
            
            k += 1

        else:
            decrypt += text[i]

    return decrypt

def decrypt_text(text, key):
    array = text.splitlines()

    decrypt = ""

    for i in range (0, len(array)):
        decrypt += decrypt_line(array[i], key) + "\n"

    return decrypt

if len(sys.argv) < 3:
    print("Usage: ./detect.sh <encrypted_log_file> <key>")
    sys.exit(2)

file_path = sys.argv[1]
b = sys.argv[2].upper()

with open(file_path, "r", encoding="utf-8") as file:
    file_input = file.read()

result = decrypt_text(file_input, b)

logs = result.splitlines()

bruf = {}
bf = {}
tb = {}
sql = {}
trav = {}

for i in logs:
    q = i.split()
    if i.count("../"):
        trav[q[0]] = trav.get(q[0], 0) + 1
        print(f"{q[3]}] [HIGH] Directory traversal detected from {q[0]}")


    if " OR 1=1" in i or " OR '1'='1'" in i or "DROP TABLE" in i:
        sql[q[0]] = sql.get(q[0], 0) + 1
        print(f"{q[3]}] [HIGH] SQL injection detected from {q[0]}")


    if " 401 " in i:
        bruf[q[0]] = bruf.get(q[0], 0) + 1
        if q[0] in tb:
            tb[q[0]].append(q[3] + "]")

        else:
            tb[q[0]] = [q[3] + "]"]

for i, j in bruf.items():
    if j >= 5:
        bf[i] = j

for i in bf:
    for j in tb[i]:
        print(f"{j} [HIGH] Brute force detected from {i}")

print("\n")

for i in bf:
    print(f"[ALERT] Brute force from {i} ({bf[i]} failed logins)")

print("\n")

for i in sql:
    print(f"[ALERT] SQL injection from {i} ({sql[i]} attempts)")

print("\n")

for i in trav:
    print(f"[ALERT] Directory traversal from {i} ({trav[i]} attempts)")

print("\n")


if len(bf) == 0 and len(sql) == 0 and len(trav) == 0:
    sys.exit(0)

else:
    sys.exit(1)