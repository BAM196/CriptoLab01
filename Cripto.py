#!/usr/bin/env python3
import sys

def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base + corrimiento) % 26 + base)
        else:
            resultado += char
    return resultado

def main():
    if len(sys.argv) != 3:
        print("Uso: sudo python3 cesar.py \"texto a cifrar\" corrimiento")
        sys.exit(1)

    texto = sys.argv[1]
    try:
        corrimiento = int(sys.argv[2])
    except ValueError:
        print("El corrimiento debe ser un número entero.")
        sys.exit(1)

    print(cifrado_cesar(texto, corrimiento))

if __name__ == "__main__":
    main()
