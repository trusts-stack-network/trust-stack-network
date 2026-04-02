#!/usr/bin/env python3
"""
Vérifie que la taille de l’image Docker reste sous le seuil.
Usage: size_check.py <size> <max>
"""
import sys
from humanfriendly import parse_size

def main():
    if len(sys.argv) != 3:
        print("Usage: size_check.py <size> <max>")
        sys.exit(1)
    size = parse_size(sys.argv[1])
    max_size = parse_size(sys.argv[2])
    if size > max_size:
        print(f"❌ Image trop grosse : {size} > {max_size}")
        sys.exit(1)
    print(f"✅ Taille OK : {size} <= {max_size}")

if __name__ == "__main__":
    main()