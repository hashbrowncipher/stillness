from ctypes import string_at
from io import BytesIO
import struct
import sys

from elftools.elf.elffile import ELFFile

def convert_hex(x):
    return int(x, 16)

def get_vdso_map():
    with open("/proc/self/maps", "r") as fh:
        for line in fh:
            if not line.endswith("[vdso]\n"):
                continue

            return line.strip()

def get_vdso_bytes():
    vdso_line = get_vdso_map()
    start, end = map(convert_hex, vdso_line.split()[0].split("-"))
    return string_at(start, end - start)

def get_version(vdso): 
    notes = vdso.get_section_by_name(".note")
    print(list(notes.iter_notes()))
    version_note = next(n.n_descdata for n in notes.iter_notes() if n.n_name == "Linux" and n.n_type == 0)
    sublevel, patch, major = struct.unpack('BBBx', version_note)
    return major, patch, sublevel

def main():
    vdso = get_vdso()
    vdso_file = BytesIO(vdso)
    vdso = ELFFile(vdso_file)
    print(list(vdso.iter_sections()))
    print(get_version(vdso))
    return 0

vdso = get_vdso_bytes()
with open("vdso.so", "wb") as fh:
    fh.write(vdso)
