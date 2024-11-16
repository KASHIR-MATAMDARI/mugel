import re
import struct
import pefile
import string
from capstone import *
import matplotlib.pyplot as plt

def read_binary_file(file_path):
    with open(file_path, "rb") as file:
        return file.read()

def hex_representation(binary_data):
    return ' '.join(f'{byte:02x}' for byte in binary_data)

def extract_strings(binary_data, min_length=4):
    ascii_re = f'[{re.escape(string.printable)}]{{{min_length},}}'
    unicode_re = f'(?:[\x20-\x7E][\x00]){{{min_length},}}'
    
    ascii_strings = re.findall(ascii_re, binary_data.decode(errors='ignore'))
    unicode_strings = [s.decode('utf-16le') for s in re.findall(unicode_re, binary_data)]
    
    return ascii_strings + unicode_strings

def disassemble_code(binary_data, arch=CS_ARCH_X86, mode=CS_MODE_32):
    md = Cs(arch, mode)
    instructions = []
    for i in md.disasm(binary_data, 0x1000):
        instructions.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
    return instructions

def parse_pe_headers(file_path):
    pe = pefile.PE(file_path)
    return {
        'DOS_HEADER': pe.DOS_HEADER.dump_dict(),
        'FILE_HEADER': pe.FILE_HEADER.dump_dict(),
        'OPTIONAL_HEADER': pe.OPTIONAL_HEADER.dump_dict(),
        'SECTIONS': [section.dump_dict() for section in pe.sections]
    }

def find_embedded_files(binary_data):
    signatures = {
        b'\x50\x4b\x03\x04': 'ZIP file',
        b'\x89\x50\x4e\x47': 'PNG image',
        b'\xFF\xD8\xFF\xE0': 'JPEG image',
        b'\x25\x50\x44\x46': 'PDF document',
        # Add more signatures as needed
    }
    found_files = {}
    for signature, filetype in signatures.items():
        pos = binary_data.find(signature)
        if pos != -1:
            found_files[filetype] = pos
    return found_files

def calculate_entropy(binary_data):
    import math
    from collections import Counter
    byte_count = Counter(binary_data)
    total_bytes = len(binary_data)
    entropy = -sum((count / total_bytes) * math.log2(count / total_bytes) for count in byte_count.values())
    
    # Plot entropy
    window_size = 256  # Adjust as needed
    entropy_values = [
        -sum((window.count(byte) / window_size) * math.log2(window.count(byte) / window_size) for byte in set(window))
        for i in range(0, len(binary_data), window_size) if len(window := binary_data[i:i+window_size]) == window_size
    ]
    
    plt.plot(entropy_values)
    plt.title("Entropy Plot")
    plt.xlabel("Offset")
    plt.ylabel("Entropy")
    plt.show()
    
    return entropy

def analyze_file(file_path):
    binary_data = read_binary_file(file_path)
    hex_data = hex_representation(binary_data)
    print(f"Hex representation of {file_path}:")
    print(hex_data)

    # Additional features
    strings = extract_strings(binary_data)
    print("Extracted Strings:")
    for s in strings:
        print(s)
    
    disassembly = disassemble_code(binary_data)
    print("Disassembled Code:")
    for instruction in disassembly:
        print(instruction)

    pe_headers = parse_pe_headers(file_path)
    print("PE Headers:")
    for header, data in pe_headers.items():
        print(header)
        print(data)

    embedded_files = find_embedded_files(binary_data)
    print("Embedded Files:")
    for filetype, position in embedded_files.items():
        print(f"{filetype} found at position {position}")

    entropy = calculate_entropy(binary_data)
    print(f"Entropy: {entropy}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python mugel.py <file_path>")
    else:
        analyze_file(sys.argv[1])
