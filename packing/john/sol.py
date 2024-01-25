BINARY_BASE = 0x8048000

def patch_binary(binary, path_file, address):
    with open(path_file, "rb") as f:
        patch = f.read()
    offset = address - BINARY_BASE
    patch_len = len(patch)
    binary = binary[:offset] + patch + binary[offset + patch_len:]
    return binary

with open("./john", "rb") as f:
    patch = f.read()

binary = patch_binary(patch, "./sixth_check_new.bin", 0x8049546)

with open("./john_patched_sixth_check_new", "wb") as f:
    f.write(binary)