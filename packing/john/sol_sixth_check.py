import z3

string_to_xored = b"\x0b\x4c\x0f\x00\x01\x16\x10\x07\x09\x38" + b"\x00"*21 + b"\xdd\xe7\x6f\xa6\x1c"

def FUN_08049546(input_flag, index: int):
    if (index < 11):
        known_char = z3.BitVecVal(string_to_xored[index], 8)
        print(known_char)
        #if (input_flag[index + 0x14] ^ known_char) == input_flag[index + 0x15]:
        if (z3.Extract((index+1)*8 - 1, (index)*8, input_flag) ^ known_char) == z3.Extract((index+2)*8 - 1, (index+1)*8, input_flag):
            uVar1 = FUN_08049546(input_flag, index + 1)
        else:
            uVar1 = 0
    else:
        uVar1 = 1
    return uVar1

#flag = z3.BitVec("flag", 12*8)
flag = [z3.BitVec(f'char{i}', 8) for i in range(12)]
solver = z3.Solver()

"""known_char = z3.BitVecVal(string_to_xored[0], 8)
solver.add((z3.Extract(7, 0, flag) ^ known_char) == z3.Extract(15, 8, flag))

known_char = z3.BitVecVal(string_to_xored[1], 8)
solver.add((z3.Extract(15, 8, flag) ^ known_char) == z3.Extract(23, 16, flag))

known_char = z3.BitVecVal(string_to_xored[2], 8)
solver.add((z3.Extract(23, 16, flag) ^ known_char) == z3.Extract(31, 24, flag))

known_char = z3.BitVecVal(string_to_xored[3], 8)
solver.add((z3.Extract(31, 24, flag) ^ known_char) == z3.Extract(39, 32, flag))

known_char = z3.BitVecVal(string_to_xored[4], 8)
solver.add((z3.Extract(39, 32, flag) ^ known_char) == z3.Extract(47, 40, flag))

known_char = z3.BitVecVal(string_to_xored[5], 8)
solver.add((z3.Extract(47, 40, flag) ^ known_char) == z3.Extract(55, 48, flag))

known_char = z3.BitVecVal(string_to_xored[6], 8)
solver.add((z3.Extract(55, 48, flag) ^ known_char) == z3.Extract(63, 56, flag))

known_char = z3.BitVecVal(string_to_xored[7], 8)
solver.add((z3.Extract(63, 56, flag) ^ known_char) == z3.Extract(71, 64, flag))

known_char = z3.BitVecVal(string_to_xored[8], 8)
solver.add((z3.Extract(71, 64, flag) ^ known_char) == z3.Extract(79, 72, flag))

known_char = z3.BitVecVal(string_to_xored[9], 8)
solver.add((z3.Extract(79, 72, flag) ^ known_char) == z3.Extract(87, 80, flag))

known_char = z3.BitVecVal(string_to_xored[10], 8)
solver.add((z3.Extract(87, 80, flag) ^ known_char) == z3.Extract(95, 88, flag))"""

known_char = z3.BitVecVal(string_to_xored[0], 8)
solver.add(flag[0] == ord('&'))
solver.add((flag[0] ^ known_char) == flag[1])

known_char = z3.BitVecVal(string_to_xored[1], 8)
solver.add((flag[1] ^ known_char) == flag[2])

known_char = z3.BitVecVal(string_to_xored[2], 8)
solver.add((flag[2] ^ known_char) == flag[3])

known_char = z3.BitVecVal(string_to_xored[3], 8)
solver.add((flag[3] ^ known_char) == flag[4])

known_char = z3.BitVecVal(string_to_xored[4], 8)
solver.add((flag[4] ^ known_char) == flag[5])

known_char = z3.BitVecVal(string_to_xored[5], 8)
solver.add((flag[5] ^ known_char) == flag[6])

known_char = z3.BitVecVal(string_to_xored[6], 8)
solver.add((flag[6] ^ known_char) == flag[7])

known_char = z3.BitVecVal(string_to_xored[7], 8)
solver.add((flag[7] ^ known_char) == flag[8])

known_char = z3.BitVecVal(string_to_xored[8], 8)
solver.add((flag[8] ^ known_char) == flag[9])

known_char = z3.BitVecVal(string_to_xored[9], 8)
solver.add((flag[9] ^ known_char) == flag[10])

known_char = z3.BitVecVal(string_to_xored[10], 8)
solver.add((flag[10] ^ known_char) == flag[11])


#solver.add(FUN_08049546(flag, 0) == 1)

solver.check()

model = solver.model()

if model:
    print(model)
