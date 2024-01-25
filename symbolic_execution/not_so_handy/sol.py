import z3

res = [0x16DBE60C, 0x487898C1, 0xEE2D55D3, 0x18D84754, 0x55C9E082, 0x47751ABE, 0x60A552E8, 0x1AE17C4D, 0xD306E0AF, 0x7C751B71, 0xE0A5C8A1, 0x1B5C0836, 0xC883DB29, 0x6980DC, 0xD30469C7, 0xFA5342, 0xE1E1B6B8, 0xD33F114F, 0xB69ADAF3, 0x11697366, 0xD2F2CEC7, 0x7341534D, 0x46E1A49F, 0x5337E65F, 0xA478DEA1, 0xEE6E084F, 0x5E83DAC7, 0x806952F3, 0xD2E17327, 0x52F293B8, 0xF32A114F, 0x1B9ADB94, 0x916E2954, 0xD3BBA55B, 0x2938CEBE, 0x25415379, 0xC6E60D54, 0xD397A4DC, 0xD386882, 0xA4FD1B71, 0xE0A5C8A1, 0x1B5C0836, 0x4883DBD3, 0x6E4754, 0xD3C9E0AF]

def compute_value(arg):
    var = z3.BitVecVal(0x7ffffff7, 64)
    arg_1 = z3.ZeroExt(56, arg)
    result = (arg_1 * var) ^ (z3.LShR(arg_1, 4))
    return result

def xhashe_slow(flag, n, start_portion):
    i = 0
    local_24 = n
    local_10 = z3.BitVecVal(0x0, 32)
    while local_24 != 0:
        arg_compute_value = ((z3.Extract(8*start_portion + (i*8)+7, 8*start_portion+(i*8), flag))) ^ (z3.Extract(7,0,z3.LShR(local_10, 0x18)))
        uvar1 = compute_value(arg_compute_value)
        local_10 = (local_10 << 8) ^ z3.Extract(31,0,uvar1)
        i += 1
        local_24 -= 1
    return local_10

def check(flag):
    i = 0
    while True:
        if(49 - 4 < i):
            if(i == 0x2d):
                return 1
            return 0
        svar2 = 49 - i
        if(svar2 < 5):
            uvar3 = svar2
        else:
            uvar3 = 4
        dvar1 = xhashe_slow(flag, uvar3, i)
        res_bv = z3.BitVecVal(res[i], 32)
        if not(dvar1 == res_bv):
            return 0
        i += 1


flag = z3.BitVec('flag', 8*49)
solver = z3.Solver()

for i in range(49):
    solver.add(z3.Extract((8*i)+7,i*8,flag) != 0x7f)
    solver.add(z3.Extract((8*i)+7,i*8,flag) >= 0x41)

for i in range(0,49):
    if(49 - i < 5):
        uvar3 = 49 - i
    else:
        uvar3 = 4
    if(i < 0x2d):
        solver.add(xhashe_slow(flag, uvar3, i) == res[i])


if solver.check() == z3.sat:
    m = solver.model()
    for i in range(48):
        print(chr(m.eval(z3.Extract((8*i)+7,i*8,flag)).as_long()), end="")

