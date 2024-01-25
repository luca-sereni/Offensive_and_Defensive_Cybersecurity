import z3

def check_flag(buffer): #copied from ghidra and modified to work in Python
    int: correct 

    if (buffer[0xb] * -0x19 + buffer[8] * 0x31 + buffer[10] * 0xbb + -0x9c2a + buffer[1] * 0x39 + buffer[2] * 3 +
        buffer[0x16] * 0xd7 + buffer[9] * -0xbd + buffer[0xc] * -0x47 + buffer[0xd] * 0xb7 +
        buffer[0xf] * -0x9b + buffer[3] * 0x73 + buffer[0x13] * -0x95 + buffer[0xe] * 0xc6 +
        buffer[4] * 0x9a + buffer[0x11] * -0x66 + buffer[0x10] * 0x7c + buffer[0x12] * 0xb9 +
        buffer[6] * -0xaa + buffer[5] * -0x6a + buffer[0x15] * 0xe1 + buffer[0x14] * -0xa6 +
        buffer[7] * -0xb5 + buffer[0] * -0xb7) == 0: #done
        if (buffer[0x15] * -0x55 +
            buffer[0xe] * -0xe5 +
            buffer[8] * -0xae + buffer[6] * -0x58 + buffer[0x14] * 0x7d + buffer[1] * -0x3c +
            buffer[0xf] * 0xe0 + buffer[10] * 0xfc + buffer[2] * -0x5e + buffer[0x12] * -0xe0 +
            buffer[5] * 0xee + buffer[0x10] * 0xe7 + buffer[7] * -0x61 + buffer[0xb] * -0x89 +
            buffer[4] * -0x80 + buffer[0] * -0xfd + buffer[0xc] * -0x9e + 0x9a2e +
            buffer[0x16] * 2 + buffer[0x16] * -0x10 + buffer[0x13] * -0x11 + buffer[0x11] * 0x30 +
            buffer[0xd] * 0x83 + buffer[9] * -0xde + buffer[3] * 0xe2) == 0: #done
            if (buffer[0x10] * -0x39 +
                buffer[0x16] * 0xc6 +
                buffer[0x15] * -0x6c + buffer[9] * 0xd4 + buffer[0xf] * -0xe2 + buffer[0xd] * 0xc5 +
                buffer[0x14] * 0x91 + buffer[2] * 0x84 + buffer[1] * 0x32 + buffer[0xe] * 0x86 + -0x3124d
                + buffer[5] * 0xd2 + buffer[0x11] * 0xea + buffer[0xb] * 0x1b + buffer[0x12] * 0x97 +
                buffer[3] * 0xf0 + buffer[4] * -0x8a + buffer[0xc] * 0x95 + buffer[0x13] * 0x9f +
                buffer[7] * -0x29 + buffer[8] * 0xb3 + buffer[0] * -0x31 + buffer[10] * 0xd1 +
                buffer[6] * 0x32) == 0: #done
                if (buffer[7] * 0x5f +
                    buffer[10] * 0x60 +
                    buffer[0x14] * 0x8d + buffer[0xc] * 0xab + buffer[6] * -0x1a + buffer[0xe] * 0xcb +
                    buffer[2] * 0x57 + buffer[0x13] * -0x8d + buffer[0x16] * -0xba + buffer[0xf] * 0xa9 +
                    buffer[0x10] * -0x14 + buffer[5] * 0x52 + buffer[0x11] * -0x23 + buffer[1] * -0x68 +
                    buffer[0x15] * 199 + buffer[0x12] * 0x57 + buffer[0xd] * 0xeb + buffer[8] * -0xa8 +
                    buffer[9] * 0x85 + buffer[0] * -0x62 + -0x20c1e + buffer[4] * 0xaf + buffer[3] * -0x26 +
                    buffer[0xb] * 0xfb) == 0: #done
                    if (buffer[0xb] * 0x23 +
                        buffer[3] * -0x80 + buffer[0x12] * 0xd0 + buffer[0xd] * 0x8a + -0x1b8ed +
                        buffer[0] * -0x51 + buffer[2] * 0x8c + buffer[1] * 4 + buffer[0x13] * 0x86 +
                        buffer[4] * 0xf0 + buffer[5] * -0xc4 + buffer[9] * -0x55 + buffer[0x14] * 0xd8 +
                        buffer[0x11] * -0xb5 + buffer[0xe] * -0x14 + buffer[7] * 0xea + buffer[10] * -0xc3 +
                        buffer[8] * 0xeb + buffer[0xf] * 0xba + buffer[0x10] * -0xf5 + buffer[0x15] * 0xe7 +
                        buffer[0xc] * 0x97 + buffer[0x16] * 0x97 + buffer[6] * -0x4e) == 0: #done
                        if (buffer[0xc] * 0xd6 +
                            buffer[0x11] * -0x80 +
                            buffer[3] * 0x21 + buffer[0xf] * -0xe8 + buffer[10] * 0xd + buffer[4] * -0x7b +
                            buffer[0x12] * 0x5a + buffer[0x13] * 0xda + buffer[6] * -0x66 + buffer[1] * -0x98 +
                            buffer[8] * 0x23 + buffer[0x14] * 0x16 + buffer[0x15] * -0x89 + buffer[9] * -0xba +
                            buffer[7] * 0x53 + buffer[0xb] * 0x6e + buffer[2] * 0x8e + buffer[5] * -0xe5 +
                            buffer[0xd] * 0xc5 + buffer[0x10] * -7 + buffer[0x16] * -0xee + buffer[0] * 0xed +
                            buffer[0xe] * 0xab + -0x3da5) == 0: #done
                            if (buffer[1] * 0xa8 +
                                buffer[7] * -0xa6 +
                                (buffer[6] * 0x7a + buffer[2] * -0x50 + buffer[0x12] * 0xdd + buffer[4] * -0xa7 +
                                buffer[5] * 0x8b + buffer[0xc] * -0x26 + buffer[8] * -0x8c +
                                buffer[0x10] * -0x9f + buffer[10] * -0xc6) - buffer[0x16] +
                                buffer[0xe] * -0x35 + buffer[9] * 0xe + buffer[0x14] * -0x6f + buffer[0xb] * 0x91
                                + 0xb2a6 + buffer[0x11] * -0x8d + buffer[0xd] * -0xd + buffer[3] * 0x39 +
                                buffer[0] * -0xcc + buffer[0xf] * -0x45 + buffer[0x13] * 0xe9 + buffer[0x15] * -0x6a) == 0: #done
                                if (buffer[0xe] * 0xe +
                                    buffer[0x15] * 0xeb +
                                    buffer[10] * 0x12 + buffer[0x13] * 0xa3 + buffer[3] * 0xa5 + buffer[4] * 0xb3 +
                                    buffer[0xf] * -0x10 + buffer[0xc] * -0x4d + buffer[2] * -0x65 +
                                    buffer[0x10] * 0xc1 + buffer[0x16] * 0x43 + -0x20fdc + buffer[0x11] * 0xeb +
                                    buffer[0x14] * 0xb4 + buffer[5] * 0x33 + buffer[0xd] * -0xe7 + buffer[9] * 0x7a
                                    + buffer[0] * -0x42 + buffer[1] * 0xca + buffer[7] * 0xca + buffer[8] * 0x35 +
                                    buffer[0xb] * 0x4e + buffer[0x12] * 0x4d + buffer[6] * -0xbe) == 0: #done
                                    if (buffer[0x11] * -199 +
                                        buffer[10] * -0x4e +
                                        buffer[5] * -0xd8 + buffer[0xd] * -0x17 + buffer[7] * 0xc5 +
                                        buffer[0xe] * 0x43 + buffer[0x10] * 0xc4 + buffer[0xf] * 0xaa + 0x4867 +
                                        buffer[1] * -0xf5 + buffer[3] * -0xa1 + buffer[9] * 0x55 + buffer[0x15] * 0x67
                                        + buffer[0xc] * -0x4e + buffer[0x13] * 8 + buffer[0] * -0xd3 +
                                        buffer[0x16] * -0xb2 + buffer[8] * 0x2d + buffer[0xb] * -0xf +
                                        buffer[4] * 0xd1 + buffer[6] * 0xf2 + buffer[2] * 0xf0 + buffer[0x14] * -0x5b
                                        + buffer[0x12] * 0x47) == 0: #done
                                        if (buffer[0x15] * 0xed +
                                            buffer[0xe] * 0x5b +
                                            buffer[4] * -0xf + buffer[9] * -0xfd + buffer[6] * 99 + buffer[2] * -0xd1 +
                                            buffer[0] * 0xf7 + buffer[0x13] * 0xc3 + buffer[0xf] * -0x6f +
                                            buffer[8] * 0xca + buffer[0x10] * 0x4a + buffer[0x14] * 0xf9 +
                                            buffer[3] * 0xd3 + -0x130f0 + buffer[0x11] * -0xfc + buffer[0x16] * -0xda +
                                            buffer[5] * 0x56 + buffer[10] * 0x3b + buffer[0xb] * 0x87 +
                                            buffer[0xd] * -0x3a + buffer[0xc] * -0xa9 + buffer[0x12] * 0xbb +
                                            buffer[1] * 0xb4 + buffer[7] * 0x8f) == 0: #done
                                            if (buffer[0xf] * -0x20 +
                                                buffer[0x16] * -0x22 +
                                                buffer[0x15] * -0x7b + buffer[0xb] * -99 + buffer[0x13] * 0x86 +
                                                buffer[0xe] * 0x9c + buffer[5] * 0x89 + buffer[0xd] * 0xe3 +
                                                buffer[0x10] * -0x7c + buffer[3] * -0x9c + 0x8354 + buffer[0] * -0x45 +
                                                buffer[1] * -0x51 + buffer[0x11] * -0x7d + buffer[7] * -0xa7 +
                                                buffer[6] * 0xaf + buffer[8] * -0xcf + buffer[0x12] * -0xbf +
                                                buffer[0x14] * 0x22 + buffer[4] * -0x3a + buffer[10] * -0x47 +
                                                buffer[0xc] * -0x5d + buffer[2] * 0xfe + buffer[9] * 0xc9) == 0: #done
                                                if (buffer[10] * 0xcc +
                                                    buffer[0x13] * 0x33 +
                                                    buffer[2] * -0x69 + buffer[3] * -0xa3 + buffer[0x10] * 0x60 +
                                                    buffer[5] * 0xea + buffer[0xb] * -0xb5 + buffer[0xc] * 0x2a +
                                                    buffer[0x14] * 0xf1 + buffer[6] * 0xb1 + buffer[0xe] * -0x14 +
                                                    buffer[9] * 0x86 + buffer[0x12] * -0x65 + -0x53c7 + buffer[1] * -0x48 +
                                                    buffer[4] * -0x30 + buffer[0xf] * -0xde + buffer[0x15] * -0x3e +
                                                    buffer[0] * 0x57 + buffer[8] * -0x37 + buffer[0xd] * 0x5a +
                                                    buffer[0x16] * 0x6c + buffer[0x11] * 0xd6 + buffer[7] * -0xe2) == 0: #done
                                                    if (buffer[4] * 0x39 +
                                                        buffer[8] * 0x23 +
                                                        buffer[3] * -0x4e + buffer[0xb] * -0x99 + buffer[0xe] * 0x47 +
                                                        buffer[6] * -0xa7 + buffer[9] * 0x74 + buffer[0x14] * 2 + 0x2d4f +
                                                        buffer[0x12] * -0x50 + buffer[0xd] * -0xb8 + buffer[0x16] * -0x4f +
                                                        buffer[0x10] * -0x31 + buffer[0xf] * 0xf2 + buffer[0] * -7 +
                                                        buffer[0xc] * -0xa4 + buffer[0x11] * 0xc4 + buffer[7] * -0x28 +
                                                        buffer[0x13] * -0xb8 + buffer[5] * 0xf0 + buffer[1] * 0x1a +
                                                        buffer[2] * -0x84 + buffer[10] * 0x8d + buffer[0x15] * -2) == 0: #done
                                                        if (buffer[4] * 0xa8 +
                                                            buffer[7] * 0xe1 +
                                                            buffer[0x12] * -0x1a + buffer[2] * -0x3d + buffer[0xf] * -0xc9 +
                                                            buffer[0x16] * -0x7f + buffer[0] * 0x2c + 0xeb6 + buffer[0xb] * 0x71 +
                                                            buffer[0x13] * -0x8f + buffer[0x10] * -0xdd + buffer[10] * -0xe1 +
                                                            buffer[6] * -0xbb + buffer[0x14] * 0x48 + buffer[0xe] * -0xb6 +
                                                            buffer[0xd] * 0xdc + buffer[3] * 0xf2 + buffer[0x15] * -0x88 +
                                                            buffer[0xc] * -0x2e + buffer[0x11] * 3 + buffer[5] * 0xb8 +
                                                            buffer[9] * 0x8c + buffer[8] * -0x77 +
                                                            buffer[1] + buffer[1] * -8) == 0: #done
                                                            if (buffer[3] * 0xad +
                                                                buffer[2] * 0x82 + buffer[0xf] * 0xa7 + buffer[7] * 0xd0 +
                                                                buffer[0x14] * -0x4f + buffer[0xc] * -0x91 + buffer[0x11] * -0x5a
                                                                + buffer[0x13] * -0x100 + buffer[0x10] * 0x27 + buffer[8] * 0xec +
                                                                buffer[0xb] * 0x3c + buffer[6] * -0x4a + buffer[5] * -0x1b +
                                                                buffer[4] * -0x47 + buffer[9] * 0x8c + buffer[0] * -0x8e +
                                                                buffer[0x16] * 0x65 + buffer[10] * -0xb9 + buffer[0x15] * 0x74 +
                                                                buffer[0xd] * -0x86 + buffer[0xe] * 0x9e + buffer[1] * 0xbb +
                                                                buffer[0x12] * -0x48) == 0x6469: #done
                                                                if (buffer[0x12] * -0xc0 +
                                                                    buffer[4] * 0xe7 +
                                                                    buffer[5] * 9 + buffer[8] * 0xa4 + buffer[0x15] * 0xf6 +
                                                                    buffer[2] * 0xd9 + buffer[0x11] * 0x57 + buffer[0xc] * -0x88 +
                                                                    buffer[3] * 0xdd + buffer[0x10] * -0x8a + buffer[6] * -0x97 +
                                                                    buffer[1] * 0x57 + buffer[0x13] * 0xe2 + buffer[7] * 0x61 +
                                                                    buffer[0x16] * 0x6c + buffer[0x14] * -0xd0 + -0x1e27d +
                                                                    buffer[0xf] * 0x46 + buffer[9] * 0xf0 + buffer[0] * 0x5a +
                                                                    buffer[0xd] * -0x52 + buffer[10] * 0xb9 + buffer[0xb] * 0xb4 +
                                                                    buffer[0xe] * -0xf8) == 0: #done
                                                                    if (buffer[3] * 0xc +
                                                                        buffer[0xe] * 0x85 +
                                                                        buffer[6] * -0xa9 + buffer[0xb] * -0x36 + buffer[0x13] * -0x93
                                                                        + buffer[8] * -0x17 + buffer[5] * 6 + buffer[0x14] * 0x99 +
                                                                        buffer[0x10] * 0xd4 + buffer[0xf] * 0xf2 + buffer[0xc] * 0xb5
                                                                        + buffer[10] * -0xb8 + buffer[2] * -0x35 + buffer[9] * -0x98 +
                                                                        buffer[0xd] * -0xe5 + -0x65d + buffer[4] * 0x3f +
                                                                        buffer[0] * 0x9d + buffer[1] * 0xe + buffer[0x11] * 0xe +
                                                                        buffer[0x16] * -0xdb + buffer[0x12] * 0x61 + buffer[7] * 0x1b
                                                                        + buffer[0x15] * -0x97) == 0: #done
                                                                        if (buffer[9] * 0xf6 +
                                                                            buffer[4] * -0x28 + 0x11400 + buffer[0xc] * -0xb2 +
                                                                            buffer[10] * -0xe2 + buffer[0xd] * -0x90 +
                                                                            buffer[0x16] * 0x62 + buffer[6] * 0xd3 +
                                                                            buffer[0x11] * -0x7a + buffer[0xb] * -0xad +
                                                                            buffer[8] * 0x1d + buffer[0x14] * 0x48 + buffer[2] * -0x17 +
                                                                            buffer[7] * -0x34 + buffer[3] * 0x9b + buffer[0x13] * -0x12
                                                                            + buffer[0xf] * 0x7a + buffer[0x15] * -0x83 +
                                                                            buffer[0x10] * 0xac + buffer[5] * -0xe3 +
                                                                            buffer[0xe] * -0xb5 + buffer[0x12] * -0x8f + buffer[0] * 0xfc) == 0: #done
                                                                            if (buffer[0x12] * -0x32 +
                                                                                buffer[0x13] * 0x50 +
                                                                                buffer[4] * -0x4f + buffer[0xb] * 0x4f + buffer[0] * 0x33 +
                                                                                buffer[3] * -0xab + buffer[8] * -0x98 +
                                                                                buffer[0x15] * -0xcb + buffer[0x16] * 0x6a +
                                                                                buffer[9] * 0x95 + 0xfde0 + buffer[2] * -0xc1 +
                                                                                buffer[6] * -0x99 + buffer[5] * -0x40 +
                                                                                buffer[0x14] * -0x72 + buffer[0xf] * -0xf9 +
                                                                                buffer[0xc] * -0xfb + buffer[1] * 0xdc +
                                                                                buffer[0xe] * -0xf9 + buffer[0x11] * 0x17 +
                                                                                buffer[0x10] * -0x14 + buffer[7] * 0x7a +
                                                                                buffer[0xd] * 0x3d + buffer[10] * 0xdd) == 0: #done
                                                                                if (buffer[0x16] * -0xfd +
                                                                                    buffer[4] * 0x85 +
                                                                                    buffer[0xb] * -0x29 + buffer[0x11] * 0x2a +
                                                                                    buffer[0] * 0xe3 + buffer[1] * -0x84 + buffer[9] * 0xad +
                                                                                    buffer[6] * 0x4c + buffer[0x14] * 0xf4 +
                                                                                    buffer[5] * -0x2d + -0x21cf + buffer[7] * -0xc6 +
                                                                                    buffer[0xe] * 0x4c + buffer[0x15] * -0x5a +
                                                                                    buffer[3] * 0x65 + buffer[0xf] * -0xfe +
                                                                                    buffer[8] * -0x29 + buffer[2] * -0x17 +
                                                                                    buffer[0x13] * 0x8a + buffer[0xd] * -0x78 +
                                                                                    buffer[0x10] * 0x6d + buffer[0x12] * -0x30 +
                                                                                    buffer[10] * 0xa1 + buffer[0xc] * 0x8a) == 0: #done
                                                                                    if (buffer[10] * -0xb +
                                                                                        buffer[0xe] * 0x54 +
                                                                                        buffer[0x14] * 0x5b + buffer[2] * 0xda +
                                                                                        buffer[3] * -0x8e + buffer[0x13] * 0x4c +
                                                                                        buffer[0x15] * -0xec + buffer[0x10] * -0x81 +
                                                                                        buffer[9] * -0x5c + buffer[0x16] * -0xdd +
                                                                                        buffer[4] * 0xac + buffer[0xf] * 0xe5 +
                                                                                        buffer[7] * -0xf9 + buffer[8] * -0x32 +
                                                                                        buffer[5] * 0xbd + buffer[0x12] * -0xbd +
                                                                                        buffer[0xd] * -100 + buffer[0xb] * 0x5d +
                                                                                        buffer[1] * 0x8b + buffer[0xc] * 0x89 +
                                                                                        buffer[0] * -0x1e + buffer[0x11] * -0x7c + -0x9bf +
                                                                                        buffer[6] * -0x1e) == 0: #done
                                                                                        if (buffer[0xb] * -0xe2 +
                                                                                            buffer[6] * -0x4b +
                                                                                            buffer[0x15] * -10 + buffer[8] * 0x33 +
                                                                                            buffer[0x16] * 0x72 + buffer[0x14] * -0x80 +
                                                                                            buffer[5] * -0xdf + buffer[7] * 0xf9 +
                                                                                            buffer[4] * 0x11 + buffer[0x11] * -0xc1 +
                                                                                            buffer[0] * 0x74 + buffer[0x12] * 0xf6 +
                                                                                            buffer[0x10] * 0xdc + buffer[0xf] * 0x65 +
                                                                                            buffer[0xe] * 0xb2 + buffer[0xc] * -0x42 +
                                                                                            buffer[10] * -0x42 + buffer[2] * 0x24 +
                                                                                            buffer[9] * -0xd4 + buffer[0x13] * 0x73 +
                                                                                            buffer[0xd] * -0x86 + buffer[3] * 0xd7 + -0xe3f6 +
                                                                                            buffer[1] * 0x76) == 0: #done
                                                                                            if (buffer[0x10] * -0x9c +
                                                                                                buffer[2] * 0x67 +
                                                                                                buffer[0xc] * -0x23 + buffer[8] * -0x48 +
                                                                                                buffer[6] * -0xd7 + buffer[7] * -0x84 +
                                                                                                buffer[1] * 10 + buffer[0xe] * -0xd7 +
                                                                                                buffer[0xb] * 0x62 + buffer[0xf] * -0x51 +
                                                                                                buffer[0] * 0xbc + buffer[0x16] * -0x4c + 0xd3bb +
                                                                                                buffer[0x13] * -0x98 + buffer[0xd] * -0x53 +
                                                                                                buffer[0x11] * -0x77 + buffer[0x15] * -0x6c +
                                                                                                buffer[3] * 0x74 + buffer[0x14] * 0x38 +
                                                                                                buffer[5] * 0x46 + buffer[9] * -0x9c +
                                                                                                buffer[4] * 0xdb + buffer[10] * -0x76 +
                                                                                                buffer[0x12] * 0x2e) == 0: #done
                                                                                                    correct = 0
                                                                                            else:
                                                                                                correct = 0x17
                                                                                        else:
                                                                                            correct = 0x16
                                                                                    else:
                                                                                        correct = 0x15
                                                                                else:
                                                                                    correct = 0x14    
                                                                            else:
                                                                                correct = 0x13
                                                                        else:
                                                                            correct = 0x12
                                                                    else:
                                                                        correct = 0x11
                                                                else:
                                                                    correct = 0x10
                                                            else:
                                                                correct = 0xf
                                                        else:
                                                            correct = 0xe
                                                    else:
                                                        correct = 0xd
                                                else:
                                                    correct = 0xc
                                            else:
                                                correct = 0xb
                                        else:
                                            correct = 10
                                    else:
                                        correct = 9
                                else:
                                    correct = 8
                            else:
                                correct = 7
                        else:
                            correct = 6
                    else:
                        correct = 5
                else:
                    correct = 4
            else:
                correct = 3
        else:
            correct = 2
    else:
        correct = 1
    
    return correct

buffer = [z3.BitVec(f'char_{i}', 8) for i in range(23)]

solver = z3.Solver()

solver.add(buffer[0] == ord('f'))
solver.add(buffer[1] == ord('l'))
solver.add(buffer[2] == ord('a'))
solver.add(buffer[3] == ord('g'))
solver.add(buffer[4] == ord('{'))
solver.add(buffer[22] == ord('}'))
solver.add(buffer[0xb] * -0x19 + buffer[8] * 0x31 + buffer[10] * 0xbb + -0x9c2a + buffer[1] * 0x39 + buffer[2] * 3 +
        buffer[0x16] * 0xd7 + buffer[9] * -0xbd + buffer[0xc] * -0x47 + buffer[0xd] * 0xb7 +
        buffer[0xf] * -0x9b + buffer[3] * 0x73 + buffer[0x13] * -0x95 + buffer[0xe] * 0xc6 +
        buffer[4] * 0x9a + buffer[0x11] * -0x66 + buffer[0x10] * 0x7c + buffer[0x12] * 0xb9 +
        buffer[6] * -0xaa + buffer[5] * -0x6a + buffer[0x15] * 0xe1 + buffer[0x14] * -0xa6 +
        buffer[7] * -0xb5 + buffer[0] * -0xb7 == 0)
solver.add(buffer[0x15] * -0x55 +
            buffer[0xe] * -0xe5 +
            buffer[8] * -0xae + buffer[6] * -0x58 + buffer[0x14] * 0x7d + buffer[1] * -0x3c +
            buffer[0xf] * 0xe0 + buffer[10] * 0xfc + buffer[2] * -0x5e + buffer[0x12] * -0xe0 +
            buffer[5] * 0xee + buffer[0x10] * 0xe7 + buffer[7] * -0x61 + buffer[0xb] * -0x89 +
            buffer[4] * -0x80 + buffer[0] * -0xfd + buffer[0xc] * -0x9e + 0x9a2e +
            buffer[0x16] * 2 + buffer[0x16] * -0x10 + buffer[0x13] * -0x11 + buffer[0x11] * 0x30 +
            buffer[0xd] * 0x83 + buffer[9] * -0xde + buffer[3] * 0xe2 == 0)
solver.add(buffer[0x10] * -0x39 +
                buffer[0x16] * 0xc6 +
                buffer[0x15] * -0x6c + buffer[9] * 0xd4 + buffer[0xf] * -0xe2 + buffer[0xd] * 0xc5 +
                buffer[0x14] * 0x91 + buffer[2] * 0x84 + buffer[1] * 0x32 + buffer[0xe] * 0x86 + -0x3124d
                + buffer[5] * 0xd2 + buffer[0x11] * 0xea + buffer[0xb] * 0x1b + buffer[0x12] * 0x97 +
                buffer[3] * 0xf0 + buffer[4] * -0x8a + buffer[0xc] * 0x95 + buffer[0x13] * 0x9f +
                buffer[7] * -0x29 + buffer[8] * 0xb3 + buffer[0] * -0x31 + buffer[10] * 0xd1 +
                buffer[6] * 0x32 == 0)
solver.add(buffer[7] * 0x5f +
                    buffer[10] * 0x60 +
                    buffer[0x14] * 0x8d + buffer[0xc] * 0xab + buffer[6] * -0x1a + buffer[0xe] * 0xcb +
                    buffer[2] * 0x57 + buffer[0x13] * -0x8d + buffer[0x16] * -0xba + buffer[0xf] * 0xa9 +
                    buffer[0x10] * -0x14 + buffer[5] * 0x52 + buffer[0x11] * -0x23 + buffer[1] * -0x68 +
                    buffer[0x15] * 199 + buffer[0x12] * 0x57 + buffer[0xd] * 0xeb + buffer[8] * -0xa8 +
                    buffer[9] * 0x85 + buffer[0] * -0x62 + -0x20c1e + buffer[4] * 0xaf + buffer[3] * -0x26 +
                    buffer[0xb] * 0xfb == 0)
solver.add(buffer[0xb] * 0x23 +
                        buffer[3] * -0x80 + buffer[0x12] * 0xd0 + buffer[0xd] * 0x8a + -0x1b8ed +
                        buffer[0] * -0x51 + buffer[2] * 0x8c + buffer[1] * 4 + buffer[0x13] * 0x86 +
                        buffer[4] * 0xf0 + buffer[5] * -0xc4 + buffer[9] * -0x55 + buffer[0x14] * 0xd8 +
                        buffer[0x11] * -0xb5 + buffer[0xe] * -0x14 + buffer[7] * 0xea + buffer[10] * -0xc3 +
                        buffer[8] * 0xeb + buffer[0xf] * 0xba + buffer[0x10] * -0xf5 + buffer[0x15] * 0xe7 +
                        buffer[0xc] * 0x97 + buffer[0x16] * 0x97 + buffer[6] * -0x4e == 0)
solver.add(buffer[0xc] * 0xd6 +
                            buffer[0x11] * -0x80 +
                            buffer[3] * 0x21 + buffer[0xf] * -0xe8 + buffer[10] * 0xd + buffer[4] * -0x7b +
                            buffer[0x12] * 0x5a + buffer[0x13] * 0xda + buffer[6] * -0x66 + buffer[1] * -0x98 +
                            buffer[8] * 0x23 + buffer[0x14] * 0x16 + buffer[0x15] * -0x89 + buffer[9] * -0xba +
                            buffer[7] * 0x53 + buffer[0xb] * 0x6e + buffer[2] * 0x8e + buffer[5] * -0xe5 +
                            buffer[0xd] * 0xc5 + buffer[0x10] * -7 + buffer[0x16] * -0xee + buffer[0] * 0xed +
                            buffer[0xe] * 0xab + -0x3da5 == 0)
solver.add(buffer[1] * 0xa8 +
                                buffer[7] * -0xa6 +
                                (buffer[6] * 0x7a + buffer[2] * -0x50 + buffer[0x12] * 0xdd + buffer[4] * -0xa7 +
                                buffer[5] * 0x8b + buffer[0xc] * -0x26 + buffer[8] * -0x8c +
                                buffer[0x10] * -0x9f + buffer[10] * -0xc6) - buffer[0x16] +
                                buffer[0xe] * -0x35 + buffer[9] * 0xe + buffer[0x14] * -0x6f + buffer[0xb] * 0x91
                                + 0xb2a6 + buffer[0x11] * -0x8d + buffer[0xd] * -0xd + buffer[3] * 0x39 +
                                buffer[0] * -0xcc + buffer[0xf] * -0x45 + buffer[0x13] * 0xe9 + buffer[0x15] * -0x6a == 0)
solver.add(buffer[0xe] * 0xe +
                                    buffer[0x15] * 0xeb +
                                    buffer[10] * 0x12 + buffer[0x13] * 0xa3 + buffer[3] * 0xa5 + buffer[4] * 0xb3 +
                                    buffer[0xf] * -0x10 + buffer[0xc] * -0x4d + buffer[2] * -0x65 +
                                    buffer[0x10] * 0xc1 + buffer[0x16] * 0x43 + -0x20fdc + buffer[0x11] * 0xeb +
                                    buffer[0x14] * 0xb4 + buffer[5] * 0x33 + buffer[0xd] * -0xe7 + buffer[9] * 0x7a
                                    + buffer[0] * -0x42 + buffer[1] * 0xca + buffer[7] * 0xca + buffer[8] * 0x35 +
                                    buffer[0xb] * 0x4e + buffer[0x12] * 0x4d + buffer[6] * -0xbe == 0)
solver.add(buffer[0x11] * -199 +
                                        buffer[10] * -0x4e +
                                        buffer[5] * -0xd8 + buffer[0xd] * -0x17 + buffer[7] * 0xc5 +
                                        buffer[0xe] * 0x43 + buffer[0x10] * 0xc4 + buffer[0xf] * 0xaa + 0x4867 +
                                        buffer[1] * -0xf5 + buffer[3] * -0xa1 + buffer[9] * 0x55 + buffer[0x15] * 0x67
                                        + buffer[0xc] * -0x4e + buffer[0x13] * 8 + buffer[0] * -0xd3 +
                                        buffer[0x16] * -0xb2 + buffer[8] * 0x2d + buffer[0xb] * -0xf +
                                        buffer[4] * 0xd1 + buffer[6] * 0xf2 + buffer[2] * 0xf0 + buffer[0x14] * -0x5b
                                        + buffer[0x12] * 0x47 == 0)
solver.add(buffer[0x15] * 0xed +
                                            buffer[0xe] * 0x5b +
                                            buffer[4] * -0xf + buffer[9] * -0xfd + buffer[6] * 99 + buffer[2] * -0xd1 +
                                            buffer[0] * 0xf7 + buffer[0x13] * 0xc3 + buffer[0xf] * -0x6f +
                                            buffer[8] * 0xca + buffer[0x10] * 0x4a + buffer[0x14] * 0xf9 +
                                            buffer[3] * 0xd3 + -0x130f0 + buffer[0x11] * -0xfc + buffer[0x16] * -0xda +
                                            buffer[5] * 0x56 + buffer[10] * 0x3b + buffer[0xb] * 0x87 +
                                            buffer[0xd] * -0x3a + buffer[0xc] * -0xa9 + buffer[0x12] * 0xbb +
                                            buffer[1] * 0xb4 + buffer[7] * 0x8f == 0)
solver.add(buffer[0xf] * -0x20 +
                                                buffer[0x16] * -0x22 +
                                                buffer[0x15] * -0x7b + buffer[0xb] * -99 + buffer[0x13] * 0x86 +
                                                buffer[0xe] * 0x9c + buffer[5] * 0x89 + buffer[0xd] * 0xe3 +
                                                buffer[0x10] * -0x7c + buffer[3] * -0x9c + 0x8354 + buffer[0] * -0x45 +
                                                buffer[1] * -0x51 + buffer[0x11] * -0x7d + buffer[7] * -0xa7 +
                                                buffer[6] * 0xaf + buffer[8] * -0xcf + buffer[0x12] * -0xbf +
                                                buffer[0x14] * 0x22 + buffer[4] * -0x3a + buffer[10] * -0x47 +
                                                buffer[0xc] * -0x5d + buffer[2] * 0xfe + buffer[9] * 0xc9 == 0)
solver.add(buffer[10] * 0xcc +
                                                    buffer[0x13] * 0x33 +
                                                    buffer[2] * -0x69 + buffer[3] * -0xa3 + buffer[0x10] * 0x60 +
                                                    buffer[5] * 0xea + buffer[0xb] * -0xb5 + buffer[0xc] * 0x2a +
                                                    buffer[0x14] * 0xf1 + buffer[6] * 0xb1 + buffer[0xe] * -0x14 +
                                                    buffer[9] * 0x86 + buffer[0x12] * -0x65 + -0x53c7 + buffer[1] * -0x48 +
                                                    buffer[4] * -0x30 + buffer[0xf] * -0xde + buffer[0x15] * -0x3e +
                                                    buffer[0] * 0x57 + buffer[8] * -0x37 + buffer[0xd] * 0x5a +
                                                    buffer[0x16] * 0x6c + buffer[0x11] * 0xd6 + buffer[7] * -0xe2 == 0)
solver.add(buffer[4] * 0x39 +
                                                        buffer[8] * 0x23 +
                                                        buffer[3] * -0x4e + buffer[0xb] * -0x99 + buffer[0xe] * 0x47 +
                                                        buffer[6] * -0xa7 + buffer[9] * 0x74 + buffer[0x14] * 2 + 0x2d4f +
                                                        buffer[0x12] * -0x50 + buffer[0xd] * -0xb8 + buffer[0x16] * -0x4f +
                                                        buffer[0x10] * -0x31 + buffer[0xf] * 0xf2 + buffer[0] * -7 +
                                                        buffer[0xc] * -0xa4 + buffer[0x11] * 0xc4 + buffer[7] * -0x28 +
                                                        buffer[0x13] * -0xb8 + buffer[5] * 0xf0 + buffer[1] * 0x1a +
                                                        buffer[2] * -0x84 + buffer[10] * 0x8d + buffer[0x15] * -2 == 0)
solver.add(buffer[4] * 0xa8 +
                                                            buffer[7] * 0xe1 +
                                                            buffer[0x12] * -0x1a + buffer[2] * -0x3d + buffer[0xf] * -0xc9 +
                                                            buffer[0x16] * -0x7f + buffer[0] * 0x2c + 0xeb6 + buffer[0xb] * 0x71 +
                                                            buffer[0x13] * -0x8f + buffer[0x10] * -0xdd + buffer[10] * -0xe1 +
                                                            buffer[6] * -0xbb + buffer[0x14] * 0x48 + buffer[0xe] * -0xb6 +
                                                            buffer[0xd] * 0xdc + buffer[3] * 0xf2 + buffer[0x15] * -0x88 +
                                                            buffer[0xc] * -0x2e + buffer[0x11] * 3 + buffer[5] * 0xb8 +
                                                            buffer[9] * 0x8c + buffer[8] * -0x77 +
                                                            buffer[1] + buffer[1] * -8 == 0)
solver.add(buffer[3] * 0xad +
                                                                buffer[2] * 0x82 + buffer[0xf] * 0xa7 + buffer[7] * 0xd0 +
                                                                buffer[0x14] * -0x4f + buffer[0xc] * -0x91 + buffer[0x11] * -0x5a
                                                                + buffer[0x13] * -0x100 + buffer[0x10] * 0x27 + buffer[8] * 0xec +
                                                                buffer[0xb] * 0x3c + buffer[6] * -0x4a + buffer[5] * -0x1b +
                                                                buffer[4] * -0x47 + buffer[9] * 0x8c + buffer[0] * -0x8e +
                                                                buffer[0x16] * 0x65 + buffer[10] * -0xb9 + buffer[0x15] * 0x74 +
                                                                buffer[0xd] * -0x86 + buffer[0xe] * 0x9e + buffer[1] * 0xbb +
                                                                buffer[0x12] * -0x48 == 0x6469)
solver.add(buffer[0x12] * -0xc0 +
                                                                    buffer[4] * 0xe7 +
                                                                    buffer[5] * 9 + buffer[8] * 0xa4 + buffer[0x15] * 0xf6 +
                                                                    buffer[2] * 0xd9 + buffer[0x11] * 0x57 + buffer[0xc] * -0x88 +
                                                                    buffer[3] * 0xdd + buffer[0x10] * -0x8a + buffer[6] * -0x97 +
                                                                    buffer[1] * 0x57 + buffer[0x13] * 0xe2 + buffer[7] * 0x61 +
                                                                    buffer[0x16] * 0x6c + buffer[0x14] * -0xd0 + -0x1e27d +
                                                                    buffer[0xf] * 0x46 + buffer[9] * 0xf0 + buffer[0] * 0x5a +
                                                                    buffer[0xd] * -0x52 + buffer[10] * 0xb9 + buffer[0xb] * 0xb4 +
                                                                    buffer[0xe] * -0xf8 == 0)
solver.add(buffer[3] * 0xc +
                                                                        buffer[0xe] * 0x85 +
                                                                        buffer[6] * -0xa9 + buffer[0xb] * -0x36 + buffer[0x13] * -0x93
                                                                        + buffer[8] * -0x17 + buffer[5] * 6 + buffer[0x14] * 0x99 +
                                                                        buffer[0x10] * 0xd4 + buffer[0xf] * 0xf2 + buffer[0xc] * 0xb5
                                                                        + buffer[10] * -0xb8 + buffer[2] * -0x35 + buffer[9] * -0x98 +
                                                                        buffer[0xd] * -0xe5 + -0x65d + buffer[4] * 0x3f +
                                                                        buffer[0] * 0x9d + buffer[1] * 0xe + buffer[0x11] * 0xe +
                                                                        buffer[0x16] * -0xdb + buffer[0x12] * 0x61 + buffer[7] * 0x1b
                                                                        + buffer[0x15] * -0x97 == 0)
solver.add(buffer[9] * 0xf6 +
                                                                            buffer[4] * -0x28 + 0x11400 + buffer[0xc] * -0xb2 +
                                                                            buffer[10] * -0xe2 + buffer[0xd] * -0x90 +
                                                                            buffer[0x16] * 0x62 + buffer[6] * 0xd3 +
                                                                            buffer[0x11] * -0x7a + buffer[0xb] * -0xad +
                                                                            buffer[8] * 0x1d + buffer[0x14] * 0x48 + buffer[2] * -0x17 +
                                                                            buffer[7] * -0x34 + buffer[3] * 0x9b + buffer[0x13] * -0x12
                                                                            + buffer[0xf] * 0x7a + buffer[0x15] * -0x83 +
                                                                            buffer[0x10] * 0xac + buffer[5] * -0xe3 +
                                                                            buffer[0xe] * -0xb5 + buffer[0x12] * -0x8f + buffer[0] * 0xfc == 0)
solver.add(buffer[9] * 0xf6 +
                                                                            buffer[4] * -0x28 + 0x11400 + buffer[0xc] * -0xb2 +
                                                                            buffer[10] * -0xe2 + buffer[0xd] * -0x90 +
                                                                            buffer[0x16] * 0x62 + buffer[6] * 0xd3 +
                                                                            buffer[0x11] * -0x7a + buffer[0xb] * -0xad +
                                                                            buffer[8] * 0x1d + buffer[0x14] * 0x48 + buffer[2] * -0x17 +
                                                                            buffer[7] * -0x34 + buffer[3] * 0x9b + buffer[0x13] * -0x12
                                                                            + buffer[0xf] * 0x7a + buffer[0x15] * -0x83 +
                                                                            buffer[0x10] * 0xac + buffer[5] * -0xe3 +
                                                                            buffer[0xe] * -0xb5 + buffer[0x12] * -0x8f + buffer[0] * 0xfc == 0)
solver.add(buffer[0x12] * -0x32 +
                                                                                buffer[0x13] * 0x50 +
                                                                                buffer[4] * -0x4f + buffer[0xb] * 0x4f + buffer[0] * 0x33 +
                                                                                buffer[3] * -0xab + buffer[8] * -0x98 +
                                                                                buffer[0x15] * -0xcb + buffer[0x16] * 0x6a +
                                                                                buffer[9] * 0x95 + 0xfde0 + buffer[2] * -0xc1 +
                                                                                buffer[6] * -0x99 + buffer[5] * -0x40 +
                                                                                buffer[0x14] * -0x72 + buffer[0xf] * -0xf9 +
                                                                                buffer[0xc] * -0xfb + buffer[1] * 0xdc +
                                                                                buffer[0xe] * -0xf9 + buffer[0x11] * 0x17 +
                                                                                buffer[0x10] * -0x14 + buffer[7] * 0x7a +
                                                                                buffer[0xd] * 0x3d + buffer[10] * 0xdd == 0)
solver.add(buffer[0x16] * -0xfd +
                                                                                    buffer[4] * 0x85 +
                                                                                    buffer[0xb] * -0x29 + buffer[0x11] * 0x2a +
                                                                                    buffer[0] * 0xe3 + buffer[1] * -0x84 + buffer[9] * 0xad +
                                                                                    buffer[6] * 0x4c + buffer[0x14] * 0xf4 +
                                                                                    buffer[5] * -0x2d + -0x21cf + buffer[7] * -0xc6 +
                                                                                    buffer[0xe] * 0x4c + buffer[0x15] * -0x5a +
                                                                                    buffer[3] * 0x65 + buffer[0xf] * -0xfe +
                                                                                    buffer[8] * -0x29 + buffer[2] * -0x17 +
                                                                                    buffer[0x13] * 0x8a + buffer[0xd] * -0x78 +
                                                                                    buffer[0x10] * 0x6d + buffer[0x12] * -0x30 +
                                                                                    buffer[10] * 0xa1 + buffer[0xc] * 0x8a == 0)
solver.add(buffer[10] * -0xb +
                                                                                        buffer[0xe] * 0x54 +
                                                                                        buffer[0x14] * 0x5b + buffer[2] * 0xda +
                                                                                        buffer[3] * -0x8e + buffer[0x13] * 0x4c +
                                                                                        buffer[0x15] * -0xec + buffer[0x10] * -0x81 +
                                                                                        buffer[9] * -0x5c + buffer[0x16] * -0xdd +
                                                                                        buffer[4] * 0xac + buffer[0xf] * 0xe5 +
                                                                                        buffer[7] * -0xf9 + buffer[8] * -0x32 +
                                                                                        buffer[5] * 0xbd + buffer[0x12] * -0xbd +
                                                                                        buffer[0xd] * -100 + buffer[0xb] * 0x5d +
                                                                                        buffer[1] * 0x8b + buffer[0xc] * 0x89 +
                                                                                        buffer[0] * -0x1e + buffer[0x11] * -0x7c + -0x9bf +
                                                                                        buffer[6] * -0x1e == 0)
solver.add(buffer[0xb] * -0xe2 +
                                                                                            buffer[6] * -0x4b +
                                                                                            buffer[0x15] * -10 + buffer[8] * 0x33 +
                                                                                            buffer[0x16] * 0x72 + buffer[0x14] * -0x80 +
                                                                                            buffer[5] * -0xdf + buffer[7] * 0xf9 +
                                                                                            buffer[4] * 0x11 + buffer[0x11] * -0xc1 +
                                                                                            buffer[0] * 0x74 + buffer[0x12] * 0xf6 +
                                                                                            buffer[0x10] * 0xdc + buffer[0xf] * 0x65 +
                                                                                            buffer[0xe] * 0xb2 + buffer[0xc] * -0x42 +
                                                                                            buffer[10] * -0x42 + buffer[2] * 0x24 +
                                                                                            buffer[9] * -0xd4 + buffer[0x13] * 0x73 +
                                                                                            buffer[0xd] * -0x86 + buffer[3] * 0xd7 + -0xe3f6 +
                                                                                            buffer[1] * 0x76 == 0)
solver.add(buffer[0x10] * -0x9c +
                                                                                                buffer[2] * 0x67 +
                                                                                                buffer[0xc] * -0x23 + buffer[8] * -0x48 +
                                                                                                buffer[6] * -0xd7 + buffer[7] * -0x84 +
                                                                                                buffer[1] * 10 + buffer[0xe] * -0xd7 +
                                                                                                buffer[0xb] * 0x62 + buffer[0xf] * -0x51 +
                                                                                                buffer[0] * 0xbc + buffer[0x16] * -0x4c + 0xd3bb +
                                                                                                buffer[0x13] * -0x98 + buffer[0xd] * -0x53 +
                                                                                                buffer[0x11] * -0x77 + buffer[0x15] * -0x6c +
                                                                                                buffer[3] * 0x74 + buffer[0x14] * 0x38 +
                                                                                                buffer[5] * 0x46 + buffer[9] * -0x9c +
                                                                                                buffer[4] * 0xdb + buffer[10] * -0x76 +
                                                                                                buffer[0x12] * 0x2e == 0)
solver.check()
print(solver.model())