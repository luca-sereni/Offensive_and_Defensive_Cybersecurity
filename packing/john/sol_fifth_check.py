from math import *

buffer = [0x0000001ca66fe7dd, 0x00000227357afcf8, 0x0000000000000015, 0x0000016c5c156c54, 0x0000001ca66fe7dd, 0x0000009de93ece66, 0x0000016c5c156c54, 0x0000016c5c156c54, 0x00000756f3444241,0x000000014660a4c5, 0x0000001ca66fe7dd]

def fifth_check(char_flag, buffer_word):
    sqrt_char = sqrt(char_flag)
    powl_char_flag = pow(char_flag, sqrt_char)

    if(powl_char_flag >= 0x8000000000000000):
        powl_char_flag = powl_char_flag - 0x8000000000000000
        powl_char_flag = round(powl_char_flag)
        uvar1 = powl_char_flag ^ 0x8000000000000000
    else:
        uvar1 = round(powl_char_flag)
    return (uvar1 + 0x15) == buffer_word

for i in range(0, 10):
    if i == 2:
        continue
    c = 33
    while not(fifth_check(c, buffer[i])):
        c = c + 1
    print(chr(c))