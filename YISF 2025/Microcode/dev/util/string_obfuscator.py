from Crypto.Util.number import *
import random

def get_random():
    return random.randrange(0, 0xffffffffffffffff)

reg_arr = {"r" + str(v) : 0 for v in range(8, 15+1)}
string = b"}"
string = [string[i:i+8][::-1] for i in range(0, len(string), 8)]
string = [bytes_to_long(v.rjust(8, b"\x00")) for v in string]

LEN = 30

for _ in range(LEN):
    a, b = 0, 0
    while a == b:
        a, b = random.choice(list(reg_arr.keys())), random.choice(list(reg_arr.keys()))
    v1, v2 = get_random(), get_random()
    
    print(f"mov {a}, {hex(v1)}")
    print(f"mov {b}, {hex(v2)}")
    reg_arr[a] = v1
    reg_arr[b] = v2
    
    print(f"xor {a}, {b}")
    reg_arr[a] ^= reg_arr[b]

for v in string:
    a, b = 0, 0
    while a == b:
        a, b = random.choice(list(reg_arr.keys())), random.choice(list(reg_arr.keys()))

    key = reg_arr[a] ^ reg_arr[b] ^ v
    print(f"xor {a}, {b}")
    reg_arr[a] ^= reg_arr[b]
    
    print(f"xor {a}, {hex(key)}")
    reg_arr[a] ^= key