def fnv1a_hash64(key: int) -> int:
    FNV_OFFSET_BASIS = 0xcbf29ce484222325
    FNV_PRIME = 0x100000001b3

    hash_value = FNV_OFFSET_BASIS
    for _ in range(8):
        hash_value ^= key & 0xFF
        hash_value *= FNV_PRIME
        hash_value &= 0xFFFFFFFFFFFFFFFF
        key >>= 8

    return hash_value

# Shift Right
def func1(flag):
    flag = bytearray(flag) 
    n = len(flag)
    if n > 1:
        last_char = flag[-1]
        for i in range(n - 1, 0, -1):
            flag[i] = flag[i - 1]
        flag[0] = last_char
    return flag

def func1_reverse(flag):
    flag = bytearray(flag) 
    n = len(flag)
    if n > 1:
        first_char = flag[0]
        for i in range(n - 1):
            flag[i] = flag[i + 1]
        flag[n - 1] = first_char
    return flag

def func2(flag):
    flag = bytearray(flag) 
    n = len(flag)
    if n > 1:
        first_char = flag[0]
        for i in range(n - 1):
            flag[i] = flag[i + 1]
        flag[n - 1] = first_char
    return flag

def func2_reverse(flag):
    flag = bytearray(flag) 
    n = len(flag)
    if n > 1:
        last_char = flag[-1]
        for i in range(n - 1, 0, -1):
            flag[i] = flag[i - 1]
        flag[0] = last_char
    return flag

def func3(flag):
    flag = bytearray(flag)
    for i in range(1, len(flag), 2):
        flag[i] ^= 0xaa
    return flag

def func3_reverse(flag):
    flag = bytearray(flag) 
    for i in range(1, len(flag), 2):
        flag[i] ^= 0xaa
    return flag

def func4(flag):
    flag = bytearray(flag) 
    for i in range(0, len(flag), 2):
        flag[i] ^= 0x77
    return flag

def func4_reverse(flag):
    flag = bytearray(flag) 
    for i in range(0, len(flag), 2):
        flag[i] ^= 0x77
    return flag

def func5(flag):
    flag = bytearray(flag) 
    for i in range(1, len(flag), 2):
        for bit in range(0, 8, 2):
            flag[i] ^= (1 << bit)
    return flag

def func5_reverse(flag):
    flag = bytearray(flag) 
    for i in range(1, len(flag), 2):
        for bit in range(0, 8, 2):
            flag[i] ^= (1 << bit)
    return flag

def func6(flag):
    flag = bytearray(flag) 
    n = len(flag)
    for i in range(16):
        flag[i], flag[n - 16 + i] = flag[n - 16 + i], flag[i]
    return flag

def func6_reverse(flag):
    flag = bytearray(flag)
    n = len(flag)
    for i in range(16):
        flag[i], flag[n - 16 + i] = flag[n - 16 + i], flag[i]
    return flag

def func7(flag):
    flag = bytearray(flag) 
    return flag

def func7_reverse(flag):
    flag = bytearray(flag) 
    return flag

def func8(flag):
    flag = bytearray(flag) 
    return flag

def func8_reverse(flag):
    flag = bytearray(flag) 
    return flag

def sha256sum_bytes(byte_array):
    import hashlib
    sha256_hash = hashlib.sha256()
    sha256_hash.update(byte_array)
    return sha256_hash.hexdigest()

key = 0x89cd31291d2aefa4
func_table = [func1, func2, func3, func4, func5, func6, func7, func8]
flag = b"b3c9f4e1d2b8a7e6c5f9d0b3a1e7c2f1d9b2"
origin_flag = flag
assert len(flag) == 36
hashed = sha256sum_bytes(flag)
print("compare hash table:", list(map(lambda x: int(x, 16), list(hashed[i:i+2] for i in range(0, len(hashed), 2)))))

order = []
for _ in range(100):
    key = fnv1a_hash64(key)
    index = key % 8
    order.append(func_table[index])

for func in order:
    flag = func(flag)

assert len(flag) == 36
result = ', '.join(list(map(lambda x: hex(x), list(flag))))
compare_table = list(eval(result))
print(f"compare table: [{result}]")

# verification
for func in order[::-1]:
    func_reverse = globals()[func.__name__ + "_reverse"]
    compare_table = func_reverse(compare_table)

assert compare_table == origin_flag
