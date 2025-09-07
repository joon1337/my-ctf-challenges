diff = [2, 6, 7, 8, 6, 1, 44, 49, 0, 52, 51, 2, 0, 0, 1, 49, 1, 1, 1, 2, 2, 45, 40, 47, 47, 46, 0, 50, 53, 7, 42, 5, 47, 3, 49, 49, 0, 1, 49, 47, 1, 5, 53, 2, 1, 1, 2, 50, 47, 51, 4, 4, 4, 48, 1, 50, 47, 0, 47, 0, 0, 4, 3, 4, 2, 1, 2, 4, 7, 1, 49, 44, 5, 0, 2, 2, 5, 43, 48, 5, 44, 47, 48, 50, 3, 46, 50, 2, 48, 46, 49, 47, 6, 4, 1, 2, 0, 2, 46, 4, 49, 0, 6, 48, 1, 47, 3, 5, 44, 45, 1, 2, 46, 52, 49, 43, 2, 47, 52, 1, 48, 44, 4, 3, 48, 2, 44, 0]

def djb2(s: bytes) -> int:
    hash = 0x1505
    for c in s:
        hash = ((hash << 5) + hash) + c
        hash &= 0xFFFFFFFFFFFFFFFF
    return hash

flag = input()

# check length
assert len(flag) == 128

# check diff
for i in range(0, len(flag)-1):
    a, b = ord(flag[i]), ord(flag[i+1])
    if a >= b:
        assert diff[i] == (a-b)
    else:
        assert diff[i] == (b-a)

# check djb2 hash
assert djb2(flag.encode()) == 0x2ebd31af413b6c2d

print("YISF{%s}" % (flag))