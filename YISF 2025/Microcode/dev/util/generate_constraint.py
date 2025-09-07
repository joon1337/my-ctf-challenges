from Crypto.Util.number import *

def djb2(s: bytes) -> int:
    hash = 5381
    for c in s:
        hash = ((hash << 5) + hash) + c
        hash &= 0xFFFFFFFFFFFFFFFF
    return hash

flag = "9718067c22f31112cbcbdf9a2a33e07af74e443d561fdedf4c0404de3bb333740235921b611316a16b3c14b02b4e6043557ea006fe638d768f2c86e12b625ec7"
print(djb2(flag.encode()))
flag = list(map(ord, flag))

assert len(flag) == 128
l = []
for i in range(0, len(flag)-1):
    a, b = flag[i], flag[i+1]
    if a >= b:
        l.append(a-b)
    else:
        l.append(b-a)
l.append(0)

l = bytes(l)
print(list(l))
inp = input().encode()

for i in range(127):
    a, b = inp[i], inp[i+1]
    if a - b >= 0:
        assert a-b == l[i]
    else:
        assert b-a == l[i]
print(f"flag: {inp}")