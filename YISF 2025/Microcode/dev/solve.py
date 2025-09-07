import string

diff = [2, 6, 7, 8, 6, 1, 44, 49, 0, 52, 51, 2, 0, 0, 1, 49, 1, 1, 1, 2, 2, 45, 40, 47, 47, 46, 0, 50, 53, 7, 42, 5, 47, 3, 49, 49, 0, 1, 49, 47, 1, 5, 53, 2, 1, 1, 2, 50, 47, 51, 4, 4, 4, 48, 1, 50, 47, 0, 47, 0, 0, 4, 3, 4, 2, 1, 2, 4, 7, 1, 49, 44, 5, 0, 2, 2, 5, 43, 48, 5, 44, 47, 48, 50, 3, 46, 50, 2, 48, 46, 49, 47, 6, 4, 1, 2, 0, 2, 46, 4, 49, 0, 6, 48, 1, 47, 3, 5, 44, 45, 1, 2, 46, 52, 49, 43, 2, 47, 52, 1, 48, 44, 4, 3, 48, 2, 44, 0]
flag_sum = 0x21e8

table = "0123456789abcdef"
candidate = []

def djb2(s: bytes) -> int:
    hash = 0x1505
    for c in s:
        hash = ((hash << 5) + hash) + c
        hash &= 0xFFFFFFFFFFFFFFFF
    return hash

def range_check(v):
    if not (0 <= v <= 0x10FFFF):
        return False
    c = chr(v)
    return c in table

def solve(l: list, idx: int, current_sum: int):
    if not range_check(l[-1]):
        return
    if idx == 127:
        if current_sum == flag_sum and djb2(bytes(l)) == 0x2ebd31af413b6c2d:
            candidate.append("".join(map(chr, l)))
        return

    for d in (diff[idx], -diff[idx]):
        next_val = l[-1] + d
        if range_check(next_val):
            l.append(next_val)
            solve(l, idx + 1, current_sum + next_val)
            l.pop()

if __name__ == "__main__":
    for c in map(ord, table):
        solve([c], 0, c)
    assert len(set(candidate)) == 1, print(set(candidate))
    print(candidate[0])