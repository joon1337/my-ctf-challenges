import random
import copy

FLAG = "YISF{f557ce79c7ec4c0f4781eca6755fe5567e21806dc6928a91b5fcf2962e234b88f628b6cc792bb0441a15ffb94a3b7c24d8f9d485efc63659d1c522c6dc8bdf8a}"
COUNT = 50000

# xor
template1 = """
void func%s(unsigned char *ptr, unsigned char length) {
    for (int i=0; i<length; i++) {
        ptr[i] ^= %s;
    }
}
"""

# rotate shift left
template2 = """
void func%s(unsigned char *ptr, unsigned char length) {
    for (int i=0; i<length; i++) {
        ptr[i] = (ptr[i] << %s) | (ptr[i] >> (8-%s));
    }
}
"""

# rotate shift right
template3 = """
void func%s(unsigned char *ptr, unsigned char length) {
    for (int i=0; i<length; i++) {
        ptr[i] = (ptr[i] >> %s) | (ptr[i] << (8-%s));
    }
}
"""

class Info:
    def __init__(self, func, type, value):
        self.func = func
        self.type = type
        self.value = value

templates = [template1, template2, template3]
l = []

for i in range(COUNT):
    idx = random.randint(0, len(templates)-1)
    template = templates[idx]

    if idx == 0:
        value = random.randint(1, 0xff-1)
        func = template % (i, value)
    elif idx == 1 or idx == 2:
        value = random.randint(1, 7)
        func = template % (i, value, value)
    l.append(Info(func, idx, value))

l_shuffle = copy.deepcopy(l)
random.shuffle(l_shuffle)

def parse_func_name(string: str):
    return string[string.index("func"):string.index("(")]

def gen_random_call(l_info: list):
    call = []
    for info in l_info:
        call.append(parse_func_name(info.func) + f"(flag, length);")
    return '\n'.join(call)

def forward_transform(l_info, flag):
    flag = list(map(ord, flag))
    for info in l_info:
        if info.type == 0:
            flag = list(map(lambda x: (x ^ info.value) & 0xff, flag))
        elif info.type == 1:
            flag = list(map(lambda x: ((x << info.value) & 0xff | (x >> (8-info.value))) & 0xff, flag))
        elif info.type == 2:
            flag = list(map(lambda x: ((x >> info.value) | (x << (8-info.value)) & 0xff) & 0xff, flag))
    return flag

def reverse_transform(l_info, enc_flag):
    for info in l_info[::-1]:
        if info.type == 0:
            enc_flag = list(map(lambda x: (x ^ info.value) & 0xff, enc_flag))
        elif info.type == 1:
            enc_flag = list(map(lambda x: ((x >> info.value) | (x << (8-info.value)) & 0xff) & 0xff, enc_flag))
        elif info.type == 2:
            enc_flag = list(map(lambda x: ((x << info.value) & 0xff | (x >> (8-info.value))) & 0xff, enc_flag))
    return enc_flag

def verify(l_info, enc_flag, flag):
    assert ''.join(map(chr, reverse_transform(l_info, enc_flag))) == flag, "verify failed"

call = gen_random_call(l_shuffle)
enc_flag = forward_transform(l_shuffle, FLAG)

verify(l_shuffle, enc_flag, FLAG)

code = """
#include <stdio.h>
#include <string.h>
#include <unistd.h>

%s

int main() {
    unsigned char flag[0x100] = {0, };
    unsigned char compare_list[] = { %s };

    ssize_t len = read(0, flag, sizeof(flag));
    if (flag[len-1] == '\\n') flag[len-1] = 0;
    else flag[len] = 0;

    unsigned char length = strlen(flag);

    if (length != %s) {
        puts("Failed");
        return 1;
    }

    %s

    if (!memcmp(flag, compare_list, sizeof(compare_list))) {
        puts("Success");
    }
    else {
        puts("Failed");
    }
    return 0;
}
"""

with open("prob.c", "w") as f:
    f.write(code % (
        '\n'.join([v.func for v in l]),
        ', '.join(map(str, enc_flag)),
        len(FLAG),
        call
    ))
