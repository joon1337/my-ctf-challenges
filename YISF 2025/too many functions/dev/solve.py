from capstone import *

def get_func_size(addr):
    global md, f, binary
    code = binary[addr:addr + 150]   # heuristic 

    for i in md.disasm(code, 0):
        address, mnemonic, op_str = i.address, i.mnemonic, i.op_str
        if "ret" in mnemonic:
            return address   

def get_info(addr):
    global md, f, binary
    code = binary[addr:addr+get_func_size(addr)]

    for i in md.disasm(code, 0):
        address, mnemonic, op_str = i.address, i.mnemonic, i.op_str
        if "xor" in mnemonic:
            value = int(op_str.split(", ")[-1], 16) & 0xff
            return [0, value]
        elif "shl" in mnemonic:
            value = int(op_str.split(", ")[-1], 16) & 0xff
            return [1, value]
        elif "shr" in mnemonic:
            value = int(op_str.split(", ")[-1], 16) & 0xff
            return [2, value]

f = open("prob", "rb")
binary = f.read()
start = 0x47873A
end = 0x59D6A7
f.seek(start)
code = f.read(end - start)

md = Cs(CS_ARCH_X86, CS_MODE_64)
func_addr = []

for i in md.disasm(code, start):
    address, mnemonic, op_str = i.address, i.mnemonic, i.op_str 
    if "call" == mnemonic:
        func_addr.append(int(op_str, 16))

assert len(func_addr) == 50000

call = []

for addr in func_addr:
    _type, value = get_info(addr)
    call.append([_type, value])

enc_flag = [83, 115, 71, 109, 23, 45, 139, 139, 143, 39, 43, 143, 147, 39, 143, 43, 39, 137, 39, 129, 45, 137, 143, 145, 131, 43, 39, 35, 141, 143, 139, 139, 45, 43, 139, 139, 141, 143, 43, 133, 131, 145, 129, 141, 41, 39, 141, 147, 133, 145, 35, 147, 131, 37, 139, 45, 39, 45, 133, 147, 141, 133, 43, 133, 135, 137, 37, 145, 145, 45, 141, 133, 145, 37, 141, 39, 39, 143, 147, 133, 37, 37, 129, 137, 137, 131, 35, 131, 139, 45, 45, 37, 147, 137, 35, 135, 37, 143, 39, 133, 137, 41, 145, 45, 147, 41, 137, 145, 139, 43, 45, 39, 141, 135, 141, 139, 147, 41, 131, 39, 139, 133, 133, 39, 141, 41, 39, 145, 37, 41, 45, 145, 35, 27]

for type, value in call[::-1]:
    if type == 0:
        enc_flag = list(map(lambda x: x ^ value, enc_flag))
    elif type == 1:
        enc_flag = list(map(lambda x: ((x >> value) | (x << (8-value)) & 0xff) & 0xff, enc_flag))
    elif type == 2:
        enc_flag = list(map(lambda x: ((x << value) & 0xff | (x >> (8-value))) & 0xff, enc_flag))

print(''.join(map(chr, enc_flag)))