import sys
import json
import random
import struct

import lifter

DEBUG = False

def p8(x):  return struct.pack('<B', x)
def p16(x): return struct.pack('<H', x)
def p32(x): return struct.pack('<I', x)
def p64(x): return struct.pack('<Q', x)

def u8(b):  return struct.unpack('<B', b)[0]
def u16(b): return struct.unpack('<H', b)[0]
def u32(b): return struct.unpack('<I', b)[0]
def u64(b): return struct.unpack('<Q', b)[0]

INSTRUCTION_SIZE = 17

def generate(input_file="prob.asm", DEBUG=True):
    result = lifter.run(input_file)
    IR = result["ir"]
    LABELS = result["labels"]

    if DEBUG:
        print(json.dumps(result, indent=2))

    def find_label_index(label_name):
        for label in LABELS:
            if label["label"] == label_name:
                return label["index"]
        return None

    for idx, info in enumerate(IR):
        bytecode = b""

        if info["type"] in lifter.type_map:
            bytecode += p8((info["op"] << 3) | lifter.type_map[info["type"]])

            dst_type, src_type = info["type"].split("-")

            if dst_type == "reg":
                bytecode += p64(info["dst"])
            elif dst_type == "mem":
                base = info["dst"]["base"]
                offset = info["dst"]["offset"]
                sign = 1 if offset >= 0 else 0
                offset_bytes = p64(abs(offset))[:6]
                bytecode += p8(base) + p8(sign) + offset_bytes

            if src_type == "imm" or src_type == "reg":
                bytecode += p64(info["src"])
            elif src_type == "mem":
                base = info["src"]["base"]
                offset = info["src"]["offset"]
                sign = 1 if offset >= 0 else 0
                offset_bytes = p64(abs(offset))[:6]
                bytecode += p8(base) + p8(sign) + offset_bytes
        elif info["type"] == "reg":
            bytecode += p8((info["op"] << 3) | lifter.type_map["reg-imm"])
            bytecode += p64(info["dst"])
            bytecode += p64(0)
        else:
            bytecode += p8(info["op"] << 3)

            if info["type"] in ["branch", "call"]:
                label_name = info["raw"].split(" ")[-1]
                target_idx = find_label_index(label_name)
                if target_idx is None:
                    target_idx = 0
                if DEBUG:
                    bytecode += p64(target_idx * INSTRUCTION_SIZE) + p64(0)
                else:
                    bytecode += p64(target_idx * INSTRUCTION_SIZE) + random.randbytes(8)
            else:
                if DEBUG:
                    bytecode += p64(0) * 2
                else:
                    bytecode += random.randbytes(16)

        assert len(bytecode) == INSTRUCTION_SIZE, f"Instruction size mismatch at idx {idx}: {len(bytecode)}"
        info["bytecode"] = bytecode

    return result

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input_file> <output_file>")
        sys.exit()
    
    result = generate(sys.argv[1], DEBUG)
    entrypoint = None

    for v in result["labels"]:
        if v["label"] == "_start":
            entrypoint = INSTRUCTION_SIZE * v["index"]
            break

    if entrypoint is not None:
        print("entrypoint:", entrypoint)
    else:
        print("At least one _start label must be present")
        sys.exit()
        
    with open(sys.argv[2], "wb") as f:
        f.write(b"".join(v["bytecode"] for v in result["ir"]))