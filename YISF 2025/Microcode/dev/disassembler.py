from pwn import *
from enum import Enum

INSTRUCTION_SIZE = 17

instr_map = {
    "mov": 0, "add": 1, "sub": 2, "xor": 3, "and": 4, "or": 5, "cmp": 6,
    "jmp": 7, "je": 8, "jne": 9, "call": 10, "ret": 11, "push": 12, 
    "pop": 13, "leave": 14, "syscall": 15
}
instr_map = {b:a for a, b in zip(instr_map.keys(), instr_map.values())}

class OperandType(Enum):
    REGIMM = 0
    REGREG = 1
    REGMEM = 2
    MEMREG = 3
    MEMIMM = 4

register_groups = [
    ("Reg1", "dwReg1", "wReg1", "lReg1", "hReg1"),
    ("Reg2", "dwReg2", "wReg2", "lReg2", "hReg2"),
    ("Reg3", "dwReg3", "wReg3", "lReg3", "hReg3"),
    ("Reg4", "dwReg4", "wReg4", "lReg4", "hReg4"),
    ("Reg5", "dwReg5", "wReg5", "lReg5"),
    ("Reg6", "dwReg6", "wReg6", "lReg6"),
    ("rbp", "ebp", "bp", "bpl"),
    ("rsp", "esp", "sp", "spl"),
    ("Reg7",  "dwReg7", "wReg7", "lReg7"),
    ("Reg8",  "dwReg8", "wReg8", "lReg8"),
    ("Reg9", "dwReg9", "wReg9", "lReg9"),
    ("Reg10", "dwReg10", "wReg10", "lReg10"),
    ("Reg11", "dwReg11", "wReg11", "lReg11"),
    ("Reg12", "dwReg12", "wReg12", "lReg12"),
    ("Reg13", "dwReg13", "wReg13", "lReg13"),
    ("Reg14", "dwReg14", "wReg14", "lReg14"),
]

register_map = {}
reg_id = 0
for group in register_groups:
    for reg in group:
        register_map[reg_id] = reg
        reg_id += 1

def parse(value):
    return [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xffffffffffff]

def disasm(bytecode):
    for i in range(0, len(bytecode), INSTRUCTION_SIZE):
        print(f"{hex(i)}: ".ljust(10, " "), end=' ')
        c = bytecode[i:i+INSTRUCTION_SIZE]
        header = c[0]
        operand_dst, operand_src = u64(c[1:9]), u64(c[9:17])
        opcode = (header >> 3) & 0b11111
        operand_type = (header) & 0b111

        assert operand_type >= 0 and operand_type <= 4
        if operand_type == OperandType.REGIMM.value:
            if instr_map[opcode] == "push":
                print(f"push {register_map[operand_dst]}")
            elif instr_map[opcode] == "pop":
                print(f"pop {register_map[operand_dst]}")
            elif instr_map[opcode] in ["call", "jmp", "je", "jne"]:
                print(f"{instr_map[opcode]} {hex(operand_dst)}")
            elif instr_map[opcode] in ["cmp", "mov", "add", "sub", "and"]:
                print(f"{instr_map[opcode]} {register_map[operand_dst]}, {hex(operand_src)}")
            else:
                print(instr_map[opcode])
        elif operand_type == OperandType.REGREG.value:
            print(f"{instr_map[opcode]} {register_map[operand_dst]}, {register_map[operand_src]}")
        elif operand_type == OperandType.REGMEM.value:
            base, sign, offset_bytes = parse(operand_src)
            if sign:
                if offset_bytes == 0:
                    print(f"{instr_map[opcode]} {register_map[operand_dst]}, [{register_map[base]}]")
                else:
                    print(f"{instr_map[opcode]} {register_map[operand_dst]}, [{register_map[base]} + {offset_bytes}]")
            else:
                if offset_bytes == 0:
                    print(f"{instr_map[opcode]} {register_map[operand_dst]}, [{register_map[base]}]")
                else:
                    print(f"{instr_map[opcode]} {register_map[operand_dst]}, [{register_map[base]} - {offset_bytes}]")
        elif operand_type == OperandType.MEMREG.value:
            base, sign, offset_bytes = parse(operand_dst)
            if sign:
                if offset_bytes == 0:
                    print(f"{instr_map[opcode]} [{register_map[base]}], {register_map[operand_src]}")
                else:
                    print(f"{instr_map[opcode]} [{register_map[base]} + {offset_bytes}], {register_map[operand_src]}")
            else:
                if offset_bytes == 0:
                    print(f"{instr_map[opcode]} [{register_map[base]}], {register_map[operand_src]}")
                else:
                    print(f"{instr_map[opcode]} [{register_map[base]} - {offset_bytes}], {register_map[operand_src]}")
        elif operand_type == OperandType.MEMIMM.value:
            base, sign, offset_bytes = parse(operand_dst)
            if sign:
                if offset_bytes == 0:
                    print(f"{instr_map[opcode]} [{register_map[base]}], {hex(operand_src)}")
                else:
                    print(f"{instr_map[opcode]} [{register_map[base]} + {offset_bytes}], {hex(operand_src)}")
            else:
                if offset_bytes == 0:
                    print(f"{instr_map[opcode]} [{register_map[base]}], {hex(operand_src)}")
                else:
                    print(f"{instr_map[opcode]} [{register_map[base]} - {offset_bytes}], {hex(operand_src)}")

if __name__ == "__main__":
    with open("./vm/vm", "rb") as f:
        f.seek(0x4018)
        bytecode = f.read(INSTRUCTION_SIZE * 662)
    disasm(bytecode)

