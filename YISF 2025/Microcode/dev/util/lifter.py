import re
import json

register_groups = [
    ("rax", "eax", "ax", "al", "ah"),
    ("rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "esi", "si", "sil"),
    ("rdi", "edi", "di", "dil"),
    ("rbp", "ebp", "bp", "bpl"),
    ("rsp", "esp", "sp", "spl"),
    ("r8",  "r8d", "r8w", "r8b"),
    ("r9",  "r9d", "r9w", "r9b"),
    ("r10", "r10d", "r10w", "r10b"),
    ("r11", "r11d", "r11w", "r11b"),
    ("r12", "r12d", "r12w", "r12b"),
    ("r13", "r13d", "r13w", "r13b"),
    ("r14", "r14d", "r14w", "r14b"),
    ("r15", "r15d", "r15w", "r15b"),
]
register_map = {}
reg_id = 0
for group in register_groups:
    for reg in group:
        register_map[reg] = reg_id
        reg_id += 1

instr_map = {
    "mov": 0, "add": 1, "sub": 2, "xor": 3, "and": 4, "or": 5, "cmp": 6,
    "jmp": 7, "je": 8, "jne": 9, "call": 10, "ret": 11, "push": 12, 
    "pop": 13, "leave": 14, "syscall": 15
}

type_map = {
    "reg-imm": 0,
    "reg-reg": 1,
    "reg-mem": 2,
    "mem-reg": 3,
    "mem-imm": 4
}

def parse_operand(op):
    op = op.strip()
    if op.startswith('[') and op.endswith(']'):
        content = op[1:-1].strip()
        if '+' in content:
            base, offset = content.split('+', 1)
            base = base.strip(); offset = offset.strip()
            sign = 1
        elif '-' in content:
            base, offset = content.split('-', 1)
            base = base.strip(); offset = offset.strip()
            sign = -1
        else:
            base, offset, sign = content, "0", 1
        base = base.lower()
        if base not in register_map:
            raise ValueError(f"Unknown register: {base}")
        base_id = register_map[base]
        offset_val = int(offset, 16) if offset.startswith('0x') else int(offset) if offset else 0
        offset_val *= sign
        return 'mem', {"base": base_id, "offset": offset_val}
    elif op.lower() in register_map:
        return 'reg', register_map[op.lower()]
    else:
        if op.startswith('0x') or op.isdigit() or (op.startswith('-') and op[1:].isdigit()):
            val = int(op, 16) if op.startswith('0x') else int(op)
            return 'imm', val
        return 'label', op

def convert_to_ir(lines):
    label_map = {}
    ir_instructions = []
    label_info = []
    line_counter = 0
    for line in lines:
        if ':' in line:
            label, rest = line.split(':', 1)
            label = label.strip()
            label_map[label] = line_counter
            label_info.append({"label": label, "index": line_counter})
            line = rest.strip()
            if not line:
                continue
        if not line:
            continue
        line_counter += 1

    for raw in lines:
        line = raw
        line = line.split(';')[0].split('#')[0].strip()
        if not line or line.endswith(':'):
            continue
        if ':' in line:
            _, instr = line.split(':', 1)
            line = instr.strip()
            if not line: continue
        parts = line.split(None, 1)
        if not parts:
            continue
        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ''
        ops = [op.strip() for op in operands.split(',')] if operands else []
        op_id = instr_map.get(mnemonic, None)
        if op_id is None:
            continue

        ir = {"op": op_id, "type": "", "dst": None, "src": None, "raw": raw.strip()}
        parsed = [parse_operand(o) for o in ops if o]

        if mnemonic in ("ret", "leave", "syscall"):
            ir["type"] = "none"
        elif mnemonic in ("jmp", "je", "jne"):
            label = parsed[0][1] if parsed else None
            target = label_map.get(label, None) if isinstance(label, str) else label
            ir["type"] = "branch"
            ir["dst"] = None
            ir["src"] = target
        elif mnemonic == "call":
            if parsed and parsed[0][0] == 'label':
                target = label_map.get(parsed[0][1], parsed[0][1])
                ir["src"] = target
            else:
                ir["src"] = parsed[0][1] if parsed else None
            ir["type"] = "call"
            ir["dst"] = None
        else:
            if len(parsed) == 1:
                kind, val = parsed[0]
                ir["dst"] = val if kind != 'mem' else {"base": val["base"], "offset": val["offset"]}
                ir["src"] = None
                ir["type"] = kind
            elif len(parsed) == 2:
                dst_kind, dst_val = parsed[0]
                src_kind, src_val = parsed[1]
                if dst_kind == 'mem':
                    ir["dst"] = {"base": dst_val["base"], "offset": dst_val["offset"]}
                else:
                    ir["dst"] = dst_val
                if src_kind == 'mem':
                    ir["src"] = {"base": src_val["base"], "offset": src_val["offset"]}
                else:
                    ir["src"] = src_val
                ir["type"] = f"{dst_kind}-{src_kind}"
        ir_instructions.append(ir)
    return ir_instructions, label_info

def run(input_file):
    with open(input_file, 'r') as f:
        lines = [line.strip().split(';')[0].split('#')[0] for line in f if line.strip()]
    lines = [l for l in lines if l]
    ir_list, label_info = convert_to_ir(lines)
    result = {
        "ir": ir_list,
        "labels": label_info
    }

    return result