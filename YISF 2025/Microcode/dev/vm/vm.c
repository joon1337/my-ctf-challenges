#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>

#define STACK_SIZE 0x3000
#define ENTRY_POINT 0
#define INSTRUCTION_SIZE 17
#define DEBUG 0

extern unsigned char _binary____util_prob_bytecode_end[];
extern unsigned char _binary____util_prob_bytecode_start[];
unsigned char *code = &_binary____util_prob_bytecode_start;

typedef enum {
    RAX, EAX, AX, AL, AH,
    RBX, EBX, BX, BL, BH,
    RCX, ECX, CX, CL, CH,
    RDX, EDX, DX, DL, DH,
    RSI, ESI, SI, SIL,
    RDI, EDI, DI, DIL,
    RBP, EBP, BP, BPL,
    RSP, ESP, SP, SPL,
    R8, R8D, R8W, R8B,
    R9, R9D, R9W, R9B,
    R10, R10D, R10W, R10B,
    R11, R11D, R11W, R11B,
    R12, R12D, R12W, R12B,
    R13, R13D, R13W, R13B,
    R14, R14D, R14W, R14B,
    R15, R15D, R15W, R15B,
} register_map_t;

typedef enum {
    OP_MOV,
    OP_ADD,
    OP_SUB,
    OP_XOR,
    OP_AND,
    OP_OR,
    OP_CMP,
    OP_JMP,
    OP_JE,
    OP_JNE,
    OP_CALL,
    OP_RET,
    OP_PUSH,
    OP_POP,
    OP_LEAVE,
    OP_SYSCALL
} instruction_map_t;

typedef enum {
    REGIMM,
    REGREG,
    REGMEM,
    MEMREG,
    MEMIMM
} operand_map_t;

typedef struct {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
} registers_t;

typedef struct {
    registers_t reg;
    void *stack_start;
    void *stack_end;
    uint8_t flag;
} context_t;

typedef struct __attribute__((packed)) {
    union {
        struct {
            uint8_t type : 3;
            uint8_t op   : 5;
        };
        uint8_t header;
    };
    union {
        struct {
            uint64_t dst;
            uint64_t src;
        } reg_or_imm;
        struct {
            uint8_t  dst_base;
            uint8_t  dst_sign;
            uint8_t  dst_offset[6];
            uint8_t  src_base;
            uint8_t  src_sign;
            uint8_t  src_offset[6];
        } mem;
    };
} instruction_t;

context_t *init_context() {
    context_t *ctx = malloc(sizeof(context_t));
    memset(ctx, 0, sizeof(context_t));
    void *addr = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }
    ctx->stack_start = addr;
    ctx->stack_end = addr + STACK_SIZE;
    ctx->reg.rbp = ctx->reg.rsp = (uintptr_t)addr + 0x2000;
    ctx->reg.rip = ENTRY_POINT;
    return ctx;
}

uint64_t get_reg(context_t *ctx, register_map_t reg) {
    switch(reg) {
        case RAX:
            return ctx->reg.rax;
        case EAX:
            return (uint32_t)ctx->reg.rax;
        case AX:
            return (uint16_t)ctx->reg.rax;
        case AL:
            return (uint8_t)ctx->reg.rax;
        case AH:
            return (uint8_t)(ctx->reg.rax >> 8);
        case RBX:
            return ctx->reg.rbx;
        case EBX:
            return (uint32_t)ctx->reg.rbx;
        case BX:
            return (uint16_t)ctx->reg.rbx;
        case BL:
            return (uint8_t)ctx->reg.rbx;
        case BH:
            return (uint8_t)(ctx->reg.rbx >> 8);
        case RCX:
            return ctx->reg.rcx;
        case ECX:
            return (uint32_t)ctx->reg.rcx;
        case CX:
            return (uint16_t)ctx->reg.rcx;
        case CL:
            return (uint8_t)ctx->reg.rcx;
        case CH:
            return (uint8_t)(ctx->reg.rcx >> 8);
        case RDX:
            return ctx->reg.rdx;
        case EDX:
            return (uint32_t)ctx->reg.rdx;
        case DX:
            return (uint16_t)ctx->reg.rdx;
        case DL:
            return (uint8_t)ctx->reg.rdx;
        case DH:
            return (uint8_t)(ctx->reg.rdx >> 8);
        case RSI:
            return ctx->reg.rsi;
        case ESI:
            return (uint32_t)ctx->reg.rsi;
        case SI:
            return (uint16_t)ctx->reg.rsi;
        case SIL:
            return (uint8_t)ctx->reg.rsi;
        case RDI:
            return ctx->reg.rdi;
        case EDI:
            return (uint32_t)ctx->reg.rdi;
        case DI:
            return (uint16_t)ctx->reg.rdi;
        case DIL:
            return (uint8_t)ctx->reg.rdi;
        case RBP:
            return ctx->reg.rbp;
        case EBP:
            return (uint32_t)ctx->reg.rbp;
        case BP:
            return (uint16_t)ctx->reg.rbp;
        case BPL:
            return (uint8_t)ctx->reg.rbp;
        case RSP:
            return ctx->reg.rsp;
        case ESP:
            return (uint32_t)ctx->reg.rsp;
        case SP:
            return (uint16_t)ctx->reg.rsp;
        case SPL:
            return (uint8_t)ctx->reg.rsp;
        case R8:
            return ctx->reg.r8;
        case R8D:
            return (uint32_t)ctx->reg.r8;
        case R8W:
            return (uint16_t)ctx->reg.r8;
        case R8B:
            return (uint8_t)ctx->reg.r8;
        case R9:
            return ctx->reg.r9;
        case R9D:
            return (uint32_t)ctx->reg.r9;
        case R9W:
            return (uint16_t)ctx->reg.r9;
        case R9B:
            return (uint8_t)ctx->reg.r9;
        case R10:
            return ctx->reg.r10;
        case R10D:
            return (uint32_t)ctx->reg.r10;
        case R10W:
            return (uint16_t)ctx->reg.r10;
        case R10B:
            return (uint8_t)ctx->reg.r10;
        case R11:
            return ctx->reg.r11;
        case R11D:
            return (uint32_t)ctx->reg.r11;
        case R11W:
            return (uint16_t)ctx->reg.r11;
        case R11B:
            return (uint8_t)ctx->reg.r11;
        case R12:
            return ctx->reg.r12;
        case R12D:
            return (uint32_t)ctx->reg.r12;
        case R12W:
            return (uint16_t)ctx->reg.r12;
        case R12B:
            return (uint8_t)ctx->reg.r12;
        case R13:
            return ctx->reg.r13;
        case R13D:
            return (uint32_t)ctx->reg.r13;
        case R13W:
            return (uint16_t)ctx->reg.r13;
        case R13B:
            return (uint8_t)ctx->reg.r13;
        case R14:
            return ctx->reg.r14;
        case R14D:
            return (uint32_t)ctx->reg.r14;
        case R14W:
            return (uint16_t)ctx->reg.r14;
        case R14B:
            return (uint8_t)ctx->reg.r14;
        case R15:
            return ctx->reg.r15;
        case R15D:
            return (uint32_t)ctx->reg.r15;
        case R15W:
            return (uint16_t)ctx->reg.r15;
        case R15B:
            return (uint8_t)ctx->reg.r15;
    default:
        exit(0);
    }
}

void set_reg(context_t *ctx, register_map_t reg, uint64_t value) {
    switch(reg) {
        case RAX:
            ctx->reg.rax = value; break;
        case EAX:
            ctx->reg.rax = (ctx->reg.rax & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case AX:
            ctx->reg.rax = (ctx->reg.rax & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case AL:
            ctx->reg.rax = (ctx->reg.rax & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case AH:
            ctx->reg.rax = (ctx->reg.rax & ~(0xFFULL << 8)) | (((uint64_t)(value) & 0xFF) << 8); break;
        case RBX:
            ctx->reg.rbx = value; break;
        case EBX:
            ctx->reg.rbx = (ctx->reg.rbx & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case BX:
            ctx->reg.rbx = (ctx->reg.rbx & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case BL:
            ctx->reg.rbx = (ctx->reg.rbx & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case BH:
            ctx->reg.rbx = (ctx->reg.rbx & ~(0xFFULL << 8)) | (((uint64_t)(value) & 0xFF) << 8); break;
        case RCX:
            ctx->reg.rcx = value; break;
        case ECX:
            ctx->reg.rcx = (ctx->reg.rcx & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case CX:
            ctx->reg.rcx = (ctx->reg.rcx & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case CL:
            ctx->reg.rcx = (ctx->reg.rcx & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case CH:
            ctx->reg.rcx = (ctx->reg.rcx & ~(0xFFULL << 8)) | (((uint64_t)(value) & 0xFF) << 8); break;
        case RDX:
            ctx->reg.rdx = value; break;
        case EDX:
            ctx->reg.rdx = (ctx->reg.rdx & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case DX:
            ctx->reg.rdx = (ctx->reg.rdx & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case DL:
            ctx->reg.rdx = (ctx->reg.rdx & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case DH:
            ctx->reg.rdx = (ctx->reg.rdx & ~(0xFFULL << 8)) | (((uint64_t)(value) & 0xFF) << 8); break;
        case RSI:
            ctx->reg.rsi = value; break;
        case ESI:
            ctx->reg.rsi = (ctx->reg.rsi & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case SI:
            ctx->reg.rsi = (ctx->reg.rsi & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case SIL:
            ctx->reg.rsi = (ctx->reg.rsi & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case RDI:
            ctx->reg.rdi = value; break;
        case EDI:
            ctx->reg.rdi = (ctx->reg.rdi & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case DI:
            ctx->reg.rdi = (ctx->reg.rdi & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case DIL:
            ctx->reg.rdi = (ctx->reg.rdi & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case RBP:
            ctx->reg.rbp = value; break;
        case EBP:
            ctx->reg.rbp = (ctx->reg.rbp & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case BP:
            ctx->reg.rbp = (ctx->reg.rbp & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case BPL:
            ctx->reg.rbp = (ctx->reg.rbp & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case RSP:
            ctx->reg.rsp = value; break;
        case ESP:
            ctx->reg.rsp = (ctx->reg.rsp & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case SP:
            ctx->reg.rsp = (ctx->reg.rsp & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case SPL:
            ctx->reg.rsp = (ctx->reg.rsp & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R8:
            ctx->reg.r8 = value; break;
        case R8D:
            ctx->reg.r8 = (ctx->reg.r8 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R8W:
            ctx->reg.r8 = (ctx->reg.r8 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R8B:
            ctx->reg.r8 = (ctx->reg.r8 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R9:
            ctx->reg.r9 = value; break;
        case R9D:
            ctx->reg.r9 = (ctx->reg.r9 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R9W:
            ctx->reg.r9 = (ctx->reg.r9 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R9B:
            ctx->reg.r9 = (ctx->reg.r9 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R10:
            ctx->reg.r10 = value; break;
        case R10D:
            ctx->reg.r10 = (ctx->reg.r10 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R10W:
            ctx->reg.r10 = (ctx->reg.r10 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R10B:
            ctx->reg.r10 = (ctx->reg.r10 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R11:
            ctx->reg.r11 = value; break;
        case R11D:
            ctx->reg.r11 = (ctx->reg.r11 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R11W:
            ctx->reg.r11 = (ctx->reg.r11 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R11B:
            ctx->reg.r11 = (ctx->reg.r11 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R12:
            ctx->reg.r12 = value; break;
        case R12D:
            ctx->reg.r12 = (ctx->reg.r12 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R12W:
            ctx->reg.r12 = (ctx->reg.r12 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R12B:
            ctx->reg.r12 = (ctx->reg.r12 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R13:
            ctx->reg.r13 = value; break;
        case R13D:
            ctx->reg.r13 = (ctx->reg.r13 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R13W:
            ctx->reg.r13 = (ctx->reg.r13 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R13B:
            ctx->reg.r13 = (ctx->reg.r13 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R14:
            ctx->reg.r14 = value; break;
        case R14D:
            ctx->reg.r14 = (ctx->reg.r14 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R14W:
            ctx->reg.r14 = (ctx->reg.r14 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R14B:
            ctx->reg.r14 = (ctx->reg.r14 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        case R15:
            ctx->reg.r15 = value; break;
        case R15D:
            ctx->reg.r15 = (ctx->reg.r15 & 0xFFFFFFFF00000000) | ((uint64_t)(value) & 0xFFFFFFFF); break;
        case R15W:
            ctx->reg.r15 = (ctx->reg.r15 & 0xFFFFFFFFFFFF0000) | ((uint64_t)(value) & 0xFFFF); break;
        case R15B:
            ctx->reg.r15 = (ctx->reg.r15 & ~0xFFULL) | ((uint64_t)(value) & 0xFF); break;
        default: 
            break;
    }
}

void fetch(instruction_t *inst, uint64_t rip) {
    memcpy(inst, &code[rip], INSTRUCTION_SIZE);
}

#if DEBUG
void debug_print(context_t *ctx) {
    printf("=== Register State ===\n");
    printf("RAX: 0x%016lx  RBX: 0x%016lx\n", ctx->reg.rax, ctx->reg.rbx);
    printf("RCX: 0x%016lx  RDX: 0x%016lx\n", ctx->reg.rcx, ctx->reg.rdx);
    printf("RSI: 0x%016lx  RDI: 0x%016lx\n", ctx->reg.rsi, ctx->reg.rdi);
    printf("RBP: 0x%016lx  RSP: 0x%016lx\n", ctx->reg.rbp, ctx->reg.rsp);
    printf("R8 : 0x%016lx  R9 : 0x%016lx\n", ctx->reg.r8,  ctx->reg.r9);
    printf("R10: 0x%016lx  R11: 0x%016lx\n", ctx->reg.r10, ctx->reg.r11);
    printf("R12: 0x%016lx  R13: 0x%016lx\n", ctx->reg.r12, ctx->reg.r13);
    printf("R14: 0x%016lx  R15: 0x%016lx\n", ctx->reg.r14, ctx->reg.r15);
    printf("RIP: 0x%016lx\n", ctx->reg.rip);
    printf("FLAG: %s\n", ctx->flag ? "SET (==)" : "CLEAR (!=)");
    printf("=======================\n");
}
#endif

void run(context_t *ctx) {
    while (1) {
        #if DEBUG
        debug_print(ctx);
        #endif
        instruction_t inst;
        fetch(&inst, ctx->reg.rip);
        uint8_t op = inst.op;
        uint8_t type = inst.type;
        uint64_t next_rip = ctx->reg.rip + INSTRUCTION_SIZE;
        if (op == OP_JMP) {
            ctx->reg.rip = inst.reg_or_imm.dst;
            continue;
        } else if (op == OP_JE) {
            if (ctx->flag)
                ctx->reg.rip = inst.reg_or_imm.dst;
            else
                ctx->reg.rip = next_rip;
            continue;
        } else if (op == OP_JNE) {
            if (!ctx->flag)
                ctx->reg.rip = inst.reg_or_imm.dst;
            else
                ctx->reg.rip = next_rip;
            continue;
        } else if (op == OP_CALL) {
            ctx->reg.rsp -= 8;
            memcpy((uint8_t*)ctx->reg.rsp, &next_rip, 8);
            ctx->reg.rip = inst.reg_or_imm.dst;
            continue;
        } else if (op == OP_RET) {
            uint64_t ret_addr;
            memcpy(&ret_addr, (uint8_t*)ctx->reg.rsp, 8);
            ctx->reg.rsp += 8;
            ctx->reg.rip = ret_addr;
            continue;
        } else if (op == OP_PUSH) {
            register_map_t src = inst.reg_or_imm.dst;
            uint64_t val = get_reg(ctx, src);
            ctx->reg.rsp -= 8;
            memcpy((uint8_t*)ctx->reg.rsp, &val, 8);
            ctx->reg.rip = next_rip;
            continue;
        } else if (op == OP_POP) {
            register_map_t dst = inst.reg_or_imm.dst;
            uint64_t val;
            memcpy(&val, (uint8_t*)ctx->reg.rsp, 8);
            ctx->reg.rsp += 8;
            set_reg(ctx, dst, val);
            ctx->reg.rip = next_rip;
            continue;
        } else if (op == OP_LEAVE) {
            ctx->reg.rsp = ctx->reg.rbp;
            uint64_t new_rbp;
            memcpy(&new_rbp, (uint8_t*)ctx->reg.rsp, 8);
            ctx->reg.rsp += 8;
            ctx->reg.rbp = new_rbp;
            ctx->reg.rip = next_rip;
            continue;
        } else if (op == OP_SYSCALL) {
            long ret = syscall(
                ctx->reg.rax,
                ctx->reg.rdi,
                ctx->reg.rsi,
                ctx->reg.rdx,
                ctx->reg.r10,
                ctx->reg.r8,
                ctx->reg.r9
            );
            ctx->reg.rax = ret;
            ctx->reg.rip = next_rip;
            continue;
        } else {
            if (type == REGIMM) {
                register_map_t dst = inst.reg_or_imm.dst;
                uint64_t imm = inst.reg_or_imm.src;
                uint64_t dst_val;
                switch (op) {
                    case OP_MOV:
                        set_reg(ctx, dst, imm);
                        break;
                    case OP_ADD:
                        dst_val = get_reg(ctx, dst) + imm;
                        set_reg(ctx, dst, dst_val);
                        break;
                    case OP_SUB:
                        dst_val = get_reg(ctx, dst) - imm;
                        set_reg(ctx, dst, dst_val);
                        break;
                    case OP_XOR:
                        dst_val = get_reg(ctx, dst) ^ imm;
                        set_reg(ctx, dst, dst_val);
                        break;
                    case OP_AND:
                        dst_val = get_reg(ctx, dst) & imm;
                        set_reg(ctx, dst, dst_val);
                        break;
                    case OP_OR:
                        dst_val = get_reg(ctx, dst) | imm;
                        set_reg(ctx, dst, dst_val);
                        break;
                    case OP_CMP:
                        ctx->flag = (get_reg(ctx, dst) == imm);
                        break;
                    default:
                        break;
                }
            } else if (type == REGREG) {
                register_map_t dst = inst.reg_or_imm.dst;
                register_map_t src = inst.reg_or_imm.src;
                uint64_t src_val = get_reg(ctx, src);
                uint64_t res;
                switch (op) {
                    case OP_MOV:
                        set_reg(ctx, dst, src_val);
                        break;
                    case OP_ADD:
                        res = get_reg(ctx, dst) + src_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_SUB:
                        res = get_reg(ctx, dst) - src_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_XOR:
                        res = get_reg(ctx, dst) ^ src_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_AND:
                        res = get_reg(ctx, dst) & src_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_OR:
                        res = get_reg(ctx, dst) | src_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_CMP:
                        ctx->flag = (get_reg(ctx, dst) == src_val);
                        break;
                    default:
                        break;
                }
            } else if (type == REGMEM) {
                register_map_t dst = inst.reg_or_imm.dst;
                uint8_t base = inst.mem.src_base;
                uint8_t sign = inst.mem.src_sign;
                uint64_t offset = 0;
                for (int i = 0; i < 6; i++) {
                    offset |= ((uint64_t)inst.mem.src_offset[i]) << (8*i);
                }
                uint64_t base_val = get_reg(ctx, base);
                uint64_t addr = (sign ? (base_val + offset) : (base_val - offset));
                uint64_t mem_val;
                memcpy(&mem_val, (uint8_t*)addr, 8);
                uint64_t res;
                switch (op) {
                    case OP_MOV:
                        set_reg(ctx, dst, mem_val);
                        break;
                    case OP_ADD:
                        res = get_reg(ctx, dst) + mem_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_SUB:
                        res = get_reg(ctx, dst) - mem_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_XOR:
                        res = get_reg(ctx, dst) ^ mem_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_AND:
                        res = get_reg(ctx, dst) & mem_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_OR:
                        res = get_reg(ctx, dst) | mem_val;
                        set_reg(ctx, dst, res);
                        break;
                    case OP_CMP:
                        ctx->flag = (get_reg(ctx, dst) == mem_val);
                        break;
                    default:
                        break;
                }
            } else if (type == MEMREG) {
                uint8_t base = inst.mem.dst_base;
                uint8_t sign = inst.mem.dst_sign;
                uint64_t offset = 0;
                for (int i = 0; i < 6; i++) {
                    offset |= ((uint64_t)inst.mem.dst_offset[i]) << (8*i);
                }
                uint64_t base_val = get_reg(ctx, base);
                uint64_t addr = (sign ? (base_val + offset) : (base_val - offset));
                register_map_t src = inst.mem.src_base;
                uint64_t src_val = get_reg(ctx, src);
                uint64_t mem_val;
                memcpy(&mem_val, (uint8_t*)addr, 8);
                uint64_t res;
                switch (op) {
                    case OP_MOV:
                        memcpy((uint8_t*)addr, &src_val, 8);
                        break;
                    case OP_ADD:
                        res = mem_val + src_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_SUB:
                        res = mem_val - src_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_XOR:
                        res = mem_val ^ src_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_AND:
                        res = mem_val & src_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_OR:
                        res = mem_val | src_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_CMP:
                        ctx->flag = (mem_val == src_val);
                        break;
                    default:
                        break;
                }
            } else if (type == MEMIMM) {
                uint8_t base = inst.mem.dst_base;
                uint8_t sign = inst.mem.dst_sign;
                uint64_t offset = 0;
                for (int i = 0; i < 6; i++) {
                    offset |= ((uint64_t)inst.mem.dst_offset[i]) << (8*i);
                }
                uint64_t base_val = get_reg(ctx, base);
                uint64_t addr = (sign ? (base_val + offset) : (base_val - offset));
                uint64_t imm_val = inst.reg_or_imm.src;
                uint64_t mem_val;
                memcpy(&mem_val, (uint8_t*)addr, 8);
                uint64_t res;
                switch (op) {
                    case OP_MOV:
                        memcpy((uint8_t*)addr, &imm_val, 8);
                        break;
                    case OP_ADD:
                        res = mem_val + imm_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_SUB:
                        res = mem_val - imm_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_XOR:
                        res = mem_val ^ imm_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_AND:
                        res = mem_val & imm_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_OR:
                        res = mem_val | imm_val;
                        memcpy((uint8_t*)addr, &res, 8);
                        break;
                    case OP_CMP:
                        ctx->flag = (mem_val == imm_val);
                        break;
                    default:
                        break;
                }
            }
            ctx->reg.rip = next_rip;
        }
    }
}

int main(int argc, char *argv[]) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    context_t *ctx = init_context();
    run(ctx);
    return 0;
}
