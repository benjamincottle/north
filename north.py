#!/usr/bin/env python3

import sys
import subprocess
from enum import Enum, auto
import argparse
from pathlib import Path


Debug = 0
MEMORY_SIZE = 128000



class Builtin(Enum):
    OP_PUSH_INT = auto()    # push int onto stack
    OP_PUSH_STR = auto()    # push str_size and &str onto stack
    OP_PRINT = auto()       # pop stack and print to `stdout` (via itoa() + write syscall) 
    OP_ADD = auto()         # add: (x, y) -> (x + y)
    OP_SUB = auto()         # subtract: (x, y) -> (x - y)
    OP_MUL = auto()         # multiply: (x, y) -> (x * y)
    OP_DIV = auto()         # divide: (x, y) -> ( x / y)
    OP_MOD = auto()         # modulus: (x, y) -> (x % y)
    OP_MEM = auto()         # push memory base address to stack
    OP_STORE8 = auto()      # pop top two items from stack, store data in stack[0] at mem[stack[1]]
    OP_STORE16 = auto()     # 
    OP_STORE32 = auto()     # 
    OP_STORE64 = auto()     # 
    OP_LOAD8 = auto()       # pop stack, load data at mem[stack[0]] back to stack
    OP_LOAD16 = auto()      #
    OP_LOAD32 = auto()      #
    OP_LOAD64 = auto()      #
    OP_EXIT = auto()        # pop stack, exit program with exit code stack[0]
    OP_DUP = auto()         # duplicate the top item on the stack (x) -> (x, x)
    OP_2DUP = auto()        # duplicate the top two items on the stack (x, y) -> (x, y, x, y)
    OP_DROP = auto()        # pop the top item from the stack
    OP_2DROP = auto()       # pop the top two item from the stack
    OP_OVER = auto()        # stack ops: (x, y) -> (x, y, x) 
    OP_2OVER = auto()       # stack ops: (w, x, y, z) -> (w, x, y, z, w, x)
    OP_SWAP = auto()        # stack ops: (x, y) -> (y, x)
    OP_2SWAP = auto()       # stack ops: (w, x, y, z) -> (y, z, w, x)
    OP_ROT = auto()         # (x, y, z) -> (y, z, x)  Rotate the top three stack entries.   
    OP_DUPNZ = auto()       # (x, 0) -> (x, 0) but (x, y) -> (x, y, y)
    OP_MAX = auto()         # (1, 2) -> (2) pop two items, return max
    OP_MIN = auto()         # (1, 2) -> (1) pop two items, return min
    OP_EQUAL = auto()       # (x, x) -> (1) and (x, y) -> (0) pop two items, push 1 if equal, otherwise 0
    OP_NOTEQUAL = auto()    # (x, x) -> (0) and (x, y) -> (1) pop two items, push 0 if equal, otherwise 1
    OP_GT = auto()          # (1, 2) -> (0) and (2, 1) -> (1) pop two items, push 1 if greater, otherwise 0
    OP_GE = auto()          # (1, 2) -> (0) and (2, 1) -> (1) and (1, 1) -> (1) pop two items, push 1 if gte otherwise 0
    OP_LT = auto()          # (1, 2) -> (1) and (2, 1) -> (0) pop two items, push 1 if less, otherwise 0
    OP_LE = auto()          # (1, 2) -> (1) and (2, 1) -> (0) and (1, 1) -> (1) pop two items, push 1 if lte, otherwise 0
    OP_LOGICAL_AND = auto() # 
    OP_LOGICAL_OR = auto()  # 
    OP_LOGICAL_NOT = auto() # 
    OP_LSHIFT = auto()      # (x, y) -> (z) Perform a logical left shift of y bit-places on x, giving z
    OP_RSHIFT = auto()      # (x, y) -> (z) Perform a logical right shift of y bit-places on x, giving z
    OP_BITWISE_AND = auto()
    OP_BITWISE_OR = auto()
    OP_BITWISE_NOT = auto()
    OP_XOR = auto()
    OP_WHILE = auto()
    OP_DO = auto()
    OP_DONE = auto()
    OP_IF = auto()
    OP_ELSE = auto()
    OP_ENDIF = auto()
    OP_SYSCALL = auto()


op_readable = {
    "OP_PRINT": "print",
    "OP_ADD": "+",
    "OP_SUB": "-",
    "OP_MUL": "*",
    "OP_DIV": "/",
    "OP_MOD": "%",
    "OP_MEM": "mem",
    "OP_STORE8": "store8",
    "OP_STORE16": "store16",
    "OP_STORE32": "store32",
    "OP_STORE64": "store64",
    "OP_LOAD8": "load8",
    "OP_LOAD16": "load16",
    "OP_LOAD32": "load32",
    "OP_LOAD64": "load64",
    "OP_EXIT": "exit",
    "OP_DUP": "dup",
    "OP_2DUP": "2dup",
    "OP_DROP": "drop",
    "OP_2DROP": "2drop",
    "OP_OVER": "over",
    "OP_2OVER": "2over",
    "OP_SWAP": "swap",
    "OP_2SWAP": "2swap",
    "OP_ROT": "rot",
    "OP_DUPNZ": "dupnz",
    "OP_MAX": "max",
    "OP_MIN": "min",
    "OP_EQUAL": "==",
    "OP_NOTEQUAL": "!=",
    "OP_GT": ">",
    "OP_GE": "<=",
    "OP_LT": "<",
    "OP_LE": "<=",
    "OP_LOGICAL_AND": "and",
    "OP_LOGICAL_OR": "or",
    "OP_LOGICAL_NOT": "not",
    "OP_BITWISE_AND": "&",
    "OP_BITWISE_OR": "|",
    "OP_BITWISE_NOT": "~",
    "OP_XOR": "^",
    "OP_LSHIFT": "<<",
    "OP_RSHIFT": ">>",
    "OP_WHILE": "while",
    "OP_DO": "do",
    "OP_DONE": "done",
    "OP_IF": "if",
    "OP_ELSE": "else",
    "OP_ENDIF": "endif",
    "OP_SYSCALL": "syscall",
}


def print_compilation_error(token, error_msg):   # (token_loc, token_type, token_value), "string"
    token_loc = token[0]
    with open(token_loc[0], "r") as input_file:
        input_line = ("".join([line for col, line in enumerate(input_file) if col == token_loc[1]]))
        if input_line[-1:] != "\n":
            input_line += "\n"
        print(input_line, end="")
        print(" "*token_loc[2] + "^")
        print("%s:%d:%d: %s" % (token_loc[0], token_loc[1], token_loc[2], error_msg))


def translate_to_elf64_asm(program, required_labels, output_file): # program = [ ... , (token_loc, token_type, token_value), ... ]
    with open(output_file, "w") as asm:
        ro_data = []
        asm.write("BITS 64\n")
        asm.write("segment .text\n")
        asm.write("print:\n")
        asm.write("    mov     r9, -3689348814741910323\n")
        asm.write("    sub     rsp, 40\n")
        asm.write("    mov     BYTE [rsp+31], 10\n")
        asm.write("    lea     rcx, [rsp+30]\n")
        asm.write(".L00:\n")
        asm.write("    mov     rax, rdi\n")
        asm.write("    lea     r8, [rsp+32]\n")
        asm.write("    mul     r9\n")
        asm.write("    mov     rax, rdi\n")
        asm.write("    sub     r8, rcx\n")
        asm.write("    shr     rdx, 3\n")
        asm.write("    lea     rsi, [rdx+rdx*4]\n")
        asm.write("    add     rsi, rsi\n")
        asm.write("    sub     rax, rsi\n")
        asm.write("    add     eax, 48\n")
        asm.write("    mov     BYTE [rcx], al\n")
        asm.write("    mov     rax, rdi\n")
        asm.write("    mov     rdi, rdx\n")
        asm.write("    mov     rdx, rcx\n")
        asm.write("    sub     rcx, 1\n")
        asm.write("    cmp     rax, 9\n")
        asm.write("    ja      .L00\n")
        asm.write("    lea     rax, [rsp+32]\n")
        asm.write("    mov     edi, 1\n")
        asm.write("    sub     rdx, rax\n")
        asm.write("    xor     eax, eax\n")
        asm.write("    lea     rsi, [rsp+32+rdx]\n")
        asm.write("    mov     rdx, r8\n")
        asm.write("    mov     rax, 1\n")
        asm.write("    syscall\n")
        asm.write("    add     rsp, 40\n")
        asm.write("    ret\n")
        asm.write("global _start\n")
        asm.write("_start:\n")
        for op in list(enumerate(program)): # op = ([ ... , ( index, (token_loc, token_label_req, token_type, token_value) ), ... ]
            token_type = op[1][1]
            if ((op[0] in required_labels) or (Debug in [2, 3])):
                asm.write(".L%d:\n" % (op[0]))
            if (Debug in [2, 3]):
                asm.write("    ;; -- %s --\n" % token_type.name)

            if token_type == Builtin.OP_PUSH_INT:
                asm.write("    mov     rax, %d\n" % op[1][2])
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_PRINT:
                asm.write("    pop     rdi\n")
                asm.write("    call    print\n")
            elif token_type == Builtin.OP_ADD:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    add     rax, rbx\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_SUB:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    sub     rbx, rax\n")
                asm.write("    push    rbx\n")
            elif token_type == Builtin.OP_MUL:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    mul     rbx\n")
                asm.write("    push    rax\n")
            # TODO: DIV can be optimised to MUL (https://repnz.github.io/posts/reversing-optimizations-division/)
            elif token_type == Builtin.OP_DIV:
                asm.write("    mov     rdx, 0\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    div     rbx\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_MOD:
                asm.write("    mov     rdx, 0\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    div     rbx\n")
                asm.write("    push    rdx\n")
            elif token_type == Builtin.OP_MEM:
                asm.write("    push    mem\n")
            elif token_type == Builtin.OP_STORE8:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], bl\n")
            elif token_type == Builtin.OP_STORE16:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], bx\n")
            elif token_type == Builtin.OP_STORE32:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], ebx\n")
            elif token_type == Builtin.OP_STORE64:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], rbx\n")
            elif token_type == Builtin.OP_LOAD8:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     bl, [rax]\n")
                asm.write("    push    rbx\n")
            elif token_type == Builtin.OP_LOAD16:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     bx, [rax]\n")
                asm.write("    push    rbx\n")
            elif token_type == Builtin.OP_LOAD32:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     ebx, [rax]\n")
                asm.write("    push    rbx\n")           
            elif token_type == Builtin.OP_LOAD64:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     rbx, [rax]\n")
                asm.write("    push    rbx\n")                
            elif token_type == Builtin.OP_EXIT:
                asm.write("    mov     eax, 231\n")
                asm.write("    pop     rdi\n")
                asm.write("    syscall\n")
            elif token_type == Builtin.OP_DUP:
                asm.write("    pop     rax\n")
                asm.write("    push    rax\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_2DUP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_DROP:
                asm.write("    pop     rax\n")
            elif token_type == Builtin.OP_2DROP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
            elif token_type == Builtin.OP_OVER:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
            elif token_type == Builtin.OP_2OVER:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n") 
                asm.write("    pop     rcx\n")
                asm.write("    pop     rdx\n")
                asm.write("    push    rdx\n")
                asm.write("    push    rcx\n")
                asm.write("    push    rbx\n") 
                asm.write("    push    rax\n") 
                asm.write("    push    rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_SWAP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n") 
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
            elif token_type == Builtin.OP_2SWAP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rcx\n")
                asm.write("    pop     rdx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_ROT:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rcx\n")
                asm.write("    push    rbx\n") 
                asm.write("    push    rax\n") 
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_DUPNZ:
                asm.write("    pop     rax\n")
                asm.write("    push    rax\n")
                asm.write("    cmp     rax, 0\n")
                asm.write("    je      .L%d\n" % (op[0] + 1))
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_MAX:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovge  rax, rbx\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_MIN:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovle  rax, rbx\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_EQUAL:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmove   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_NOTEQUAL:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovne  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_GT:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovg   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_GE:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovge  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_LT:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovl   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_LE:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovle  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_LOGICAL_AND:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    mul     rbx\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_LOGICAL_OR:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    add     rax, rbx\n")                
                asm.write("    cmp     rax, 0\n")
                asm.write("    cmovne  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_LOGICAL_NOT:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    cmp     rax, 0\n")
                asm.write("    cmove  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif token_type == Builtin.OP_LSHIFT:
                asm.write("    pop     rcx\n")
                asm.write("    pop     rax\n")
                asm.write("    shl     rax, cl\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_RSHIFT:
                asm.write("    pop     rcx\n")
                asm.write("    pop     rax\n")
                asm.write("    shr     rax, cl\n")
                asm.write("    push    rax\n")
            elif token_type == Builtin.OP_BITWISE_AND:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    and     rax, rbx\n")
                asm.write("    push    rax\n")                
            elif token_type == Builtin.OP_BITWISE_OR:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    or     rax, rbx\n")
                asm.write("    push    rax\n")   
            elif token_type == Builtin.OP_BITWISE_NOT:
                asm.write("    pop     rax\n")
                asm.write("    not     rax\n")
                asm.write("    push    rax\n")   
            elif token_type == Builtin.OP_XOR:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    xor     rax, rbx\n")
                asm.write("    push    rax\n")
            # Note: for condition checking in `do` and `if`, and for logical comparisons, 
            # 0 is considered False, and not 0 is considered True
            elif token_type == Builtin.OP_WHILE:
                pass
            elif token_type == Builtin.OP_DO:
                asm.write("    pop     rax\n")
                asm.write("    cmp     rax, 0\n")
                asm.write("    je      .L%d\n" % (op[1][2]))
            elif token_type == Builtin.OP_DONE:
                asm.write("    jmp     .L%d\n" % (op[1][2]))
            elif token_type == Builtin.OP_IF:
                asm.write("    pop     rax\n")
                asm.write("    cmp     rax, 0\n")      
                asm.write("    je      .L%d\n" % (op[1][2]))
            elif token_type == Builtin.OP_ELSE:
                asm.write("    jmp     .L%d\n" % (op[1][2]))
            elif token_type == Builtin.OP_ENDIF:
                pass        
            elif token_type == Builtin.OP_SYSCALL:
                # TODO: Support all syscalls
                # These are Linux syscalls that utilise arg0 (%rdi)	arg1 (%rsi)	arg2 (%rdx)
                if op[1][2] in [0, 1, 2, 7, 8, 10, 16, 19, 20, 26, 27, 28, 29, 30, 31, 38, 41, 42, 43, 46, 47, 49, 51, 52, 59, 64, 65, 71, 72, 78, 89, 92, 93, 94, 103, 117, 118, 119, 120, 129, 133, 139, 141, 144, 173, 175, 187, 194, 195, 196, 203, 204, 209, 210, 212, 217, 222, 234, 238, 245, 251, 254, 258, 261, 263, 266, 268, 269, 274, 282, 292, 304, 309, 313, 314, 317, 318, 321, 324, 325]:
                    asm.write("    pop     rax\n")
                    asm.write("    pop     rdi\n")
                    asm.write("    pop     rsi\n")
                    asm.write("    pop     rdx\n")
                    asm.write("    syscall\n")
                    asm.write("    push     rax\n")
                # These are Linux syscalls that utilise arg0 (%rdi)
                elif op[1][2] in [3, 12, 22, 32, 37, 60, 63, 67, 74, 75, 80, 81, 84, 87, 95, 99, 100, 105, 106, 121, 122, 123, 124, 134, 135, 145, 146, 147, 151, 159, 161, 163, 168, 201, 207, 213, 218, 225, 226, 231, 241, 272, 284, 291, 294, 306, 323, 331]:
                    asm.write("    pop     rax\n")
                    asm.write("    pop     rdi\n")
                    asm.write("    syscall\n")
                    asm.write("    push     rax\n")
                else:
                    try:
                        raise NotImplementedError()
                    except NotImplementedError as e:
                        print_compilation_error(program[op[0] - 1], "ERROR `%d syscall` is not implemented" % (op[1][2]))
                        exit(1)

            elif token_type == Builtin.OP_PUSH_STR:
                if (not (op[1][2]) in ro_data):
                    ro_data.append(op[1][2])
                asm.write("    push    %s\n" % ("str" + str(ro_data.index(op[1][2])) + "_len"))
                asm.write("    push    %s\n" % ("str" + str(ro_data.index(op[1][2]))))

            else:
                assert False, "Unreachable"

        asm.write(".L%d:\n" % len(program))         # implicit exit       
        asm.write("    mov     eax, 231\n")
        asm.write("    mov     rdi, 0\n")
        asm.write("    syscall\n")

        asm.write("section .rodata\n")              # .ro_data section
        for string in list(enumerate(ro_data)):
            str_label = "str%d" % (string[0])
            str_data = "`" + string[1][1:-1] + "`"    # nasm: Strings enclosed in backquotes support C-style -escapes for special characters.
            asm.write("    " + str_label + ": db " + str_data + "\n")
            asm.write("    " + str_label + "_len: equ $ - " + str_label + "\n")
        asm.write("segment .bss\n")                 # .bss section
        asm.write("    mem: resb %d\n" % MEMORY_SIZE)


def locate_blocks(program): # [ ... ,(token_loc, token_type, token_value), ... ]
    block_stack = []
    required_labels = []
    for op_label in range(len(program)):
        token_loc = program[op_label][0]
        token_type = program[op_label][1]
        if (token_type == Builtin.OP_WHILE):
            block_stack.append(op_label)
        elif (token_type == Builtin.OP_DO):
            block_stack.append(op_label)
        elif (token_type == Builtin.OP_DONE):
            try:
                do_loc = block_stack.pop()
            except IndexError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)
            try:
                assert program[do_loc][1] == Builtin.OP_DO
            except AssertionError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)
            try:
                while_loc = block_stack.pop()
            except IndexError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)
            try:
                assert program[while_loc][1] == Builtin.OP_WHILE 
            except AssertionError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)
            program[do_loc] = (program[do_loc][0], program[do_loc][1], (op_label + 1)) # do has the the (done + 1)  op's # as val
            required_labels.append(op_label + 1)
            program[op_label] = (token_loc, token_type, (while_loc + 1)) # done has the while + 1 op's # as val
            required_labels.append(while_loc + 1)
        elif (token_type == Builtin.OP_IF):
            block_stack.append(op_label)
        elif (token_type == Builtin.OP_ELSE):
            try:
                if_loc = block_stack.pop()
            except IndexError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)
            try:
                assert program[if_loc][1] == Builtin.OP_IF 
            except AssertionError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)
            program[if_loc] = (program[if_loc][0], program[if_loc][1], (op_label + 1)) # if has (else + 1) op's # as val
            required_labels.append(op_label + 1)
            block_stack.append(op_label)
        elif (token_type == Builtin.OP_ENDIF):
            try:
                if_or_else_loc = block_stack.pop()
            except IndexError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)
            try:
                assert (program[if_or_else_loc][1] == Builtin.OP_IF) or (program[if_or_else_loc][1] == Builtin.OP_ELSE), "`endif` missing matching `if` or `else` block"
            except AssertionError as e:
                print_compilation_error(program[op_label], "ERROR unmatched token `%s`" % op_readable[token_type.name])
                exit(1)

            program[if_or_else_loc] = (program[if_or_else_loc][0], program[if_or_else_loc][1], (op_label + 1)) # if/else has (endif + 1) op's # as val
            required_labels.append(op_label + 1)
        # TODO: should check that `program[op_label - 1][2]` is a supported syscall number
        #       not just a valid integer that exists in the token_value
        elif (token_type == Builtin.OP_SYSCALL):
            try:
                int(program[op_label - 1][2])    #TODO: better check for if valid syscall
            except (IndexError, ValueError) as e:
                print_compilation_error(program[op_label - 1], "ERROR invalid syscall number `%s`" % op_readable[program[op_label - 1][1].name])
                exit(1)
            program[op_label] = (token_loc, token_type, program[op_label - 1][2]) # syscall has (syscall - 1) op's value as value (syscall number)
        elif (token_type == Builtin.OP_DUPNZ):
            required_labels.append(op_label + 1)
    try:
        assert block_stack == []  # block_stack is a list of indexes of left over tokens
    except AssertionError as e:
        left_over_token = program[block_stack.pop()]
        token_type = left_over_token[1]
        print_compilation_error(left_over_token, "ERROR unmatched token `%s`" % op_readable[token_type.name])
        exit(1)

    if Debug == 3:
        print("program_2:", program, "\n")
    return program, required_labels


def parse_tokens(tokens): # tokens = [ ... , (token_loc, token), ... ]
    program = []
    for token in tokens:
        token_loc = token[0] 
        token_value = token[1] 
        if token_value == "print":
            program.append((token_loc, Builtin.OP_PRINT))
        elif token_value == "+":
            program.append((token_loc, Builtin.OP_ADD))
        elif token_value == "-":
            program.append((token_loc, Builtin.OP_SUB))
        elif token_value == "*":
            program.append((token_loc, Builtin.OP_MUL))
        elif token_value == "/":
            program.append((token_loc, Builtin.OP_DIV))
        elif token_value == "%":
            program.append((token_loc, Builtin.OP_MOD))
        elif token_value == "mem":
            program.append((token_loc, Builtin.OP_MEM))
        elif token_value == "store8":
            program.append((token_loc, Builtin.OP_STORE8))
        elif token_value == "store16":
            program.append((token_loc, Builtin.OP_STORE16))
        elif token_value == "store32":
            program.append((token_loc, Builtin.OP_STORE32))
        elif token_value == "store64":
            program.append((token_loc, Builtin.OP_STORE64))
        elif token_value == "load8":
            program.append((token_loc, Builtin.OP_LOAD8))
        elif token_value == "load16":
            program.append((token_loc, Builtin.OP_LOAD16))
        elif token_value == "load32":
            program.append((token_loc, Builtin.OP_LOAD32))
        elif token_value == "load64":
            program.append((token_loc, Builtin.OP_LOAD64))
        elif token_value == "exit":
            program.append((token_loc, Builtin.OP_EXIT))
        elif token_value == "dup":
            program.append((token_loc, Builtin.OP_DUP))
        elif token_value == "2dup":
            program.append((token_loc, Builtin.OP_2DUP))
        elif token_value == "drop":
            program.append((token_loc, Builtin.OP_DROP))
        elif token_value == "2drop":
            program.append((token_loc, Builtin.OP_2DROP))
        elif token_value == "over":
            program.append((token_loc, Builtin.OP_OVER))
        elif token_value == "2over":
            program.append((token_loc, Builtin.OP_2OVER))
        elif token_value == "swap":
            program.append((token_loc, Builtin.OP_SWAP))
        elif token_value == "2swap":
            program.append((token_loc, Builtin.OP_2SWAP))
        elif token_value == "rot":
            program.append((token_loc, Builtin.OP_ROT))
        elif token_value == "dupnz":
            program.append((token_loc, Builtin.OP_DUPNZ))
        elif token_value == "max":
            program.append((token_loc, Builtin.OP_MAX))
        elif token_value == "min":
            program.append((token_loc, Builtin.OP_MIN))
        elif token_value == "==":
            program.append((token_loc, Builtin.OP_EQUAL))
        elif token_value == "!=":
            program.append((token_loc, Builtin.OP_NOTEQUAL))
        elif token_value == ">":
            program.append((token_loc, Builtin.OP_GT))
        elif token_value == ">=":
            program.append((token_loc, Builtin.OP_GE))
        elif token_value == "<":
            program.append((token_loc, Builtin.OP_LT))
        elif token_value == "<=":
            program.append((token_loc, Builtin.OP_LE))
        elif ((token_value == "and") or (token_value == "&&")):
            program.append((token_loc, Builtin.OP_LOGICAL_AND))
        elif ((token_value == "or") or (token_value == "||")):
            program.append((token_loc, Builtin.OP_LOGICAL_OR))
        elif ((token_value == "not") or (token_value == "!")):
            program.append((token_loc, Builtin.OP_LOGICAL_NOT))
        elif token_value == "<<":
            program.append((token_loc, Builtin.OP_LSHIFT))
        elif token_value == ">>":
            program.append((token_loc, Builtin.OP_RSHIFT))
        elif token_value == "&":
            program.append((token_loc, Builtin.OP_BITWISE_AND))            
        elif token_value == "|":
            program.append((token_loc, Builtin.OP_BITWISE_OR))            
        elif token_value == "~":
            program.append((token_loc, Builtin.OP_BITWISE_NOT))            
        elif token_value == "^":
            program.append((token_loc, Builtin.OP_XOR)) 
        elif token_value == "while":
            program.append((token_loc, Builtin.OP_WHILE))
        elif token_value == "do":
            program.append((token_loc, Builtin.OP_DO))
        elif token_value == "done":
            program.append((token_loc, Builtin.OP_DONE))
        elif token_value == "if":
            program.append((token_loc, Builtin.OP_IF))
        elif token_value == "else":
            program.append((token_loc, Builtin.OP_ELSE))
        elif token_value == "endif":
            program.append((token_loc, Builtin.OP_ENDIF))
        elif token_value == "syscall":
            program.append((token_loc, Builtin.OP_SYSCALL))
        elif token_value[0] == "\"":
            program.append((token_loc, Builtin.OP_PUSH_STR, token_value))
        elif token_value[0] == "\'":
            program.append((token_loc, Builtin.OP_PUSH_INT, ord(bytes(token_value[1:-1], "utf-8").decode("unicode-escape"))))
        else:
            try:
                program.append((token_loc, Builtin.OP_PUSH_INT, int(token_value)))
            except ValueError as e:
                print_compilation_error(token, "ERROR invalid token `%s`" % token_value)
                exit(1)
    if Debug == 3:
        print("program_1:", program, "\n")

    return program


def load_tokens(file_path):
    tokens = []
    with open(file_path, "r", encoding="utf-8") as input_file:  
        for line in list(enumerate(input_file)): # (..., (0, ('./tests/character_literals.north', 0, 0), (1, ('"\\n"')) ), ...)
            token = ""
            end_mark = ""
            line_loc = 0
            column_loc = 0
            line = (line[0], line[1].split(";", 1)[0] + "\n")    # single line comment handling
            line_loc = line[0]
            for column in list(enumerate(line[1])):# (..., (0, ('\n')), ...)
                if (token == ""):                    # Looking for beginning of the next token
                    if ((column[1] == "\"") or (column[1] == "\'") or (not column[1].isspace())):  # this is the start of a string/character literal token_end = ´"´ or ´'´
                        column_loc = column[0]
                        token += column[1]                       
                        if ((column[1] == "\"") or (column[1] == "\'")):
                            end_mark = column[1]
                        if (not (column[0] == 0)):  # not the beginning of the line
                            try:
                                assert (line[1][column[0] - 1] == " ") # the previous char must be space, i.e. "abc""def" and 'a''b' not supported
                            except AssertionError as e:
                                token_type = "string" if (end_mark == "\"") else "character"
                                print_compilation_error((((input_file.name, line_loc, column_loc), token)), "ERROR tokens should be separated by whitespace")
                                exit(1)

                else:                                # We're building a token, find the end
                    if ((column[0] == len(line[1]) - 1) and ((token.count("\"") == 1) or (token.count("\'") == 1))):  # end of line and there's only one ´"´ or ´'´ in the token
                        try:
                            assert (end_mark == "")
                        except AssertionError as e:
                            if (token[-1:] == "\n"):
                                token = token[:-1]
                            token_type = "string" if (end_mark == "\"") else "character"
                            print_compilation_error((((input_file.name, line_loc, column_loc), token)), "ERROR invalid %s literal `%s`" % (token_type, token))
                            exit(1)
                    elif (((column[1] == "\n") or (column[1] == " "))  and  (not end_mark == "")):  # newline and space inside of string literal should be added to string and character literals
                        token += column[1] 
                    elif ((column[1] == "\"")  and  (end_mark == "\"")):  # this is the closing mark of a string literal
                        token += column[1] 
                        tokens.append(((input_file.name, line_loc, column_loc), token))
                        token = ""
                        end_mark = ""
                    elif (column[1] == "\'") and (end_mark == "\'"):  # this is the end_mark of a character literal
                        token += column[1]
                        if (len(token) == 2):
                            token = "0"
                        try:
                            assert len(bytes(token, "utf-8").decode("unicode-escape")) <= 3
                        except AssertionError as e:
                            print_compilation_error((((input_file.name, line_loc, column_loc), token)), "ERROR invalid character literal `%s`" % token)
                            exit(1)

                        tokens.append(((input_file.name, line_loc, column_loc), token))
                        token = ""
                        end_mark = ""
                    elif ((column[1].isspace()) or (column[0] == len(line[1]) - 1)):  # this is the end_mark of number or a word, end = space or newline or last position in the line
                        tokens.append( ((input_file.name, line_loc, column_loc), token) )
                        token = ""
                    else:        # continue building token
                        token += column[1]

    if Debug == 3:
        print("tokens:", tokens, "\n")
    
    if tokens == []:
        print_compilation_error(((file_path, line_loc, column_loc), None), "ERROR no tokens found")
        exit(1)

    return tokens   # tokens = [ ... , (token_loc, token), ... ]        


def run_cmd(cmd):
    if Debug in [1, 2, 3]:
        print(cmd)
    subprocess.call(cmd)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(add_help=False, description="north.py is a compiler for the north programming language. north is a concatenative, stack based language inspired by forth. Target for compilation is x86-64 Linux. Output is a statically linked ELF 64-bit LSB executable.")
    arg_parser.add_argument("-h", action="help", default=argparse.SUPPRESS, help="Show this help message and exit.")
    arg_parser.add_argument("-g", required=False, default=False, action="store_true", help="Generate an executable containing debug symbols.")
    arg_parser.add_argument("-D", choices=[1, 2, 3], required=False, type=int, default=0, help="Use compliation debug mode with increasing verbosity.")
    arg_parser.add_argument("-o", dest="output_file", required=False, type=str, help="Provide an alternative filename for the generated executable.")
    arg_parser.add_argument("-r", dest="exec_output", required=False, default=False, action="store_true", help="Additionally execute output on successful compilation.")
    arg_parser.add_argument("input_file", type=str, help="path to the input_file.")
    args = arg_parser.parse_args()

    input_file = args.input_file
    asm_file = Path(input_file).stem + ".asm"
    o_file = Path(input_file).stem + ".o"
    output_file = Path(input_file).stem

    if (not args.output_file == None):
        asm_file = args.output_file + ".asm"
        o_file = args.output_file + ".o"
        output_file = args.output_file

    Debug = args.D
    exec_output = args.exec_output

    nasm_command = ["nasm", "-g", "-felf64", asm_file]
    ld_command = ["ld", "-o", output_file, o_file]
    cleanup_command = ["rm", asm_file, o_file]

    if (not args.g):
        nasm_command.remove("-g")

    if Debug in [1, 2]:
        cleanup_command.remove(asm_file)

    tokens = load_tokens(input_file)
    program, required_labels = locate_blocks(parse_tokens(tokens))
    translate_to_elf64_asm(program, required_labels, asm_file)
    run_cmd(nasm_command)
    run_cmd(ld_command)
    
    if not Debug == 3:
        run_cmd(cleanup_command)

    if exec_output:
        run_cmd(["./" + output_file])
