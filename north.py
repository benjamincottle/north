import sys
import subprocess
from enum import Enum, auto
import argparse
from pathlib import Path


# TODO:
# Or, And, Not, Syscalls, Load and Store differnet memory sizes, for, String Literals, character literals, etc.

Debug = 0
MEMORY_SIZE = 128000


class Builtin(Enum):
    OP_PUSH_INT = auto()    # push int ont stack
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
    OP_LSHIFT = auto()      # (x, y) -> (z) Perform a logical left shift of y bit-places on x, giving z
    OP_RSHIFT = auto()      # (x, y) -> (z) Perform a logical right shift of y bit-places on x, giving z
    OP_WHILE = auto()
    OP_DO = auto()
    OP_DONE = auto()
    OP_IF = auto()
    OP_ELSE = auto()
    OP_ENDIF = auto()


def translate_to_elf64_asm(program, output_file):
    memory_size = 0
    required_labels = program[1]
    program = program[0]
    with open(output_file, "w") as asm:
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
        for op in list(enumerate(program)):
            Builtin_Type = op[1][0]
            if ((op[0] in required_labels) or (Debug in [2, 3])):
                asm.write(".L%d:\n" % (op[0]))
            if (Debug in [2, 3]):
                asm.write("    ;; -- %s --\n" % Builtin_Type.name)

            if Builtin_Type == Builtin.OP_PUSH_INT:
                asm.write("    mov     rax, %d\n" % op[1][1])
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_PRINT:
                asm.write("    pop     rdi\n")
                asm.write("    call    print\n")
            elif Builtin_Type == Builtin.OP_ADD:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    add     rax, rbx\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_SUB:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    sub     rbx, rax\n")
                asm.write("    push    rbx\n")
            elif Builtin_Type == Builtin.OP_MUL:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    mul     rbx\n")
                asm.write("    push    rax\n")    
            elif Builtin_Type == Builtin.OP_DIV:
                asm.write("    mov     rdx, 0\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    div     rbx\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_MOD:
                asm.write("    mov     rdx, 0\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    div     rbx\n")
                asm.write("    push    rdx\n")
            elif Builtin_Type == Builtin.OP_MEM:
                asm.write("    push    mem\n")
            elif Builtin_Type == Builtin.OP_STORE8:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], bl\n")
            elif Builtin_Type == Builtin.OP_STORE16:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], bx\n")
            elif Builtin_Type == Builtin.OP_STORE32:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], ebx\n")
            elif Builtin_Type == Builtin.OP_STORE64:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], rbx\n")
            elif Builtin_Type == Builtin.OP_LOAD8:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     bl, [rax]\n")
                asm.write("    push    rbx\n")
            elif Builtin_Type == Builtin.OP_LOAD16:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     bx, [rax]\n")
                asm.write("    push    rbx\n")
            elif Builtin_Type == Builtin.OP_LOAD32:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     ebx, [rax]\n")
                asm.write("    push    rbx\n")           
            elif Builtin_Type == Builtin.OP_LOAD64:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     rbx, [rax]\n")
                asm.write("    push    rbx\n")                
            elif Builtin_Type == Builtin.OP_EXIT:
                asm.write("    mov     eax, 231\n")
                asm.write("    pop     rdi\n")
                asm.write("    syscall\n")
            elif Builtin_Type == Builtin.OP_DUP:
                asm.write("    pop     rax\n")
                asm.write("    push    rax\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_2DUP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_DROP:
                asm.write("    pop     rax\n")
            elif Builtin_Type == Builtin.OP_2DROP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
            elif Builtin_Type == Builtin.OP_OVER:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
            elif Builtin_Type == Builtin.OP_2OVER:
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
            elif Builtin_Type == Builtin.OP_SWAP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n") 
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
            elif Builtin_Type == Builtin.OP_2SWAP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rcx\n")
                asm.write("    pop     rdx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rdx\n")
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_ROT:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rcx\n")
                asm.write("    push    rbx\n") 
                asm.write("    push    rax\n") 
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_DUPNZ:
                asm.write("    pop     rax\n")
                asm.write("    push    rax\n")
                asm.write("    cmp     rax, 0\n")
                asm.write("    je      .L%d\n" % (op[0] + 1))
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_MAX:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovge  rax, rbx\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_MIN:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovle  rax, rbx\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_EQUAL:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmove   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_NOTEQUAL:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovne  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_GT:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovg   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_GE:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovge  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_LT:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovl   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_LE:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovle  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif Builtin_Type == Builtin.OP_LSHIFT:
                asm.write("    pop     rcx\n")
                asm.write("    pop     rax\n")
                asm.write("    shl     rax, cl\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_RSHIFT:
                asm.write("    pop     rcx\n")
                asm.write("    pop     rax\n")
                asm.write("    shr     rax, cl\n")
                asm.write("    push    rax\n")
            elif Builtin_Type == Builtin.OP_WHILE:
                pass
            elif Builtin_Type == Builtin.OP_DO:
                asm.write("    pop     rax\n")
                asm.write("    cmp     rax, 1\n")
                asm.write("    jl      .L%d\n" % (op[1][1]))
            elif Builtin_Type == Builtin.OP_DONE:
                asm.write("    jmp     .L%d\n" % (op[1][1]))
            elif Builtin_Type == Builtin.OP_IF:
                asm.write("    pop     rax\n")
                asm.write("    cmp     rax, 1\n")      
                asm.write("    jl      .L%d\n" % (op[1][1]))
            elif Builtin_Type == Builtin.OP_ELSE:
                asm.write("    jmp     .L%d\n" % (op[1][1]))
            elif Builtin_Type == Builtin.OP_ENDIF:
                pass        
            else:
                assert False, "Unreachable"

        asm.write(".L%d:\n" % len(program))                
        asm.write("    mov     eax, 231\n")
        asm.write("    mov     rdi, 0\n")
        asm.write("    syscall\n")
        asm.write("segment .bss\n")
        asm.write("mem: resb %d\n" % MEMORY_SIZE)


def locate_blocks(program):
    required_labels = []
    block_stack = []
    for op_loc in range(len(program)):
        Builtin_Type = program[op_loc][0]
        if (Builtin_Type == Builtin.OP_WHILE):
            block_stack.append(op_loc)
        elif (Builtin_Type == Builtin.OP_DO):
            block_stack.append(op_loc)
        elif (Builtin_Type == Builtin.OP_DONE):
            do_loc = block_stack.pop()
            while_loc = block_stack.pop()
            program[do_loc] = (program[do_loc][0], (op_loc + 1))
            required_labels.append(op_loc + 1)
            program[op_loc] = (Builtin_Type, (while_loc + 1))
            required_labels.append(while_loc + 1)
        elif (Builtin_Type == Builtin.OP_IF):
            block_stack.append(op_loc)
        elif (Builtin_Type == Builtin.OP_ELSE):
            if_loc = block_stack.pop()
            program[if_loc] = (program[if_loc][0], (op_loc + 1))
            required_labels.append(op_loc + 1)
            block_stack.append(op_loc)
        elif (Builtin_Type == Builtin.OP_ENDIF):
            if_or_else_loc = block_stack.pop()
            program[if_or_else_loc] = (program[if_or_else_loc][0], (op_loc + 1))
            required_labels.append(op_loc + 1)
    if Debug == 3:
        print("requried_labels:", required_labels, "\n")
    return (program, required_labels)


def parse_tokens(tokens):
    program = []
    for token in tokens:
        if token[1] == "print":
            program.append((Builtin.OP_PRINT, ))
        elif token[1] == "+":
            program.append((Builtin.OP_ADD, ))
        elif token[1] == "-":
            program.append((Builtin.OP_SUB, ))
        elif token[1] == "*":
            program.append((Builtin.OP_MUL, ))
        elif token[1] == "/":
            program.append((Builtin.OP_DIV, ))
        elif token[1] == "%":
            program.append((Builtin.OP_MOD, ))
        elif token[1] == "mem":
            program.append((Builtin.OP_MEM, ))
        elif token[1] == "store8":
            program.append((Builtin.OP_STORE8, ))
        elif token[1] == "store16":
            program.append((Builtin.OP_STORE16, ))
        elif token[1] == "store32":
            program.append((Builtin.OP_STORE32, ))
        elif token[1] == "store64":
            program.append((Builtin.OP_STORE64, ))
        elif token[1] == "load8":
            program.append((Builtin.OP_LOAD8, ))
        elif token[1] == "load16":
            program.append((Builtin.OP_LOAD16, ))
        elif token[1] == "load32":
            program.append((Builtin.OP_LOAD32, ))
        elif token[1] == "load64":
            program.append((Builtin.OP_LOAD64, ))
        elif token[1] == "exit":
            program.append((Builtin.OP_EXIT, ))            
        elif token[1] == "dup":
            program.append((Builtin.OP_DUP, ))   
        elif token[1] == "2dup":
            program.append((Builtin.OP_2DUP, ))
        elif token[1] == "drop":
            program.append((Builtin.OP_DROP, ))
        elif token[1] == "2drop":
            program.append((Builtin.OP_2DROP, ))
        elif token[1] == "over":
            program.append((Builtin.OP_OVER, ))
        elif token[1] == "2over":
            program.append((Builtin.OP_2OVER, ))
        elif token[1] == "swap":
            program.append((Builtin.OP_SWAP, ))
        elif token[1] == "2swap":
            program.append((Builtin.OP_2SWAP, ))
        elif token[1] == "rot":
            program.append((Builtin.OP_ROT, ))
        elif token[1] == "dupnz":
            program.append((Builtin.OP_DUPNZ, ))
        elif token[1] == "max":
            program.append((Builtin.OP_MAX, ))
        elif token[1] == "min":
            program.append((Builtin.OP_MIN, ))
        elif token[1] == "==":
            program.append((Builtin.OP_EQUAL, ))
        elif token[1] == "!=":
            program.append((Builtin.OP_NOTEQUAL, ))
        elif token[1] == ">":
            program.append((Builtin.OP_GT, ))
        elif token[1] == ">=":
            program.append((Builtin.OP_GE, ))
        elif token[1] == "<":
            program.append((Builtin.OP_LT, ))
        elif token[1] == "<=":
            program.append((Builtin.OP_LE, ))
        elif token[1] == "<<":
            program.append((Builtin.OP_LSHIFT, ))
        elif token[1] == ">>":
            program.append((Builtin.OP_RSHIFT, ))
        elif token[1] == "while":
            program.append((Builtin.OP_WHILE, ))
        elif token[1] == "do":
            program.append((Builtin.OP_DO, ))
        elif token[1] == "done":
            program.append((Builtin.OP_DONE, ))
        elif token[1] == "if":
            program.append((Builtin.OP_IF, ))
        elif token[1] == "else":
            program.append((Builtin.OP_ELSE, ))
        elif token[1] == "endif":
            program.append((Builtin.OP_ENDIF, ))
        else:
            try:
                program.append((Builtin.OP_PUSH_INT, int(token[1])))
            except ValueError as e:
                with open(token[0][0], "r") as source_file:
                    print(''.join([line for col, line in enumerate(source_file) if col == token[0][1]]), end='')
                    print(" "*token[0][2] + "^")
                print("%s:%d:%d: %s" % (token[0][0], token[0][1], token[0][2], e))
                exit(1)
    if Debug == 3:
        print("program:", program, "\n")
    return program


def load_tokens(file_path):
    tokens = []
    token = ""
    with open(file_path, "r") as source_file:
        for line in list(enumerate(source_file)):
            line = (line[0], line[1].split(";", 1)[0])   # single line comment handling
            line_loc = line[0]
            for column in list(enumerate(line[1])):
                if (not (column[1].isspace())):
                    if (token == ""):
                        column_loc = column[0]
                    token += column[1]
                    if (column[0] == (len(line[1]) - 1)):  # no newline at end of file
                        if (not (token == "")):
                            tokens.append( ((source_file.name, line_loc, column_loc), token) )
                        token = ""                        
                else:
                    if (not (token == "")):
                        tokens.append( ((source_file.name, line_loc, column_loc), token) )
                    token = ""
    if Debug == 3:
        print("tokens:", tokens, "\n")    
    return tokens


def run_cmd(cmd):
    if Debug in [1, 2, 3]:
        print(cmd)
    subprocess.call(cmd)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(add_help=False, description='north.py is a compiler for the north programming language. north is a concatenative, stack based language inspired by forth. Target for compilation is x86-64 Linux. Output is a statically linked ELF 64-bit LSB executable.')
    arg_parser.add_argument('-h', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')
    arg_parser.add_argument("-g", required=False, default=False, action="store_true", help="Generate an executable containing debug symbols.")
    arg_parser.add_argument("-D", choices=[1, 2, 3], required=False, type=int, default=0, help="Use compliation debug mode.")
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
    program = locate_blocks(parse_tokens(tokens))
    translate_to_elf64_asm(program, asm_file)
    run_cmd(nasm_command)
    run_cmd(ld_command)
    
    if not Debug == 3:
        run_cmd(cleanup_command)

    if exec_output:
        run_cmd(["./" + output_file])
