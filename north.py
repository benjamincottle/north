import sys
import subprocess


OP_PUSH_INT = 0     # push int ont stack
OP_PRINT = 1        # pop stack and print to `stdout` (via itoa() + write syscall) 
OP_ADD = 2          # add: (x, y) -> (x + y)
OP_SUB = 3          # subtract: (x, y) -> (x - y)
OP_MUL = 4          # multiply: (x, y) -> (x * y)
OP_DIV = 5          # divide: (x, y) -> ( x / y)
OP_MOD = 6          # modulus: (x, y) -> (x % y)
OP_MEM = 7          # push memory base address to stack
OP_STORE = 8        # pop top two items from stack, store data in stack[0] at mem[stack[1]]
OP_LOAD = 9         # pop stack, load data at mem[stack[0]] back to stack
OP_EXIT = 10        # pop stack, exit program with exit code stack[0]
OP_DUP = 11         # duplicate the top item on the stack (x) -> (x, x)
OP_2DUP = 12        # duplicate the top two items on the stack (x, y) -> (x, y, x, y)
OP_DROP = 13        # pop the top item from the stack
OP_2DROP = 14       # pop the top two item from the stack
OP_OVER = 15        # stack ops: (x, y) -> (x, y, x) 
OP_2OVER = 16       # stack ops: (w, x, y, z) -> (w, x, y, z, w, x)
OP_SWAP = 17        # stack ops: (x, y) -> (y, x)
OP_2SWAP = 18       # stack ops: (w, x, y, z) -> (y, z, w, x)
OP_ROT = 19         # (x, y, z) -> (y, z, x)  Rotate the top three stack entries.   
OP_DUPNZ = 20       # (x, 0) -> (x, 0) but (x, y) -> (x, y, y)
OP_MAX = 21         # (1, 2) -> (2) pop two items, return max
OP_MIN = 22         # (1, 2) -> (1) pop two items, return min
OP_EQUAL = 23       # (x, x) -> (1) and (x, y) -> (0) pop two items, push 1 if equal, otherwise 0
OP_NOTEQUAL = 24    # (x, x) -> (0) and (x, y) -> (1) pop two items, push 0 if equal, otherwise 1
OP_GT = 25          # (1, 2) -> (0) and (2, 1) -> (1) pop two items, push 1 if greater, otherwise 0
OP_GE = 26          # (1, 2) -> (0) and (2, 1) -> (1) and (1, 1) -> (1) pop two items, push 1 if gte otherwise 0
OP_LT = 27          # (1, 2) -> (1) and (2, 1) -> (0) pop two items, push 1 if less, otherwise 0
OP_LE = 28          # (1, 2) -> (1) and (2, 1) -> (0) and (1, 1) -> (1) pop two items, push 1 if lte, otherwise 0
OP_WHILE = 29
OP_DO = 30
OP_DONE = 31
OP_LSHIFT = 32      # (x, y) -> (z) Perform a logical left shift of y bit-places on x, giving z
OP_RSHIFT = 33      # (x, y) -> (z) Perform a logical right shift of y bit-places on x, giving z
OP_IF = 34
OP_ELSE = 35
OP_ENDIF = 36

# TODO:
# Or, And, Not, Syscalls, Load and Store differnet memory sizes, for, String Literals, character literals, etc.

Debug = False
MEMORY_SIZE = 128000


def translate_program_to_elf64_asm(program, output_file):
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
            if ((op[0] in required_labels) or (Debug)):
                asm.write(".L%d:\n" % (op[0]))
            if (Debug):
                asm.write("    ;; -- %d --\n" % op[1][0])

            if op[1][0] == OP_PUSH_INT:
                asm.write("    push     %d\n" % op[1][1])
            elif op[1][0] == OP_PRINT:
                asm.write("    pop     rdi\n")
                asm.write("    call    print\n")
            elif op[1][0] == OP_ADD:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    add     rax, rbx\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_SUB:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    sub     rbx, rax\n")
                asm.write("    push    rbx\n")
            elif op[1][0] == OP_MUL:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    mul     rbx\n")
                asm.write("    push    rax\n")    
            elif op[1][0] == OP_DIV:
                asm.write("    mov     rdx, 0\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    div     rbx\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_MOD:
                asm.write("    mov     rdx, 0\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    div     rbx\n")
                asm.write("    push    rdx\n")
            elif op[1][0] == OP_MEM:
                asm.write("    push    mem\n")
            elif op[1][0] == OP_STORE:
                asm.write("    pop     rbx\n")
                asm.write("    pop     rax\n")
                asm.write("    mov     [rax], bl\n")
            elif op[1][0] == OP_LOAD:
                asm.write("    pop     rax\n")
                asm.write("    xor     rbx, rbx\n")
                asm.write("    mov     bl, [rax]\n")
                asm.write("    push    rbx\n")
            elif op[1][0] == OP_EXIT:
                asm.write("    mov     eax, 231\n")
                asm.write("    pop     rdi\n")
                asm.write("    syscall\n")
            elif op[1][0] == OP_DUP:
                asm.write("    pop     rax\n")
                asm.write("    push    rax\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_2DUP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_DROP:
                asm.write("    pop     rax\n")
            elif op[1][0] == OP_2DROP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
            elif op[1][0] == OP_OVER:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
            elif op[1][0] == OP_2OVER:
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
            elif op[1][0] == OP_SWAP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n") 
                asm.write("    push    rax\n")
                asm.write("    push    rbx\n")
            elif op[1][0] == OP_2SWAP:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rcx\n")
                asm.write("    pop     rdx\n")
                asm.write("    push    rbx\n")
                asm.write("    push    rax\n")
                asm.write("    push    rdx\n")
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_ROT:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    pop     rcx\n")
                asm.write("    push    rbx\n") 
                asm.write("    push    rax\n") 
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_DUPNZ:
                asm.write("    pop     rax\n")
                asm.write("    push    rax\n")
                asm.write("    cmp     rax, 0\n")
                asm.write("    je      .L%d\n" % ((op[0]) + 1))
                asm.write("    push    rax\n")
            elif op[1][0] == OP_MAX:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovge  rax, rbx\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_MIN:
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovle  rax, rbx\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_EQUAL:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmove   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_NOTEQUAL:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovne  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_GT:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovg   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_GE:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovge  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_LT:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovl   rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_LE:
                asm.write("    mov     rcx, 0\n")
                asm.write("    mov     rdx, 1\n")
                asm.write("    pop     rax\n")
                asm.write("    pop     rbx\n")
                asm.write("    cmp     rbx, rax\n")
                asm.write("    cmovle  rcx, rdx\n")
                asm.write("    push    rcx\n")
            elif op[1][0] == OP_WHILE:
                pass
            elif op[1][0] == OP_DO:
                asm.write("    pop     rax\n")
                asm.write("    cmp     rax, 1\n")
                asm.write("    jl      .L%d\n" % (op[1][1]))
            elif op[1][0] == OP_DONE:
                asm.write("    jmp     .L%d\n" % (op[1][1]))
            elif op[1][0] == OP_LSHIFT:
                asm.write("    pop     rcx\n")
                asm.write("    pop     rax\n")
                asm.write("    shl     rax, cl\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_RSHIFT:
                asm.write("    pop     rcx\n")
                asm.write("    pop     rax\n")
                asm.write("    shr     rax, cl\n")
                asm.write("    push    rax\n")
            elif op[1][0] == OP_IF:
                asm.write("    pop     rax\n")
                asm.write("    cmp     rax, 1\n")      
                asm.write("    jl      .L%d\n" % (op[1][1]))
            elif op[1][0] == OP_ELSE:
                asm.write("    jmp     .L%d\n" % (op[1][1]))
            elif op[1][0] == OP_ENDIF:
                pass        
            else:
                assert False, "Unreachable"

        asm.write(".L%d:\n" % len(program))                
        asm.write("    mov     eax, 231\n")
        asm.write("    mov     rdi, 0\n")
        asm.write("    syscall\n")
        asm.write("segment .bss\n")
        asm.write("mem: resb %d\n" % MEMORY_SIZE)


def locate_codeblocks(program):
    required_labels = []
    block_stack = []
    for op_loc in range(len(program)):
        if (program[op_loc][0] == OP_WHILE):
            block_stack.append(op_loc)
        elif (program[op_loc][0] == OP_DO):
            block_stack.append(op_loc)
        elif (program[op_loc][0] == OP_DONE):
            do_loc = block_stack.pop()
            while_loc = block_stack.pop()
            program[do_loc] = (program[do_loc][0], (op_loc + 1))
            required_labels.append(op_loc + 1)
            program[op_loc] = (program[op_loc][0], (while_loc + 1))
            required_labels.append(while_loc + 1)
        elif (program[op_loc][0] == OP_IF):
            block_stack.append(op_loc)
        elif (program[op_loc][0] == OP_ELSE):
            if_loc = block_stack.pop()
            program[if_loc] = (program[if_loc][0], (op_loc + 1))
            required_labels.append(op_loc + 1)
            block_stack.append(op_loc)
        elif (program[op_loc][0] == OP_ENDIF):
            if_or_else_loc = block_stack.pop()
            program[if_or_else_loc] = (program[if_or_else_loc][0], (op_loc + 1))
            required_labels.append(op_loc + 1)
    return (program, required_labels)


def parse_tokens_to_program(tokens):
    program = []
    for token in tokens:
        if token[1] == "print":
            program.append((OP_PRINT, ))
        elif token[1] == "+":
            program.append((OP_ADD, ))
        elif token[1] == "-":
            program.append((OP_SUB, ))
        elif token[1] == "*":
            program.append((OP_MUL, ))
        elif token[1] == "/":
            program.append((OP_DIV, ))
        elif token[1] == "%":
            program.append((OP_MOD, ))
        elif token[1] == "mem":
            program.append((OP_MEM, ))
        elif token[1] == "store":
            program.append((OP_STORE, ))
        elif token[1] == "load":
            program.append((OP_LOAD, ))
        elif token[1] == "exit":
            program.append((OP_EXIT, ))            
        elif token[1] == "dup":
            program.append((OP_DUP, ))   
        elif token[1] == "2dup":
            program.append((OP_2DUP, ))
        elif token[1] == "drop":
            program.append((OP_DROP, ))
        elif token[1] == "2drop":
            program.append((OP_2DROP, ))
        elif token[1] == "over":
            program.append((OP_OVER, ))
        elif token[1] == "2over":
            program.append((OP_2OVER, ))
        elif token[1] == "swap":
            program.append((OP_SWAP, ))
        elif token[1] == "2swap":
            program.append((OP_2SWAP, ))
        elif token[1] == "rot":
            program.append((OP_ROT, ))
        elif token[1] == "dupnz":
            program.append((OP_DUPNZ, ))
        elif token[1] == "max":
            program.append((OP_MAX, ))
        elif token[1] == "min":
            program.append((OP_MIN, ))
        elif token[1] == "==":
            program.append((OP_EQUAL, ))
        elif token[1] == "!=":
            program.append((OP_NOTEQUAL, ))
        elif token[1] == ">":
            program.append((OP_GT, ))
        elif token[1] == ">=":
            program.append((OP_GE, ))
        elif token[1] == "<":
            program.append((OP_LT, ))
        elif token[1] == "<=":
            program.append((OP_LE, ))       
        elif token[1] == "while":
            program.append((OP_WHILE, ))
        elif token[1] == "do":
            program.append((OP_DO, ))
        elif token[1] == "done":
            program.append((OP_DONE, ))
        elif token[1] == "<<":
            program.append((OP_LSHIFT, ))
        elif token[1] == ">>":
            program.append((OP_RSHIFT, ))
        elif token[1] == "if":
            program.append((OP_IF, ))
        elif token[1] == "else":
            program.append((OP_ELSE, ))
        elif token[1] == "endif":
            program.append((OP_ENDIF, ))
        else:
            try:
                program.append((OP_PUSH_INT, int(token[1])))
            except ValueError as e:
                with open(token[0][0], "r") as source_file:
                    print(''.join([line for col, line in enumerate(source_file) if col == token[0][1]]), end='')
                    print(" "*token[0][2] + "^")
                print("%s:%d:%d: %s" % (token[0][0], token[0][1], token[0][2], e))
                exit(1)
    return program


def load_tokens_from_source(file_path):
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
    return tokens


def usage():
    print("Usage: %s <SOURCE_FILE>" % sys.argv[0])


def run_cmd(cmd):
    print(cmd)
    subprocess.call(cmd)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        print("ERROR: no source file provided")
        exit(1)
    source_code = sys.argv[1]
    tokens = load_tokens_from_source(source_code)
    program = locate_codeblocks(parse_tokens_to_program(tokens))
    translate_program_to_elf64_asm(program, "output.asm")
    run_cmd(["nasm", "-g", "-felf64", "output.asm"])
    run_cmd(["ld", "-o", "output", "output.o"])
