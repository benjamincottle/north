import sys
import subprocess

OP_PUSH_INT = 0     # push int ont stack
OP_PRINT = 1        # pop stack and print to `stdout` (via itoa() + write syscall) 
OP_ADD = 2          # pop top two items from stack, add them, and push the result back to stack
OP_SUB = 3          # pop top two items from stack, subtract stack[1] from stack[0], and push the result back to stack
OP_MUL = 4          # pop top two items from stack, multiply, and push the result back to stack
OP_DIV = 5          # pop top two items from stack, divide stack[1] by stack[0], push the quotient back to stack
OP_MOD = 6          # pop top two items from stack, divide stack[1] by stack[0], push the remainder back to stack
OP_MEM = 7          # push memory base address to stack
OP_STORE = 8        # pop top two items from stack, store data in stack[0] at mem[stack[1]]
OP_LOAD = 9         # pop stack, load data at mem[stack[0]] back to stack
OP_EXIT = 10        # pop stack, exit program with exit code stack[0]

MEMORY_SIZE = 128000


def compile_program_to_asm(program, output_file):
   with open(output_file, "w") as asm:
        asm.write("BITS 64")
        asm.write("segment .text\n")
        asm.write("print:\n")
        asm.write("    mov     r9, -3689348814741910323\n")
        asm.write("    sub     rsp, 40\n")
        asm.write("    mov     BYTE [rsp+31], 10\n")
        asm.write("    lea     rcx, [rsp+30]\n")
        asm.write(".L2:\n")
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
        asm.write("    ja      .L2\n")
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
        for op in program:
            if op[0] == OP_PUSH_INT:
                asm.write("    ;; -- PUSH_INT %d --\n" % op[1])
                asm.write("    push %d\n" % op[1])
            elif op[0] == OP_PRINT:
                asm.write("    ;; -- PRINT --\n")
                asm.write("    pop rdi\n")
                asm.write("    call print\n")
            elif op[0] == OP_ADD:
                asm.write("    ;; -- ADD --\n")
                asm.write("    pop rax\n")
                asm.write("    pop rbx\n")
                asm.write("    add rax, rbx\n")
                asm.write("    push rax\n")
            elif op[0] == OP_SUB:
                asm.write("    ;; -- SUB --\n")
                asm.write("    pop rax\n")
                asm.write("    pop rbx\n")
                asm.write("    sub rbx, rax\n")
                asm.write("    push rbx\n")
            elif op[0] == OP_MUL:
                asm.write("    ;; -- MUL --\n")
                asm.write("    pop rax\n")
                asm.write("    pop rbx\n")
                asm.write("    mul rbx\n")
                asm.write("    push rax\n")    
            elif op[0] == OP_DIV:
                asm.write("    ;; -- DIV --\n")
                asm.write("    mov rdx, 0\n")
                asm.write("    pop rbx\n")
                asm.write("    pop rax\n")
                asm.write("    div rbx\n")
                asm.write("    push rax\n")
            elif op[0] == OP_MOD:
                asm.write("    ;; -- MOD --\n")
                asm.write("    mov rdx, 0\n")
                asm.write("    pop rbx\n")
                asm.write("    pop rax\n")
                asm.write("    div rbx\n")
                asm.write("    push rdx\n")
            elif op[0] == OP_MEM:
                asm.write("    ;; -- MEM --\n")
                asm.write("    push mem\n")
            elif op[0] == OP_STORE:
                asm.write("    ;; -- STORE --\n")
                asm.write("    pop rbx\n")
                asm.write("    pop rax\n")
                asm.write("    mov [rax], bl\n")
            elif op[0] == OP_LOAD:
                asm.write("    ;; -- LOAD --\n")
                asm.write("    pop rax\n")
                asm.write("    xor rbx, rbx\n")
                asm.write("    mov bl, [rax]\n")
                asm.write("    push rbx\n")
            elif op[0] == OP_EXIT:
                asm.write("    ;; -- EXIT: _NR_exit_group syscall --\n")
                asm.write("    mov eax, 231\n")
                asm.write("    pop rdi\n")
                asm.write("    syscall\n")

            else:
                assert False, "Unreachable"
        asm.write("    ;; -- EXIT: _NR_exit_group syscall --\n")
        asm.write("    mov eax, 231\n")
        asm.write("    mov rdi, 0\n")
        asm.write("    syscall\n")
        asm.write("segment .bss\n")
        asm.write("mem: resb %d\n" % MEMORY_SIZE)


def parse_tokens_to_program(tokens):   # tokens [((0, 0), '42'), ((0, 3), '23'), ((1, 0), '14')]
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
        else:
            try:
                program.append((OP_PUSH_INT, int(token[1])))
            except ValueError as e:
                print("%d:%d: %s" % (token[0][0], token[0][1], e))                
                exit(1)
    print("program", program)
    return program


def load_tokens_from_source(file_path):
    tokens = []
    token = ""
    with open(file_path, "r") as source_file:
        for line in list(enumerate(source_file)):
            line_loc = line[0]
            for column in list(enumerate(line[1])):
                if (not (column[1].isspace())):
                    if (token == ""):
                        column_loc = column[0]
                    token += column[1]
                else:
                    if (not token == ""):  # line contained only none or some whitespace and newline
                        tokens.append( ((line_loc, column_loc), token) )
                    token = ""
    print("tokens", tokens)
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
    program = parse_tokens_to_program(tokens)
    compile_program_to_asm(program, "output.asm")
    run_cmd(["nasm", "-g", "-felf64", "output.asm"])
    run_cmd(["ld", "-o", "output", "output.o"])

