import sys
import subprocess


OP_PUSH_INT = 0

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
                asm.write("    ;; -- PUSH_INT: push %d onto stack --\n" % op[1])
                asm.write("    push %d\n" % op[1])
            else:
                assert False, "Unreachable"
        asm.write("    ;; -- EXIT: _NR_exit_group syscall --\n")
        asm.write("    mov eax, 231\n")
        asm.write("    mov rdi, 0\n")
        asm.write("    syscall\n")
        asm.write("segment .bss\n")
        asm.write("mem: resb 128000\n")


def parse_tokens_to_program(tokens):   # tokens [((0, 0), '42'), ((0, 3), '23'), ((1, 0), '14')]
    program = []
    for token in tokens:
        if token[1] == ".":
            assert False, "Not implemented"
        else:
            program.append((OP_PUSH_INT, int(token[1])))
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
                    tokens.append( ((line_loc, column_loc), token) )
                    token = ""
    print("tokens", tokens)
    return tokens

def usage():
    print("Usage: %s <SOURCE_FILE>" % sys.argv[0])


def run_cmd(cmd):
    print(cmd)
    subprocess.call(cmd)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        print("ERROR: no source file provided")
        exit(1)

    source_code = sys.argv[1]
    tokens = load_tokens_from_source(source_code)
    program = parse_tokens_to_program(tokens)
    compile_program_to_asm(program, "output.asm")
    run_cmd(["nasm", "-felf64", "output.asm"])
    run_cmd(["ld", "-o", "output", "output.o"])

