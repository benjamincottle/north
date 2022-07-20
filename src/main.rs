use clap::{ArgEnum, CommandFactory, ErrorKind, Parser};
//use colored::Colorize;
use phf::phf_map;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{fmt, fs};

const MAX_INCLUDE_DEPTH: u32 = 58;
const MEMORY_SIZE: &str = "0x1f400";

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Specify assembler to use.
    #[clap(short, arg_enum, value_parser, value_name = "NAME", display_order = 1)]
    assembler: Option<Assembler>,

    /// Generate an executable containing debug symbols (nasm only)
    #[clap(short, action, display_order = 2)]
    generate_debug_symbols: bool,

    /// Use compliation debug mode [possible values: 0, 1, 2, 3]
    #[clap(short, value_parser, value_name = "LEVEL", display_order = 3)]
    debug_level: Option<usize>,

    /// Provide an alternative filename for the generated executable.
    #[clap(short, value_parser, value_name = "OUTPUT_FILE", display_order = 4)]
    output_file: Option<String>,

    /// Path to input file to compile
    #[clap(value_parser, value_name = "INPUT_FILE")]
    input_file: PathBuf,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum, Debug)]
enum Assembler {
    Fasm,
    Nasm,
}

#[derive(Hash, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum TokenType {
    Builtin,
    Uint,
    String,
    Char,
    Identifier,
    Label,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TokenType::Builtin => write!(f, "builtin"),
            TokenType::Uint => write!(f, "uint"),
            TokenType::String => write!(f, "string"),
            TokenType::Char => write!(f, "char"),
            TokenType::Identifier => write!(f, "identifier"),
            TokenType::Label => write!(f, "label"),
        }
    }
}

#[derive(Hash, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum ProgramOp {
    PUSHINT,    // push int onto stack
    PUSHSTR,    // push str_size and &str onto stack
    PRINT,      // pop stack and print to `stdout` (via itoa() + write syscall)
    ADD,        // add: (x, y) -> (x + y)
    SUB,        // subtract: (x, y) -> (x - y)
    MUL,        // multiply: (x, y) -> (x * y)
    DIV,        // divide: (x, y) -> ( x / y)
    MOD,        // modulus: (x, y) -> (x % y)
    MEM,        // push memory base address to stack
    STORE8,     // pop top two items from stack, store data in stack[0] at mem[stack[1]]
    STORE16,    //
    STORE32,    //
    STORE64,    //
    LOAD8,      // pop stack, load data at mem[stack[0]] back to stack
    LOAD16,     //
    LOAD32,     //
    LOAD64,     //
    EXIT,       // pop stack, exit program with exit code stack[0]
    DUP,        // duplicate the top item on the stack (x) -> (x, x)
    TWODUP,     // duplicate the top two items on the stack (x, y) -> (x, y, x, y)
    DROP,       // pop the top item from the stack
    TWODROP,    // pop the top two item from the stack
    OVER,       // stack ops: (x, y) -> (x, y, x)
    TWOOVER,    // stack ops: (w, x, y, z) -> (w, x, y, z, w, x)
    SWAP,       // stack ops: (x, y) -> (y, x)
    TWOSWAP,    // stack ops: (w, x, y, z) -> (y, z, w, x)
    ROT,        // (x, y, z) -> (y, z, x)  Rotate the top three stack entries.
    DUPNZ,      // (x, 0) -> (x, 0) but (x, y) -> (x, y, y)
    MAX,        // (1, 2) -> (2) pop two items, return max
    MIN,        // (1, 2) -> (1) pop two items, return min
    EQUAL,      // (x, x) -> (1) and (x, y) -> (0) pop two items, push 1 if equal, otherwise 0
    NOTEQUAL,   // (x, x) -> (0) and (x, y) -> (1) pop two items, push 0 if equal, otherwise 1
    GT,         // (1, 2) -> (0) and (2, 1) -> (1) pop two items, push 1 if greater, otherwise 0
    GE, // (1, 2) -> (0) and (2, 1) -> (1) and (1, 1) -> (1) pop two items, push 1 if gte otherwise 0
    LT, // (1, 2) -> (1) and (2, 1) -> (0) pop two items, push 1 if less, otherwise 0
    LE, // (1, 2) -> (1) and (2, 1) -> (0) and (1, 1) -> (1) pop two items, push 1 if lte, otherwise 0
    LOGICALAND, //
    LOGICALOR, //
    LOGICALNOT, //
    LSHIFT, // (x, y) -> (z) Perform a logical left shift of y bit-places on x, giving z
    RSHIFT, // (x, y) -> (z) Perform a logical right shift of y bit-places on x, giving z
    BITWISEAND,
    BITWISEOR,
    BITWISENOT,
    XOR,
    WHILE,
    DO,
    DONE,
    BREAK,
    CONTINUE,
    IF,
    ELSE,
    ENDIF,
    SYSCALL0,
    SYSCALL1,
    SYSCALL2,
    SYSCALL3,
    SYSCALL4,
    SYSCALL5,
    SYSCALL6,
    FUNCCALL,
    FUNCDEF,
    FUNCRET,
    ARGC,
    ARGV,
    DEF,
    INCLUDE,
    DEFINE,
    RETURN,
}

static KEYWORDS: phf::Map<&'static str, ProgramOp> = phf_map! {
    "print" => ProgramOp::PRINT,
    "+" => ProgramOp::ADD,
    "-" => ProgramOp::SUB,
    "*" => ProgramOp::MUL,
    "/" => ProgramOp::DIV,
    "%" => ProgramOp::MOD,
    "mem" => ProgramOp::MEM,
    "store8" => ProgramOp::STORE8,
    "store16" => ProgramOp::STORE16,
    "store32" => ProgramOp::STORE32,
    "store64" => ProgramOp::STORE64,
    "load8" => ProgramOp::LOAD8,
    "load16" => ProgramOp::LOAD16,
    "load32" => ProgramOp::LOAD32,
    "load64" => ProgramOp::LOAD64,
    "exit" => ProgramOp::EXIT,
    "dup" => ProgramOp::DUP,
    "2dup" => ProgramOp::TWODUP,
    "drop" => ProgramOp::DROP,
    "2drop" => ProgramOp::TWODROP,
    "over" => ProgramOp::OVER,
    "2over" => ProgramOp::TWOOVER,
    "swap" => ProgramOp::SWAP,
    "2swap" => ProgramOp::TWOSWAP,
    "rot" => ProgramOp::ROT,
    "dupnz" => ProgramOp::DUPNZ,
    "max" => ProgramOp::MAX,
    "min" => ProgramOp::MIN,
    "==" => ProgramOp::EQUAL,
    "!=" => ProgramOp::NOTEQUAL,
    ">" => ProgramOp::GT,
    ">=" => ProgramOp::GE,
    "<" => ProgramOp::LT,
    "<=" => ProgramOp::LE,
    "and" => ProgramOp::LOGICALAND,
    "&&" => ProgramOp::LOGICALAND,
    "or" => ProgramOp::LOGICALOR,
    "||" => ProgramOp::LOGICALOR,
    "not" => ProgramOp::LOGICALNOT,
    "!" => ProgramOp::LOGICALNOT,
    "&" => ProgramOp::BITWISEAND,
    "|" => ProgramOp::BITWISEOR,
    "~" => ProgramOp::BITWISENOT,
    "^" => ProgramOp::XOR,
    "<<" => ProgramOp::LSHIFT,
    ">>" => ProgramOp::RSHIFT,
    "while" => ProgramOp::WHILE,
    "do" => ProgramOp::DO,
    "done" => ProgramOp::DONE,
    "break" => ProgramOp::BREAK,
    "continue" => ProgramOp::CONTINUE,
    "if" => ProgramOp::IF,
    "else" => ProgramOp::ELSE,
    "endif" => ProgramOp::ENDIF,
    "syscall0" => ProgramOp::SYSCALL0,
    "syscall1" => ProgramOp::SYSCALL1,
    "syscall2" => ProgramOp::SYSCALL2,
    "syscall3" => ProgramOp::SYSCALL3,
    "syscall4" => ProgramOp::SYSCALL4,
    "syscall5" => ProgramOp::SYSCALL5,
    "syscall6" => ProgramOp::SYSCALL6,
    "def" => ProgramOp::DEF,
    "#include" => ProgramOp::INCLUDE,
    "#define" => ProgramOp::DEFINE,
    "argc" => ProgramOp::ARGC,
    "argv" => ProgramOp::ARGV,
    "return" => ProgramOp::RETURN,
};

#[derive(Hash, Clone, Eq, PartialEq, Debug)]
struct Define {
    file_path: PathBuf,
    line_num: usize,
    col_num: usize,
    tokens: Vec<((PathBuf, usize, usize), (TokenType, String))>,
}

fn print_compilation_message(token_loc: (PathBuf, usize, usize), error_msg: &str) -> std::io::Result<()> {
    let input_file = File::open(token_loc.0.clone()).expect("failed to open input file");
    let input_line = BufReader::new(input_file)
        .lines()
        .nth(token_loc.1)
        .expect("failed to read input line");
    let input_line = input_line.expect("failed to read input line");
    let input_line = input_line.as_str();
    let input_line = if input_line.ends_with('\n') {
        &input_line[..input_line.len() - 1]
    } else {
        input_line
    };
    eprintln!("{}", input_line);
    //    eprintln!("{}{}", " ".repeat(token_loc.2), "^".bright_yellow().bold()); // TODO colours!
    eprintln!("{}{}", " ".repeat(token_loc.2), "^");
    let mut escaped_error_message = String::new();
    error_msg.chars().for_each(|c| {
        if c == "\n".chars().next().unwrap() {
            escaped_error_message.push('\\');
            escaped_error_message.push('n');
        } else {
            escaped_error_message.push(c);
        }
    });
    eprintln!(
        "{}:{}:{}: {}",
        token_loc.0.file_name().unwrap().to_str().unwrap(),
        token_loc.1,
        token_loc.2,
        escaped_error_message
    );
    Ok(())
}

fn run_cmd(mut cmd: Command, debug_level: usize) -> std::io::Result<i32> {
    match debug_level {
        0 => {
            if cmd.get_program() == "fasm" {
                cmd.stdout(Stdio::null());
            };
        }
        _ => {
            if cmd.get_program() == "fasm" {
                cmd.stdout(Stdio::null());
            };
            eprintln!("[ {} {} ]", cmd.get_program().to_str().unwrap(), cmd.get_args().into_iter().map(|s|s.to_str().unwrap()).collect::<Vec<_>>().join(" "));
        }
    };
    let status = cmd
        .status()
        .expect(format!("ERROR command `{:?}` failed to start", cmd.get_program()).as_str());
    Ok(status.code().unwrap())
}

fn compile_to_elf64_asm(
    program: Vec<(
        (PathBuf, usize, usize),
        (TokenType, ProgramOp, Option<String>),
    )>,
    function_defs: HashMap<String, (String, Vec<String>, Vec<String>)>,
    required_labels: Vec<usize>,
    asm_file: PathBuf,
    assembler: Assembler,
    debug_level: usize,
) -> std::io::Result<()> {
    let mut str_data: Vec<String> = Vec::new();
    let mut implicit_exit_req: bool = true;
    {
        let mut asm = File::create(asm_file)?;
        match assembler {
            Assembler::Nasm => {
                write!(asm, "BITS 64\n")?;
                write!(asm, "section .text\n")?;
            }
            Assembler::Fasm => {
                write!(asm, "format ELF64\n")?;
                write!(asm, "section '.text' executable\n")?;
            }
        };
        write!(asm, "print:\n")?;
        write!(asm, "    sub     rsp, 0x28\n")?;
        write!(asm, "    mov     r9, 0xcccccccccccccccd\n")?;
        write!(asm, "    mov     BYTE [rsp+0x1f], 0xa\n")?;
        write!(asm, "    lea     rcx, [rsp+0x1e]\n")?;
        write!(asm, ".L00:\n")?;
        write!(asm, "    mov     rax, rdi\n")?;
        write!(asm, "    lea     r8, [rsp+0x20]\n")?;
        write!(asm, "    mul     r9\n")?;
        write!(asm, "    mov     rax, rdi\n")?;
        write!(asm, "    sub     r8, rcx\n")?;
        write!(asm, "    shr     rdx, 0x3\n")?;
        write!(asm, "    lea     rsi, [rdx+rdx*0x4]\n")?;
        write!(asm, "    add     rsi, rsi\n")?;
        write!(asm, "    sub     rax, rsi\n")?;
        write!(asm, "    add     eax, 0x30\n")?;
        write!(asm, "    mov     BYTE [rcx], al\n")?;
        write!(asm, "    mov     rax, rdi\n")?;
        write!(asm, "    mov     rdi, rdx\n")?;
        write!(asm, "    mov     rdx, rcx\n")?;
        write!(asm, "    sub     rcx, 0x1\n")?;
        write!(asm, "    cmp     rax, 0x9\n")?;
        write!(asm, "    ja      .L00\n")?;
        write!(asm, "    lea     rax, [rsp+0x20]\n")?;
        write!(asm, "    mov     edi, 0x1\n")?;
        write!(asm, "    sub     rdx, rax\n")?;
        write!(asm, "    xor     eax, eax\n")?;
        write!(asm, "    lea     rsi, [rsp+0x20+rdx]\n")?;
        write!(asm, "    mov     rdx, r8\n")?;
        write!(asm, "    mov     rax, 0x1\n")?;
        write!(asm, "    syscall\n")?;
        write!(asm, "    add     rsp, 0x28\n")?;
        write!(asm, "    ret\n")?;
        match assembler {
            Assembler::Nasm => {
                write!(asm, "global _start\n")?;
            }
            Assembler::Fasm => {
                write!(asm, "public _start as '_start'\n")?;
            }
        };
        write!(asm, "_start:\n")?;
        write!(asm, "    mov     [argc_ptr], rsp\n")?;
        for (index, program_op) in program.clone().iter().enumerate() {
            let builtin_type = program_op.1 .1;
            if required_labels.contains(&index) || debug_level > 1 {
                write!(asm, ".L{}:\n", index)?;
            }
            if debug_level > 1 {
                write!(asm, "    ;; -- {:?} --\n", builtin_type)?;
            }
            match builtin_type {
                ProgramOp::PUSHINT => {
                    write!(
                        asm,
                        "    mov     rax, {:#02x}\n",
                        program_op.1 .2.clone().unwrap().parse::<u64>().unwrap()
                    )
                    ?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::PRINT => {
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    call    print\n")?;
                }
                ProgramOp::ADD => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    add     rax, rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::SUB => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    sub     rbx, rax\n")?;
                    write!(asm, "    push    rbx\n")?;
                }
                ProgramOp::MUL => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    mul     rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::DIV => {
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    match program[index - 1].1 .2.clone().unwrap().parse::<f64>() {
                        Ok(explicit_divisor) => {
                            let opt_divisor: u64 = (2_f64.powf(64.0) / explicit_divisor) as u64;
                            write!(asm, "    mov     rcx, {:#02x}\n", opt_divisor)?;
                            write!(asm, "    mul     rcx\n")?;
                            write!(asm, "    push    rdx\n")?;
                        }
                        Err(_) => {
                            write!(asm, "    mov     rdx, 0x0\n")?;
                            write!(asm, "    div     rbx\n")?;
                            write!(asm, "    push    rax\n")?;
                        }
                    };
                }
                ProgramOp::MOD => {
                    write!(asm, "    mov     rdx, 0x0\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    div     rbx\n")?;
                    write!(asm, "    push    rdx\n")?;
                }
                ProgramOp::MEM => {
                    write!(asm, "    push    mem\n")?;
                }
                ProgramOp::STORE8 => {
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    mov     [rax], bl\n")?;
                }
                ProgramOp::STORE16 => {
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    mov     [rax], bx\n")?;
                }
                ProgramOp::STORE32 => {
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    mov     [rax], ebx\n")?;
                }
                ProgramOp::STORE64 => {
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    mov     [rax], rbx\n")?;
                }
                ProgramOp::LOAD8 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    xor     rbx, rbx\n")?;
                    write!(asm, "    mov     bl, [rax]\n")?;
                    write!(asm, "    push    rbx\n")?;
                }
                ProgramOp::LOAD16 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    xor     rbx, rbx\n")?;
                    write!(asm, "    mov     bx, [rax]\n")?;
                    write!(asm, "    push    rbx\n")?;
                }
                ProgramOp::LOAD32 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    xor     rbx, rbx\n")?;
                    write!(asm, "    mov     ebx, [rax]\n")?;
                    write!(asm, "    push    rbx\n")?;
                }
                ProgramOp::LOAD64 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    xor     rbx, rbx\n")?;
                    write!(asm, "    mov     rbx, [rax]\n")?;
                    write!(asm, "    push    rbx\n")?;
                }
                ProgramOp::EXIT => {
                    write!(asm, "    mov     eax, 0xe7\n")?;
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    syscall\n")?;
                }
                ProgramOp::DUP => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::TWODUP => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    push    rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    push    rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::DROP => {
                    write!(asm, "    pop     rax\n")?;
                }
                ProgramOp::TWODROP => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                }
                ProgramOp::OVER => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    push    rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    push    rbx\n")?;
                }
                ProgramOp::TWOOVER => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rcx\n")?;
                    write!(asm, "    pop     rdx\n")?;
                    write!(asm, "    push    rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                    write!(asm, "    push    rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    push    rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::SWAP => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    push    rbx\n")?;
                }
                ProgramOp::TWOSWAP => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rcx\n")?;
                    write!(asm, "    pop     rdx\n")?;
                    write!(asm, "    push    rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    push    rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::ROT => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    pop     rcx\n")?;
                    write!(asm, "    push    rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::DUPNZ => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, "    cmp     rax, 0\n")?;
                    write!(asm, "    je      .L{}a\n", index)?;
                    write!(asm, "    push    rax\n")?;
                    write!(asm, ".L{}a:\n", index)?;
                }
                ProgramOp::MAX => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmovge  rax, rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::MIN => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmovle  rax, rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::EQUAL => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmove   rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::NOTEQUAL => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmovne  rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::GT => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmovg   rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::GE => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmovge  rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::LT => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmovl   rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::LE => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    cmp     rbx, rax\n")?;
                    write!(asm, "    cmovle  rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::LOGICALAND => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    mul     rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::LOGICALOR => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    add     rax, rbx\n")?;
                    write!(asm, "    cmp     rax, 0x0\n")?;
                    write!(asm, "    cmovne  rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::LOGICALNOT => {
                    write!(asm, "    mov     rcx, 0x0\n")?;
                    write!(asm, "    mov     rdx, 0x1\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    cmp     rax, 0x0\n")?;
                    write!(asm, "    cmove  rcx, rdx\n")?;
                    write!(asm, "    push    rcx\n")?;
                }
                ProgramOp::LSHIFT => {
                    write!(asm, "    pop     rcx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    shl     rax, cl\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::RSHIFT => {
                    write!(asm, "    pop     rcx\n")?;
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    shr     rax, cl\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::BITWISEAND => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    and     rax, rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::BITWISEOR => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    or     rax, rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::BITWISENOT => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    not     rax\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::XOR => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rbx\n")?;
                    write!(asm, "    xor     rax, rbx\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::WHILE => {}
                ProgramOp::DO => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    cmp     rax, 0x0\n")?;
                    write!(asm, "    je      .L{}\n", program_op.1 .2.clone().unwrap())?;
                }
                ProgramOp::DONE => {
                    write!(asm, "    jmp     .L{}\n", program_op.1 .2.clone().unwrap())?;
                }
                ProgramOp::BREAK => {
                    write!(asm, "    jmp     .L{}\n", program_op.1 .2.clone().unwrap())?;
                }
                ProgramOp::CONTINUE => {
                    write!(asm, "    jmp     .L{}\n", program_op.1 .2.clone().unwrap())?;
                }
                ProgramOp::IF => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    cmp     rax, 0x0\n")?;
                    write!(asm, "    je      .L{}\n", program_op.1 .2.clone().unwrap())?;
                }
                ProgramOp::ELSE => {
                    write!(asm, "    jmp     .L{}\n", program_op.1 .2.clone().unwrap())?;
                }
                ProgramOp::ENDIF => {}
                ProgramOp::SYSCALL0 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    syscall\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::SYSCALL1 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    syscall\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::SYSCALL2 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    pop     rsi\n")?;
                    write!(asm, "    syscall\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::SYSCALL3 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    pop     rsi\n")?;
                    write!(asm, "    pop     rdx\n")?;
                    write!(asm, "    syscall\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::SYSCALL4 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    pop     rsi\n")?;
                    write!(asm, "    pop     rdx\n")?;
                    write!(asm, "    pop     r10\n")?;
                    write!(asm, "    syscall\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::SYSCALL5 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    pop     rsi\n")?;
                    write!(asm, "    pop     rdx\n")?;
                    write!(asm, "    pop     r10\n")?;
                    write!(asm, "    pop     r8\n")?;
                    write!(asm, "    syscall\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::SYSCALL6 => {
                    write!(asm, "    pop     rax\n")?;
                    write!(asm, "    pop     rdi\n")?;
                    write!(asm, "    pop     rsi\n")?;
                    write!(asm, "    pop     rdx\n")?;
                    write!(asm, "    pop     r10\n")?;
                    write!(asm, "    pop     r8\n")?;
                    write!(asm, "    pop     r9\n")?;
                    write!(asm, "    syscall\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::PUSHSTR => {
                    if !str_data.contains(&program_op.1 .2.clone().unwrap()) {
                        str_data.push(program_op.1 .2.clone().unwrap());
                    };
                    let str_len = program_op.1 .2.clone().unwrap().len();
                    write!(asm, "    push    {:#04x}\n", (str_len))?;
                    let str_index = str_data
                        .iter()
                        .position(|r| r == &program_op.1 .2.clone().unwrap())
                        .unwrap();
                    write!(asm, "    push    str{}\n", str_index)?;
                }
                ProgramOp::ARGC => {
                    write!(asm, "    mov     rax, [argc_ptr]\n")?;
                    write!(asm, "    mov     rax, [rax]\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::ARGV => {
                    write!(asm, "    mov     rax, [argc_ptr]\n")?;
                    write!(asm, "    add     rax, 0x8\n")?;
                    write!(asm, "    push    rax\n")?;
                }
                ProgramOp::RETURN => {
                    let function = function_defs
                        .get(&program_op.1 .2.clone().unwrap())
                        .unwrap();
                    let returns_count = function.2.len();
                    if returns_count > 0 {
                        write!(asm, "    pop     rax\n")?;
                    };
                    write!(asm, "    pop     rbp\n")?;
                    write!(asm, "    ret\n")?;
                }
                ProgramOp::FUNCCALL => {
                    let function = function_defs
                        .get(&program_op.1 .2.clone().unwrap())
                        .unwrap();
                    let function_name = function.0.clone();
                    let args_count = function.1.len();
                    let returns_count = function.2.len();
                    if args_count > 0 {
                        write!(asm, "    pop     rdi\n")?;
                    };
                    if args_count > 1 {
                        write!(asm, "    pop     rsi\n")?;
                    };
                    if args_count > 2 {
                        write!(asm, "    pop     rdx\n")?;
                    };
                    if args_count > 3 {
                        write!(asm, "    pop     rcx\n")?;
                    };
                    if args_count > 4 {
                        write!(asm, "    pop     r8\n")?;
                    };
                    if args_count > 5 {
                        write!(asm, "    pop     r9\n")?;
                    };
                    if args_count > 6 {
                        print_compilation_message(
                            program_op.0.clone(),
                            "Too many arguments to function",
                        ).unwrap();
                        std::process::exit(1);
                    };
                    write!(asm, "    call    {}\n", function_name)?;
                    if returns_count > 0 {
                        write!(asm, "    push    rax\n")?;
                    };
                }
                ProgramOp::FUNCRET => {
                    let function = function_defs
                        .get(&program_op.1 .2.clone().unwrap())
                        .unwrap();
                    let returns_count = function.2.len();
                    if returns_count > 0 {
                        write!(asm, "    pop     rax\n")?;
                    };
                    write!(asm, "    pop     rbp\n")?;
                    write!(asm, "    ret\n")?;
                }
                ProgramOp::FUNCDEF => {
                    let function = function_defs
                        .get(&program_op.1 .2.clone().unwrap())
                        .unwrap();
                    let function_name = function.0.clone();
                    let args_count = function.1.len();
                    if implicit_exit_req {
                        write!(asm, ".L{}:\n", program.len())?;
                        write!(asm, "    mov     eax, 0xe7\n")?;
                        write!(asm, "    mov     rdi, 0x0\n")?;
                        write!(asm, "    syscall\n")?;
                        implicit_exit_req = false;
                    };
                    write!(asm, "{}:\n", function_name)?;
                    write!(asm, "    push    rbp\n")?;
                    write!(asm, "    mov     rbp, rsp\n")?;
                    if args_count > 6 {
                        print_compilation_message(
                            program_op.0.clone(),
                            "Too many arguments to function",
                        ).unwrap();
                        std::process::exit(1);
                    };
                    if args_count > 5 {
                        write!(asm, "    push    r9\n")?;
                    };
                    if args_count > 4 {
                        write!(asm, "    push    r8\n")?;
                    };
                    if args_count > 3 {
                        write!(asm, "    push    rcx\n")?;
                    };
                    if args_count > 2 {
                        write!(asm, "    push    rdx\n")?;
                    };
                    if args_count > 1 {
                        write!(asm, "    push    rsi\n")?;
                    };
                    if args_count > 0 {
                        write!(asm, "    push    rdi\n")?;
                    };
                }
                ProgramOp::DEF => {}
                ProgramOp::INCLUDE => {}
                ProgramOp::DEFINE => {}
            };
        }
        match implicit_exit_req {
            true => {
                write!(asm, ".L{}:\n", program.len())?;
                write!(asm, "    mov     eax, 0xe7\n")?;
                write!(asm, "    mov     rdi, 0x0\n")?;
                write!(asm, "    syscall\n")?;
            }
            false => {}
        };
        match assembler {
            Assembler::Nasm => {
                write!(asm, "section .data\n")?;
            }
            Assembler::Fasm => {
                write!(asm, "section '.data' writable\n")?;
            }
        };
        if str_data.len() > 0 {
            for (str_index, static_str) in str_data.iter().enumerate() {
                let str_label = format!("str{}", str_index);
                let mut hex_str = String::new();
                for byte in static_str.bytes() {
                    hex_str.push_str(&format!("0x{:02x},", byte));
                }
                hex_str.pop();
                if hex_str.len() > 0 {
                    hex_str.extend(",0x00".chars());
                } else {
                    hex_str.extend("0x00".chars());
                }
                write!(asm, "    {}: db {}\n", str_label, hex_str)?;
            }
        };
        match assembler {
            Assembler::Nasm => {
                write!(asm, "section .bss\n")?;
                write!(asm, "    argc_ptr: resq 0x1\n")?;
                write!(asm, "    mem: resb {}\n", MEMORY_SIZE)?;
            }
            Assembler::Fasm => {
                write!(asm, "    argc_ptr: rq 0x1\n")?;
                write!(asm, "    mem: rb {}\n", MEMORY_SIZE)?;
            }
        };
    }
    Ok(())
}

fn locate_blocks(
    tokens: Vec<(
        (PathBuf, usize, usize),
        (TokenType, ProgramOp, Option<String>),
    )>,
    function_defs: HashMap<String, (String, Vec<String>, Vec<String>)>,
    debug_level: usize,
) -> std::io::Result<(
    Vec<(
        (PathBuf, usize, usize),
        (TokenType, ProgramOp, Option<String>),
    )>,
    HashMap<String, (String, Vec<String>, Vec<String>)>,
    Vec<usize>,
)> {
    let mut required_labels: Vec<usize> = Vec::new();
    let mut while_stack: Vec<(
        usize,
        (
            (PathBuf, usize, usize),
            (TokenType, ProgramOp, Option<String>),
        ),
    )> = Vec::new();
    let mut if_stack: Vec<(
        usize,
        (
            (PathBuf, usize, usize),
            (TokenType, ProgramOp, Option<String>),
        ),
    )> = Vec::new();
    let mut program = tokens;
    for (index, _program_op) in program.clone().iter().enumerate() {
        let builtin_type = program[index].1 .1;
        match builtin_type {
            ProgramOp::WHILE => {
                while_stack.push((index, (program[index].clone())));
            }
            ProgramOp::DO => {
                while_stack.push((index, (program[index].clone())));
            }
            ProgramOp::BREAK => {
                while_stack.push((index, (program[index].clone())));
            }
            ProgramOp::CONTINUE => {
                while_stack.push((index, (program[index].clone())));
            }
            ProgramOp::DONE => {
                if while_stack.len() < 2 {
                    if while_stack.len() == 1
                        // && while_stack.last().unwrap().1 .1 .1 == ProgramOp::DO
                        && while_stack.last().unwrap().1 .1 .1 == ProgramOp::DO                        
                    {
                        let error_message = "ERROR missing `while` before `do`";
                        let token_loc = program[while_stack.last().unwrap().0.clone()].0.clone();
                        print_compilation_message(token_loc, error_message)?;
                        std::process::exit(1);
                    } else if while_stack.len() == 1
                        && while_stack.last().unwrap().1 .1 .1 == ProgramOp::WHILE
                    {
                        let error_message = "ERROR missing `do` before `done`";
                        let token_loc = program[index].0.clone();
                        print_compilation_message(token_loc, error_message)?;
                        std::process::exit(1);
                    } else {
                        let error_message = "ERROR missing `while` and `do` before `done`";
                        let token_loc = program[index].0.clone();
                        print_compilation_message(token_loc, error_message)?;
                        std::process::exit(1);
                    };
                };
                let mut continue_labels: Vec<usize> = Vec::new();
                let mut break_labels: Vec<usize> = Vec::new();
                let mut do_loc: usize = 0;
                while while_stack.last().unwrap().1 .1 .1 != ProgramOp::WHILE {
                    match while_stack.last().unwrap().1 .1 .1 {
                        ProgramOp::CONTINUE => {
                            continue_labels.push(while_stack.pop().unwrap().0);
                        }
                        ProgramOp::BREAK => {
                            break_labels.push(while_stack.pop().unwrap().0);
                        }
                        ProgramOp::DO => {
                            if while_stack[while_stack.len() - 2].1 .1 .1 != ProgramOp::WHILE {
                                print_compilation_message(
                                    program[while_stack.last().unwrap().0.clone()].0.clone(),
                                    "ERROR missing `while` before `do`",
                                )?;
                                std::process::exit(1);
                            };
                            do_loc = while_stack.pop().unwrap().0;
                        }
                        _ => {}
                    };
                }
                let while_loc = while_stack.pop().unwrap().0;
                for c_index in continue_labels {
                    program[c_index] = (
                        program[c_index].0.clone(),
                        (
                            program[c_index].1 .0,
                            program[c_index].1 .1,
                            Some((while_loc + 1).to_string()),
                        ),
                    );
                }
                for b_index in break_labels {
                    program[b_index] = (
                        program[b_index].0.clone(),
                        (
                            program[b_index].1 .0,
                            program[b_index].1 .1,
                            Some((index + 1).to_string()),
                        ),
                    );
                }
                program[do_loc] = (
                    program[do_loc].0.clone(),
                    (
                        program[do_loc].1 .0,
                        program[do_loc].1 .1,
                        Some((index + 1).to_string()),
                    ),
                );
                required_labels.push(index + 1);
                program[index] = (
                    program[index].0.clone(),
                    (
                        program[index].1 .0,
                        program[index].1 .1,
                        Some((while_loc + 1).to_string()),
                    ),
                );
                required_labels.push(while_loc + 1);
            }
            ProgramOp::IF => {
                if_stack.push((index, (program[index].clone())));
            }
            ProgramOp::ELSE => {
                if if_stack.len() == 0 {
                    print_compilation_message(
                        program[index].0.clone(),
                        "ERROR missing `if` before `else`",
                    )?;
                    std::process::exit(1);
                };
                let if_loc = if_stack.pop().unwrap().0;
                program[if_loc] = (
                    program[if_loc].0.clone(),
                    (
                        program[if_loc].1 .0,
                        program[if_loc].1 .1,
                        Some((index + 1).to_string()),
                    ),
                );
                required_labels.push(index + 1);
                if_stack.push((index, (program[index].clone())));
            }
            ProgramOp::ENDIF => {
                if if_stack.len() == 0 {
                    print_compilation_message(
                        program[index].0.clone(),
                        "ERROR missing `if` before `endif`",
                    )?;
                    std::process::exit(1);
                };
                let if_or_else_loc = if_stack.pop().unwrap().0;
                program[if_or_else_loc] = (
                    program[if_or_else_loc].0.clone(),
                    (
                        program[if_or_else_loc].1 .0,
                        program[if_or_else_loc].1 .1,
                        Some((index + 1).to_string()),
                    ),
                );
                required_labels.push(index + 1);
            }
            _ => {}
        };
    }
    if while_stack.len() != 0 {
        let unmatched_token_index = while_stack.pop().unwrap().0;
        let unmatched_token = program[unmatched_token_index].clone();
        let builtin_type = unmatched_token.1 .1.clone();
        let error_message: &str = if builtin_type == ProgramOp::WHILE {
            "ERROR `while` missing `do` and `done`"
        } else if builtin_type == ProgramOp::CONTINUE {
            "ERROR `continue` not valid outside `while` loop"
        } else if builtin_type == ProgramOp::BREAK {
            "ERROR `break` not valid outside `while` loop"
        } else if builtin_type == ProgramOp::DO {
            "ERROR `do` missing `while`"
        } else {
            // TODO something about the token should appear in the mesage
            "ERROR unmatched token"
        };
        print_compilation_message(unmatched_token.0.clone(), error_message)?;
        std::process::exit(1);
    };
    if if_stack.len() != 0 {
        let unmatched_token_index = if_stack.pop().unwrap().0;
        let unmatched_token = program[unmatched_token_index].clone();
        let builtin_type = unmatched_token.1 .1.clone();
        let error_message: &str = if builtin_type == ProgramOp::IF {
            "ERROR missing `endif` after `if`"
        } else {
            // TODO something about the token should appear in the mesage
            "ERROR unmatched token"
        };
        print_compilation_message(unmatched_token.0.clone(), error_message)?;
        std::process::exit(1);
    };
    if debug_level > 2 {
        println!("[ intermediate representation ]");
        for op in program.clone() {
            println!("  {:?}", op);
        }
    };
    Ok((program, function_defs, required_labels))
}

fn parse_tokens(
    tokens: Vec<((PathBuf, usize, usize), (TokenType, String, Option<String>))>,
    function_defs: HashMap<String, (String, Vec<String>, Vec<String>)>,
    debug_level: usize,
) -> std::io::Result<(
    Vec<(
        (PathBuf, usize, usize),
        (TokenType, ProgramOp, Option<String>),
    )>,
    HashMap<String, (String, Vec<String>, Vec<String>)>,
)> {
    let mut program: Vec<(
        (PathBuf, usize, usize),
        (TokenType, ProgramOp, Option<String>),
    )> = Vec::new();
    for token in tokens {
        let token_loc = token.0.clone();
        let token_type = token.1 .0.clone();
        let token_data = token.1 .1.clone();
        match token_type {
            TokenType::Builtin => {
                if KEYWORDS.contains_key(token.1 .1.as_str()) {
                    match token.1 .2.clone() {
                        Some(_s) => {
                            program.push((
                                token.0.clone(),
                                (
                                    token.1 .0,
                                    *KEYWORDS.get(token.1 .1.as_str()).unwrap(),
                                    token.1 .2.clone(),
                                ),
                            ));
                        }
                        _ => {
                            program.push((
                                token.0.clone(),
                                (
                                    token.1 .0,
                                    *KEYWORDS.get(token.1 .1.as_str()).unwrap(),
                                    None,
                                ),
                            ));
                        }
                    };
                };
            }
            TokenType::Uint => {
                program.push((
                    token.0.clone(),
                    (token.1 .0, ProgramOp::PUSHINT, Some(token_data.clone())),
                ));
            }
            TokenType::String => {
                program.push((
                    token.0.clone(),
                    (
                        token.1 .0,
                        ProgramOp::PUSHSTR,
                        Some(
                            token_data
                                .clone()
                                .strip_prefix("\"")
                                .unwrap()
                                .strip_suffix("\"")
                                .unwrap()
                                .to_string(),
                        ),
                    ),
                ));
            }
            TokenType::Char => {
                let token_data = (token_data
                    .clone()
                    .strip_prefix("\'")
                    .unwrap()
                    .strip_suffix("\'")
                    .unwrap()
                    .chars()
                    .next()
                    .unwrap() as u32)
                    .to_string();
                program.push((
                    token.0.clone(),
                    (token.1 .0, ProgramOp::PUSHINT, Some(token_data)),
                ));
            }
            TokenType::Identifier => {
                if function_defs.contains_key(token_data.as_str()) {
                    program.push((
                        token.0.clone(),
                        (token.1 .0, ProgramOp::FUNCCALL, Some(token_data.clone())),
                    ));
                } else {
                    print_compilation_message(
                        token.0.clone(),
                        format!("ERROR invalid token `{}`", token.1 .1.clone()).as_str(),
                    )?;
                    std::process::exit(1);
                };
            }
            TokenType::Label => {
                match token.1 .2.unwrap().as_str() {
                    "f_def" => {
                        program.push((
                            token_loc.clone(),
                            (token_type, ProgramOp::FUNCDEF, Some(token_data.clone())),
                        ));
                    }
                    "f_ret" => {
                        program.push((
                            token_loc.clone(),
                            (token_type, ProgramOp::FUNCRET, Some(token_data.clone())),
                        ));
                    }
                    _ => {
                        eprintln!(
                            "{:?}:{:?}:{:?} ERROR Invalid internal function label {:?}",
                            token_loc.0,
                            token_loc.1,
                            token_loc.2,
                            token_data.clone()
                        );
                        std::process::exit(1);
                    }
                };
            }
        };
    }
    if debug_level > 3 {
        println!("parse_tokens(): \n{:?}\n", program);
    };

    Ok((program, function_defs))
}

fn preprocessor_function(
    mut tokens: Vec<((PathBuf, usize, usize), (TokenType, String))>,
    debug_level: usize,
) -> std::io::Result<(
    Vec<((PathBuf, usize, usize), (TokenType, String, Option<String>))>,
    HashMap<String, (String, Vec<String>, Vec<String>)>,
)> {
    let mut function_defs = HashMap::new();
    let mut function_tokens: Vec<((PathBuf, usize, usize), (TokenType, String, Option<String>))> =
        Vec::new();
    let mut tokens_expanded: Vec<((PathBuf, usize, usize), (TokenType, String, Option<String>))> =
        Vec::new();
    while tokens.len() > 0 {
        let token = tokens.remove(0).clone();
        let token_data = token.1 .1.clone();
        if token_data == "def" {
            if tokens.len() == 0 {
                print_compilation_message(
                    token.0.clone(),
                    "ERROR invalid function definition, expected function name",
                )?;
                std::process::exit(1);
            };
            if tokens[0].1 .0 != TokenType::Identifier {
                print_compilation_message(
                    tokens[0].0.clone(),
                    (format!(
                        "ERROR invalid function name type `{}`, expected `identifier`",
                        tokens[0].1 .0.to_string()
                    ))
                    .as_str(),
                )?;
                std::process::exit(1);
            };
            if function_defs.contains_key(&tokens[0].1 .1) {
                print_compilation_message(
                    tokens[0].0.clone(),
                    (format!("ERROR duplicate function name `{}`", tokens[0].1 .1)).as_str(),
                )?;
                std::process::exit(1);
            };
            if tokens.len() < 3 {
                print_compilation_message(token.0.clone(), "ERROR invalid function definition")?;
                std::process::exit(1);
            };
            if tokens[1].1 .1 != "(" {
                print_compilation_message(
                    tokens[1].0.clone(),
                    (format!("ERROR invalid function argument definiton, expected `(`")).as_str(),
                )?;
                std::process::exit(1);
            };
            if tokens.len() < 8 {
                print_compilation_message(token.0.clone(), "ERROR invalid function definition")?;
                std::process::exit(1);
            };
            let mut function_args: Vec<String> = Vec::new();
            let mut function_returns: Vec<String> = Vec::new();
            let function_name_loc = tokens[0].0.clone();
            let function_name = tokens.remove(0).clone().1 .1;
            // Valid characters in labels are letters, numbers, _, $, #, @, ~, ., and ?
            // The only characters which may be used as the first character of an identifier are letters, _ and ?
            let mut valid_function_name: Vec<String> = Vec::new();
            valid_function_name.push("f".to_string());
            for c in function_name.chars() {
                if c.is_alphanumeric()
                    || c == '_'
                    || c == '$'
                    || c == '#'
                    || c == '@'
                    || c == '~'
                    || c == '.'
                    || c == '?'
                {
                    valid_function_name.push(c.to_string());
                } else {
                    valid_function_name.push(hex::encode(c.to_string()));
                }
            }
            tokens.remove(0); // Remove the opening parenthesis
            while tokens[0].1 .1 != "--" {
                // while not at the end of a function arguments
                if tokens[0].1 .1 == ")" {
                    print_compilation_message(
                        tokens[0].0.clone(),
                        (format!(
                            "ERROR invalid function argument definiton, expected `--` before `)`"
                        ))
                        .as_str(),
                    )?;
                    std::process::exit(1);
                };
                if tokens[0].1 .0 != TokenType::Identifier {
                    print_compilation_message(
                        tokens[0].0.clone(),
                        (format!(
                            "ERROR invalid function argument type `{}`, expected `identifier`",
                            tokens[0].1 .0.to_string()
                        ))
                        .as_str(),
                    )?;
                    std::process::exit(1);
                };
                function_args.push(tokens.remove(0).1 .1.clone());
            }
            tokens.remove(0); // Remove the --
            while tokens[0].1 .1 != ")" {
                if tokens[0].1 .1 == "{" {
                    print_compilation_message(
                        tokens[0].0.clone(),
                        (format!(
                            "ERROR invalid function argument definiton, expected `)` before `{{`"
                        ))
                        .as_str(),
                    )?;
                    std::process::exit(1);
                };
                if tokens[0].1 .0 != TokenType::Identifier {
                    print_compilation_message(
                        tokens[0].0.clone(),
                        (format!(
                            "ERROR invalid function return type `{}`, expected `identifier`",
                            tokens[0].1 .0.to_string()
                        ))
                        .as_str(),
                    )?;
                    std::process::exit(1);
                };
                function_returns.push(tokens.remove(0).1 .1.clone());
            }
            tokens.remove(0); // Remove the )
            if tokens[0].1 .1 != "{" {
                print_compilation_message(
                    tokens[0].0.clone(),
                    (format!("ERROR invalid function definition, expected `{{`")).as_str(),
                )?;
                std::process::exit(1);
            };
            let function_body_loc = tokens[0].0.clone();
            tokens.remove(0); // Remove the {
            function_tokens.push((
                function_name_loc.clone(),
                (
                    TokenType::Label,
                    function_name.clone(),
                    Some("f_def".to_string()),
                ),
            ));
            while tokens[0].1 .1 != "}" {
                if tokens.len() == 1 && tokens[0].1 .1 != "}" {
                    print_compilation_message(
                        function_body_loc,
                        "ERROR invalid function definition, unmatched `{`",
                    )?;
                    std::process::exit(1);
                };
                if tokens[0].1 .1 == "{" {
                    print_compilation_message(
                        tokens[0].0.clone(),
                        (format!("ERROR invalid function definition, `{{` unexpected")).as_str(),
                    )?;
                    std::process::exit(1);
                };

                if tokens[0].1 .1 == "return" {
                    function_tokens.push((
                        tokens[0].0.to_owned(),
                        (
                            tokens[0].1 .0,
                            tokens[0].1 .1.to_owned(),
                            Some(function_name.to_owned()),
                        ),
                    ));
                    tokens.remove(0);
                } else {
                    function_tokens.push((
                        tokens[0].0.to_owned(),
                        (tokens[0].1 .0, tokens[0].1 .1.to_owned(), None),
                    ));
                    tokens.remove(0);
                }
            }
            tokens.remove(0); // Remove the }
            function_tokens.push((
                function_name_loc,
                (
                    TokenType::Label,
                    function_name.to_owned(),
                    Some("f_ret".to_string()),
                ),
            ));
            function_defs.insert(
                function_name,
                (
                    valid_function_name.join(""),
                    function_args,
                    function_returns,
                ),
            );
        } else {
            // token is not a function def component
            if token.1 .1 == "return" {
                print_compilation_message(
                    token.0.clone(),
                    format!("ERROR `return` not valid outside function body").as_str(),
                )?;
                std::process::exit(1);
            };
            tokens_expanded.push((token.0, (token.1 .0, token.1 .1, None)));
        }
    }
    tokens_expanded.extend(function_tokens);
    if debug_level > 3 {
        println!("preprocessor_function(): \n{:?}\n", tokens_expanded);
    }

   Ok((tokens_expanded, function_defs))
}

fn preprocessor_define(
    mut tokens: Vec<((PathBuf, usize, usize), (TokenType, String))>,
    debug_level: usize,
) -> std::io::Result<Vec<((PathBuf, usize, usize), (TokenType, String))>> {
    let mut tokens_expanded: Vec<((PathBuf, usize, usize), (TokenType, String))> = Vec::new();
    let mut defines: HashMap<String, Define> = HashMap::new();
    while tokens.len() > 0 {
        let token = tokens.remove(0);
        let token_data = token.1 .1.clone();
        if token_data == "#define" {
            if tokens.len() < 1 {
                print_compilation_message(token.0.clone(), "ERROR `#define` missing define name")?;
                std::process::exit(1);
            };
            if tokens[0].1 .0 != TokenType::Identifier {
                print_compilation_message(tokens[0].0.clone(), "ERROR invalid `#define` name")?;
                std::process::exit(1);
            };
            if tokens.len() < 3 {
                print_compilation_message(token.0.clone(), "ERROR `#define` missing define value")?;
                std::process::exit(1);
            };
            let define_name_loc = tokens[0].0.clone();
            let define_name = tokens.remove(0).1 .1.clone();
            let mut define = Define {
                file_path: token.0 .0.clone(),
                line_num: token.0 .1,
                col_num: tokens[0].0 .2,
                tokens: Vec::new(),
            };
            while tokens[0].0 .1 == define.line_num {
                define.tokens.push(tokens.remove(0));
            }
            match defines.get(&define_name) {
                Some(_name) => {
                    print_compilation_message(
                        define_name_loc,
                        format!("ERROR `#define` redefinition of `{}`", define_name).as_str(),
                    )?;
                    std::process::exit(1);
                }
                _ => {
                    let mut redefined_tokens: Vec<((PathBuf, usize, usize), (TokenType, String))> =
                        Vec::new();

                    for token in define.tokens.clone().iter() {
                        match defines.get(&token.1 .1) {
                            Some(_redefine) => {
                                redefined_tokens
                                    .extend(defines.get(&token.1 .1).unwrap().tokens.clone());
                            }
                            _ => {
                                redefined_tokens.push(token.to_owned());
                            }
                        } // end match
                    } // end for token
                    define.tokens = redefined_tokens;
                    defines.insert(define_name, define);
                }
            }
        } else {
            match defines.get(&token.1 .1) {
                Some(_redefine) => {
                    let replace_loc = token.0.clone();
                    for token in &defines.get(&token.1 .1).unwrap().tokens {
                        tokens_expanded.push((replace_loc.clone(), token.1.clone()));
                    }
                }
                _ => {
                    tokens_expanded.push(token);
                }
            }
        }
    }
    if debug_level > 3 {
        println!("preprocessor_define(): \n{:?}\n", tokens_expanded.clone());
    }
    Ok(tokens_expanded)
}

fn preprocessor_include(
    mut tokens: Vec<((PathBuf, usize, usize), (TokenType, String))>,
    mut include_depth: Vec<PathBuf>,
    debug_level: usize,
) -> std::io::Result<Vec<((PathBuf, usize, usize), (TokenType, String))>> {
    if include_depth.len() > MAX_INCLUDE_DEPTH.try_into().unwrap() {
        print_compilation_message(tokens[0].clone().0, "ERROR `#include` nested too deeply")?;
        std::process::exit(1);
    };
    let mut tokens_expanded: Vec<((PathBuf, usize, usize), (TokenType, String))> = Vec::new();
    while tokens.len() > 0 {
        let token = tokens.remove(0);
        let token_data = token.1 .1.clone();
        let parent_file = token.0 .0.clone();
        if token_data == "#include" {
            if tokens.len() == 0 {
                print_compilation_message(token.0.clone(), "ERROR `#include` missing include file")?;
                std::process::exit(1);
            };
            let next_token = tokens.remove(0);
            let next_token_data = &next_token.1 .1;
            if !((next_token_data.starts_with("<") && next_token_data.ends_with(">"))
                || (next_token_data.starts_with("\"") && next_token_data.ends_with("\"")))
            {
                print_compilation_message(next_token.0.clone(), "ERROR invalid `#include` file")?;
                std::process::exit(1);
            }
            if next_token_data // TODO: trim_start replacces with strip_prefix
                .trim_start()
                .trim_end()
                .matches(parent_file.file_stem().unwrap().to_str().unwrap())
                .count()
                > 0
            {
                print_compilation_message(
                    next_token.0.clone(),
                    "ERROR `#include` circular dependency",
                )?;
                std::process::exit(1);
            };
            if next_token_data.contains("/") {
                print_compilation_message(
                    next_token.0.clone(),
                    "ERROR `#include` can not be a path. Additional search paths not implemented",
                )?;
                std::process::exit(1);
            }
            let include_file = next_token_data;
            let include_file_path = if include_file.starts_with("<") && include_file.ends_with(">")
            {
                let search_path = PathBuf::from("./lib");
                let mut include_file =
                    PathBuf::from(include_file.trim_start_matches('<').trim_end_matches('>'));
                include_file.set_extension("north");
                let include_file = search_path.join(include_file);
                include_file
            } else if include_file.starts_with("\"") && include_file.ends_with("\"") {
                let search_path = if parent_file.parent().unwrap().to_str().unwrap() == "" {
                    PathBuf::from(".")
                } else {
                    parent_file.parent().unwrap().to_path_buf()
                };
                let include_file = PathBuf::from(
                    search_path.join(include_file.trim_start_matches('"').trim_end_matches('"')),
                );
                include_file
            } else {
                print_compilation_message(
                    next_token.0.clone(),
                    format!("ERROR invalid include `{}`", next_token_data).as_str(),
                )?;
                std::process::exit(1);
            };
            if !include_file_path.exists() {
                print_compilation_message(
                    next_token.0.clone(),
                    format!(
                        "ERROR include file `{}` not found",
                        include_file
                            .strip_prefix("\"")
                            .unwrap()
                            .strip_suffix("\"")
                            .unwrap()
                    )
                    .as_str(),
                )?;
                std::process::exit(1);
            };
            if !include_file_path.is_file() {
                print_compilation_message(
                    next_token.0.clone(),
                    format!(
                        "ERROR include file `{}` is not a file",
                        include_file_path.to_str().unwrap()
                    )
                    .as_str(),
                )?;
                std::process::exit(1);
            };

            if include_depth.contains(&PathBuf::from(include_file)) {
                if debug_level > 0 {
                    let error_message = format!(
                        "INFO: ignoring `#include {}`, already included ",
                        include_file
                    );
                    print_compilation_message(next_token.0.clone(), error_message.as_str())?;
                };
            } else {
                include_depth.push(PathBuf::from(include_file));
                let include_file_tokens =
                    load_tokens(&PathBuf::from(include_file_path), debug_level).unwrap();

                let include_file_tokens =
                    preprocessor_include(include_file_tokens, include_depth.clone(), debug_level).unwrap();

                //add include_file_tokens to tokens_expanded
                for include_file_token in include_file_tokens {
                    tokens_expanded.push(include_file_token);
                }
            }
        } else {
            tokens_expanded.push(token);
        }
    }
    if debug_level > 3 {
        println!("preprocessor_include(): \n{:?}\n", tokens_expanded.clone());
    }

    Ok(tokens_expanded)
}

fn parse_line(
    path: &PathBuf,
    line_num: usize,
    line: &String,
) -> std::io::Result<Vec<((PathBuf, usize, usize), (TokenType, String))>> {
    let path = path.clone();
    let mut line = line.clone();
    let mut token = "".to_string();
    let mut token_type;
    let mut col_num = 0;
    let mut cur_column = 0;
    let mut result = Vec::new();
    while line.len() > 0 {
        let c = line.remove(0);
        // skip leading whitespace
        if c.is_whitespace() && token.len() == 0 {
            cur_column += 1;
        }
        // string literal begin
        else if c == '\"' {
            if token.len() != 0 {
                let error_message =
                    format!("ERROR tokens should be separated by whitespace `{}`", token);
                print_compilation_message(
                    (path.clone(), line_num, col_num),
                    error_message.as_str(),
                )?;
                std::process::exit(1);
            };
            col_num = cur_column;
            token_type = TokenType::String;
            cur_column += 1;
            token.push(c); // push the first quote
            while line.len() > 0 {
                let c = line.remove(0);
                // string literal escape next char
                if c == '\\' {
                    if line.len() > 0 {
                        let c = line.remove(0);
                        if c == 'n' {
                            token.push('\n');
                        } else if c == 't' {
                            token.push('\t');
                        } else if c == 'r' {
                            token.push('\r');
                        } else if c == '\"' {
                            token.push('\"');
                        } else if c == '\'' {
                            token.push('\'');
                        } else if c == '\\' {
                            token.push('\\');
                        } else {
                            return Err(std::io::Error::new(
                                // TODO: more error reporting here
                                std::io::ErrorKind::InvalidData,
                                format!("Invalid escape sequence: \\{}", c),
                            ));
                        }
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid escape sequence: \\ at end of line",
                        ));
                    }
                }
                // string literal end
                else if c == '\"' {
                    token.push(c); // push the last quote
                    if line.len() > 0 && !line.starts_with(" ") {
                        let error_message =
                            format!("ERROR tokens should be separated by whitespace `{}`", token);
                        print_compilation_message(
                            (path.clone(), line_num, col_num),
                            error_message.as_str(),
                        )?;
                        std::process::exit(1);
                    }
                    result.push(((path.clone(), line_num, col_num), (token_type, token)));
                    token = "".to_string();
                    cur_column += 1;
                    break;
                }
                // continue building string literal
                else {
                    token.push(c);
                    cur_column += 1;
                }
            }
        }
        // character literal begin
        else if c == '\'' {
            col_num = cur_column;
            token_type = TokenType::Char;
            cur_column += 1;
            token.push(c); // push the first quote
            while line.len() > 0 {
                let c = line.remove(0);
                // character literal escape next char
                if c == '\\' {
                    if line.len() > 0 {
                        let c = line.remove(0);
                        if c == 'n' {
                            token.push('\n');
                        } else if c == 't' {
                            token.push('\t');
                        } else if c == 'r' {
                            token.push('\r');
                        } else if c == '\"' {
                            token.push('\"');
                        } else if c == '\'' {
                            token.push('\'');
                        } else if c == '\\' {
                            token.push('\\');
                        } else {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Invalid escape sequence: \\{}", c),
                            ));
                        }
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid escape sequence: \\ at end of line",
                        ));
                    }
                }
                // character literal end
                else if c == '\'' {
                    token.push(c); // push the last quote
                                   // TODO: at the moment `💖` is invalid and reported as `'\u{1f496}'` instead of `💖`
                    if token.len() != 3 {
                        let error_message = format!("ERROR invalid character literal `{}`", token);
                        print_compilation_message(
                            (path.clone(), line_num, col_num),
                            error_message.as_str(),
                        )?;
                        std::process::exit(1);
                    };
                    if line.len() > 0 && !line.starts_with(" ") {
                        let error_message =
                            format!("ERROR tokens should be separated by whitespace `{}`", token);
                        print_compilation_message(
                            (path.clone(), line_num, col_num),
                            error_message.as_str(),
                        )?;
                        std::process::exit(1);
                    };
                    result.push(((path.clone(), line_num, col_num), (token_type, token)));
                    token = "".to_string();
                    cur_column += 1;
                    break;
                }
                // continue building character literal
                else {
                    token.push(c);
                    cur_column += 1;
                }
            }
        }
        // parenthesis, braces
        else if c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' {
            if token.len() > 0 {
                if token.parse::<f64>().is_ok() {
                    token_type = TokenType::Uint;
                } else if KEYWORDS.contains_key(&token as &str) {
                    token_type = TokenType::Builtin;
                } else {
                    token_type = TokenType::Identifier;
                }
                result.push(((path.clone(), line_num, col_num), (token_type, token)));
                token = "".to_string();
            }
            token.push(c);
            col_num = cur_column;
            token_type = TokenType::Builtin;
            result.push(((path.clone(), line_num, col_num), (token_type, token)));
            cur_column += 1;
            token = "".to_string();
        }
        // whitespace marks end of token
        else if c.is_whitespace() {
            if token.parse::<f64>().is_ok() {
                token_type = TokenType::Uint;
            } else if KEYWORDS.contains_key(&token as &str) {
                token_type = TokenType::Builtin;
            } else {
                token_type = TokenType::Identifier;
            }

            result.push(((path.clone(), line_num, col_num), (token_type, token)));
            token = "".to_string();
            cur_column += 1;
        }
        // start or continue building the token
        else {
            if token.len() == 0 {
                col_num = cur_column;
            }
            token.push(c);
            cur_column += 1;
        }
    }

    if token.matches("\"").count() == 1 {
        let error_message = format!("ERROR invalid string literal `{}`", token);
        print_compilation_message((path.clone(), line_num, col_num), error_message.as_str())?;
        std::process::exit(1);
    };
    if token.matches("'").count() == 1 {
        let error_message = format!("ERROR invalid character literal `{}`", token);
        print_compilation_message((path.clone(), line_num, col_num), error_message.as_str())?;
        std::process::exit(1);
    };
    // push last token on the line
    if token.len() > 0 {
        if token.parse::<f64>().is_ok() {
            token_type = TokenType::Uint;
        } else if KEYWORDS.contains_key(&token as &str) {
            token_type = TokenType::Builtin;
        } else {
            token_type = TokenType::Identifier;
        }

        result.push(((path.clone(), line_num, col_num), (token_type, token)));
    }
    Ok(result)
}

fn load_tokens(
    path: &PathBuf,
    debug_level: usize,
) -> std::io::Result<Vec<((PathBuf, usize, usize), (TokenType, String))>> {
    if !fs::metadata(path).is_ok() {
        eprintln!("ERROR input file `{}` not found", path.as_path().file_name().unwrap().to_str().unwrap());
        std::process::exit(1);
    };
    if !fs::metadata(path)?.is_file() {
        eprintln!("ERROR input file `{}` not a file", path.as_path().file_name().unwrap().to_str().unwrap());
        std::process::exit(1);
    };
    let contents = std::fs::read_to_string(path)?;
    let lines: Vec<(usize, String)> = contents
        .lines()
        .enumerate()
        .map(|(line_number, line)| {
            let line = line
                .split(';')
                .next()
                .unwrap()
                .to_string()
                .trim_end()
                .to_string();
            (line_number, line)
        })
        .filter(|(_, line)| !line.is_empty())
        .collect();
    let tokens = lines
        .iter()
        .flat_map(|(line_number, line)| parse_line(&path, *line_number, line).unwrap())
        .collect::<Vec<_>>();
    if debug_level > 3 {
        println!("load_tokens(): \n{:?}\n", tokens.clone());
    }
    if tokens.len() == 0 {
        eprintln!("{}:0:0: ERROR empty input file", path.as_path().file_name().unwrap().to_str().unwrap());
        std::process::exit(1);
    }
    Ok(tokens)
}
fn main() {
    let args = Args::parse();
    let assembler = match args.assembler {
        Some(Assembler::Fasm) => Assembler::Fasm,
        Some(Assembler::Nasm) => Assembler::Nasm,
        None => Assembler::Fasm,
    };
    let debug_level = args.debug_level.unwrap_or_default();
    let generate_debug_symbols = match args.generate_debug_symbols {
        true => true,
        false => false,
    };
    let output_file = match args.output_file {
        Some(f) => f,
        None => "".to_string(),
    };
    let input_file = args.input_file;
    if assembler == Assembler::Fasm && generate_debug_symbols == true {
        let mut cmd = Args::command();
        cmd.error(ErrorKind::ArgumentConflict, "-g is not supported by fasm")
            .exit();
    }
    let asm_file = if output_file == "" {
        format!("{}.asm", input_file.file_stem().unwrap().to_str().unwrap())
    } else {
        format!("{}.asm", output_file)
    };
    let o_file = if output_file == "" {
        format!("{}.o", input_file.file_stem().unwrap().to_str().unwrap())
    } else {
        format!("{}.o", output_file)
    };
    let output_file = if output_file == "" {
        format!("{}", input_file.file_stem().unwrap().to_str().unwrap())
    } else {
        format!("{}", output_file)
    };
    let tokens = load_tokens(&input_file, debug_level).unwrap();
    let include_depth: Vec<PathBuf> = Vec::new();
    let tokens_post_include = preprocessor_include(tokens, include_depth, debug_level).unwrap();
    let tokens_post_define = preprocessor_define(tokens_post_include, debug_level).unwrap();
    let (tokens_post_function, function_defs) =
        preprocessor_function(tokens_post_define, debug_level).unwrap();
    let (tokens_post_parse, function_defs) =
        parse_tokens(tokens_post_function, function_defs, debug_level).unwrap();
    let (program, function_defs, required_labels) =
        locate_blocks(tokens_post_parse, function_defs, debug_level).unwrap();
    compile_to_elf64_asm(
        program,
        function_defs,
        required_labels,
        PathBuf::from(asm_file.clone()),
        assembler,
        debug_level,
    ).unwrap();
    let assembler_command = match assembler {
        Assembler::Fasm => {
            let mut assembler_command = Command::new("fasm");
            assembler_command.arg(asm_file.clone()).arg(o_file.clone());
            assembler_command
        }
        Assembler::Nasm => {
            let mut assembler_command = Command::new("nasm");
            if generate_debug_symbols {
                assembler_command.arg("-g");
            };
            assembler_command
                .arg("-felf64")
                .arg("-o")
                .arg(o_file.clone())
                .arg(asm_file.clone());
            assembler_command
        }
    };
    run_cmd(assembler_command, debug_level).unwrap();
    let mut ld_command = Command::new("ld");
    ld_command
        .arg("-o")
        .arg(output_file.clone())
        .arg(o_file.clone());
    run_cmd(ld_command, debug_level).unwrap();
    let mut cleanup_command = Command::new("rm");
    cleanup_command.arg(o_file);
    if debug_level < 1 {
        cleanup_command.arg(asm_file);
    };
    run_cmd(cleanup_command, debug_level).unwrap();
}
