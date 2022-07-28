# northc
`northc` is a compiler for the toy programming language *north*.

`northc` is written in rust and builds on x86_64 Linux. It compiles `*.north` source code to assembly which targets the Linux x86_64 platform. The generated assembly is assembled to machine code by flat assembler ([fasm](https://flatassembler.net/)). Ensure that `fasm` is in your `$PATH` before running `northc`. Optionally, the Netwide Assembler ([nasm](https://www.nasm.us/)) may be used by specifying the `-a nasm` command line option.

## Quick Start

#### Install an assembler
fasm (recommended): 
  - Available at https://flatassembler.net/ or via your package manager.

nasm (required to generate executables with debug symbols):
  - Available at https://www.nasm.us/ or via your package manager.

#### Install Rust
```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
#### Build the project
```
$ cargo build
```
#### Compile and run some code
```
$ ./target/debug/northc ./examples/isprime.north
$ ./isprime 59
yes, it's a prime!
```

## Dependencies
- a modern Linux x86_64 system
- rustc and cargo
- flat assembler (and optionally Netwide Assember)

## Compiling source code with `northc`

### `northc` Usage
```
$ ./target/debug/northc --help
northc 0.1.0

USAGE:
    northc [OPTIONS] <INPUT_FILE>

ARGS:
    <INPUT_FILE>    Path to input file to compile

OPTIONS:
    -a <NAME>               Specify assembler to use [possible values: fasm, nasm]
    -g                      Generate an executable containing debug symbols (nasm only)
    -d <LEVEL>              Use compliation debug mode [possible values: 0, 1, 2, 3]
    -o <OUTPUT_FILE>        Provide an alternative filename for the generated executable
    -h, --help              Print help information
    -V, --version           Print version information
```

## Testing the project
`*.north` source code files that test the `northc` compiler in various ways are located in `./tests` 

All `*.north` files in `./tests` can be compiled and the resultant output from the generated exectuables verified against the validation data in `./_test_artifacts` by running:
```
$ cargo test
```

### cargo-case
`cargo-case` extends rust's `cargo` command. It provides a `case` subcommand for updating the project's integration test validation data.

### Using `cargo case` to update validation data
Ensure you've built the project with `cargo build -r`. Put `./target/release/cargo-case` somewhere in your `$PATH`. It might be easier to use a symlink: 
```
$ ln -s ~/projects/north/target/release/cargo-case ~/bin/cargo-case
```
Then run: 
```
$ cargo case help
```
### Usage
```
$ cargo case help
Usage: cargo case [COMMAND]
  Run or update the integration tests. The default [COMMAND] is `run`

  COMMAND:
    run (synonym: test) [TARGET]:
      Run the test on [TARGET]: either a `*.north` file or a folder
      containing `*.north` files. The default [TARGET] is `./tests/`

    update (synonym: record) [SUBCOMMAND]
      Update `input` or `output` of the integration tests
      The default [SUBCOMMAND] is `output`

      SUBCOMMAND:
        input <TARGET> [ARGV]
          Update the input of the <TARGET>. The <TARGET> can only be a
          `*.north` file. [ARGV] is an optional list of arguments to
          pass to <TARGET>

        output [TARGET]
          Update the output of the [TARGET]. The [TARGET] is either a
          `*.north` file or folder with `*.north` files
          The default [TARGET] is `./tests/`

    help (synonyms: --help, -h)
      Print this help message and exit
```

# north Language Reference
*north* is toy programming language inspired by stack based concatenative programming languages like [Forth](https://forth-standard.org/). It's a work in progress and subject to major change.

## Literals

### String

### Character

### Unsigned integer

## Stack operations
| operator | description |
| -------  | ----------- |
| `dup`    | (x) -> (x, x) |
| `2dup`   | (x, y) -> (x, y, x, y) |
| `drop`   | (x, y) -> (x) |
| `2drop`  | (x, y, z) -> (x) |
| `over`   | (x, y) -> (x, y, x) |
| `2over`  | (w, x, y, z) -> (w, x, y, z, w, x) |
| `swap`   | (x, y) -> (y, x) |
| `2swap`  | (w, x, y, z) -> (y, z, w, x) |
| `rot`    | (x, y, z) -> (y, z, x) |
| `dupnz`  | (x, y) -> (x, y, y) ∀ y ≠ 0 |

## Arithmetic operations
| operator | description |
| -------- | ----------- |
| `+`      | (x, y) -> (x + y) |
| `-`      | (x, y) -> (x - y) |
| `*`      | (x, y) -> (x * y) |
| `/`      | (x, y) -> (x / y) |
| `%`      | (x, y) -> (x % y) |

## Bitwise operations
| operator | description |
| -------- | ----------- |
| `&`      | (x, y) -> (x & y) |
| `\|`      | (x, y) -> (x \| y) |
| `~`      | (x)    -> (~x) |
| `^`      | (x, y) -> (x ^ y) |
| `<<`     | (x, y) -> (x << y) |
| `>>`     | (x, y) -> (x >> y) |

## Comparisons
| operator | description |
| -------- | ----------- |
| `max`      | (x, y) -> (x), ∀ x > y |
| `min`      | (x, y) -> (x), ∀ x < y |
| `=`        | (x, y) -> (1) ∀ x = y |
| `!=`       | (x, y) -> (1) ∀ x ≠ y |
| `>`        | (x, y) -> (1) ∀ x > y |
| `>=`       | (x, y) -> (1) ∀ x >= y |
| `<`        | (x, y) -> (1) ∀ x < y |
| `<=`       | (x, y) -> (1) ∀ x <= y |

## Control flow

### while loop
```
while (condition) do
  (while body)
done
```
### if condition
```
(condition) if
   (if body)
else
   (else body)
endif
```

## Working with global memory

## Interacting with Linux System

## Preprocessor directives

## Functions

## Syntax highlighting
see [`./misc`](./misc) (support for `vim` and `vscode`)

## Project License
[The Unlicense](https://unlicense.org/)
