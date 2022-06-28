#!/usr/bin/env python3

from cmath import e
import sys
import os
from os import path
import subprocess
import shlex
from tabnanny import verbose
from typing import List, BinaryIO, Tuple, Optional
from dataclasses import dataclass, field


NORTH_EXT = '.north'
TEST_DATA_FOLDER = "_test_artifacts"   # no trailing slash or preceding slash

def cmd_run_echoed(cmd, **kwargs):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.run(cmd, **kwargs)


def read_blob_field(f: BinaryIO, name: bytes) -> bytes:
    line = f.readline()
    field = b':b ' + name + b' '
    assert line.startswith(field)
    assert line.endswith(b'\n')
    size = int(line[len(field):-1])
    blob = f.read(size)
    assert f.read(1) == b'\n'
    return blob


def read_int_field(f: BinaryIO, name: bytes) -> int:
    line = f.readline()
    field = b':i ' + name + b' '
    assert line.startswith(field)
    assert line.endswith(b'\n')
    return int(line[len(field):-1])


def write_int_field(f: BinaryIO, name: bytes, value: int):
    f.write(b':i %s %d\n' % (name, value))


def write_blob_field(f: BinaryIO, name: bytes, blob: bytes):
    f.write(b':b %s %d\n' % (name, len(blob)))
    f.write(blob)
    f.write(b'\n')


@dataclass
class TestCase:
    argv: List[str]
    stdin: bytes
    returncode: int
    stdout: bytes
    stderr: bytes


DEFAULT_TEST_CASE=TestCase(argv=[], stdin=bytes(), returncode=0, stdout=bytes(), stderr=bytes())


def load_test_case(file_path: str) -> Optional[TestCase]:
    try:
        with open(file_path, "rb") as f:
            argv = []
            argc = read_int_field(f, b'argc')
            for index in range(argc):
                argv.append(read_blob_field(f, b'arg%d' % index).decode('utf-8'))
            stdin = read_blob_field(f, b'stdin')
            returncode = read_int_field(f, b'returncode')
            stdout = read_blob_field(f, b'stdout')
            stderr = read_blob_field(f, b'stderr')
            return TestCase(argv, stdin, returncode, stdout, stderr)
    except FileNotFoundError:
        return None


def save_test_case(file_path: str,
                   argv: List[str], stdin: bytes,
                   returncode: int, stdout: bytes, stderr: bytes):
    with open(file_path, "wb") as f:
        write_int_field(f, b'argc', len(argv))
        for index, arg in enumerate(argv):
            write_blob_field(f, b'arg%d' % index, arg.encode('utf-8'))
        write_blob_field(f, b'stdin', stdin)
        write_int_field(f, b'returncode', returncode)
        write_blob_field(f, b'stdout', stdout)
        write_blob_field(f, b'stderr', stderr)


@dataclass
class RunStats:
    passed: int = 0
    failed: int = 0
    ignored: int = 0
    failed_files: List[str] = field(default_factory=list)
    ignored_files: List[str] = field(default_factory=list)

def create_folder(folder: str):
    if not path.exists(folder):
        os.makedirs(folder)


def run_test_for_file(file_path: str, stats: RunStats = RunStats()):
    assert path.isfile(file_path)
    assert file_path.endswith(NORTH_EXT)
    create_folder(TEST_DATA_FOLDER + "/" + (path.dirname(file_path)))
    print('[INFO] Testing %s' % file_path)
    tc_path = TEST_DATA_FOLDER + "/" + path.dirname(file_path) + "/" + path.basename(file_path)[:-len(NORTH_EXT)] + ".txt"
    tc = load_test_case(tc_path)

    error = False
    ignored = False

    if tc is not None:
        if len(tc.argv) != 0:
            com = cmd_run_echoed([sys.executable, "north.py", "-a", assembler, "-r", "-rA", *tc.argv, "-o", "output", file_path], input=tc.stdin, capture_output=True)
        else:
            com = cmd_run_echoed([sys.executable, "north.py", "-a", assembler, "-r", "-o", "output", file_path], input=tc.stdin, capture_output=True)
        if com.returncode != tc.returncode or com.stdout != tc.stdout or com.stderr != tc.stderr:
            print("[ERROR] Unexpected output ------------------------------------------")
            print("  >> Expected:")
            print("    return code: %s" % tc.returncode)
            print("    stdout: \n%s" % tc.stdout.decode("utf-8"))
            print("    stderr: \n%s" % tc.stderr.decode("utf-8"))
            print("  >> Actual:")
            print("    return code: %s" % com.returncode)
            print("    stdout: \n%s" % com.stdout.decode("utf-8"))
            print("    stderr: \n%s" % com.stderr.decode("utf-8"))
            print("--------------------------------------------------------------------")
            error = True
            stats.failed += 1
        else:
            stats.passed += 1
    else:
        print('[WARNING] Could not find any input/output data for %s. Ignoring testing. Only checking if it compiles.' % file_path)
        com = cmd_run_echoed([sys.executable, "north.py", "-a", assembler, "-o", "output", file_path], capture_output=True)
        if com.returncode != 0:
            error = True
            stats.failed += 1
        ignored = True
        stats.ignored += 1

    if error:
        stats.failed_files.append(file_path)
    if ignored:
        stats.ignored_files.append(file_path)


def run_test_for_folder(folder: str):
    stats = RunStats()
    for entry in os.scandir(folder):
        if entry.is_file() and entry.path.endswith(NORTH_EXT):
            run_test_for_file(entry.path, stats)
    print()
    print(" Passed: %d, Failed: %d, Ignored: %d" % (stats.passed, stats.failed, stats.ignored))
    print()
    if stats.failed != 0:
        print("Failed files:")
        for failed_file in stats.failed_files:
            print(f"{failed_file}")
        print()
    if stats.ignored != 0:
        print("Ignored files:")
        for ignored_file in stats.ignored_files:
            print(f"{ignored_file}")
        print()
        exit(1)

def update_input_for_file(file_path: str, argv: List[str]):
    assert file_path.endswith(NORTH_EXT)
    create_folder(TEST_DATA_FOLDER + "/" + (path.dirname(file_path)))
    tc_path = TEST_DATA_FOLDER + "/" + path.dirname(file_path) + "/" + path.basename(file_path)[:-len(NORTH_EXT)] + ".txt"   
    tc = load_test_case(tc_path) or DEFAULT_TEST_CASE

    print("[INFO] Provide the stdin for the test case. Press ^D when you are done...")

    stdin = sys.stdin.buffer.read()

    print("[INFO] Saving input to %s" % tc_path)
    save_test_case(tc_path,
                   argv, stdin,
                   tc.returncode, tc.stdout, tc.stderr)


def update_output_for_file(file_path: str):
    create_folder(TEST_DATA_FOLDER + "/" + (path.dirname(file_path)))
    tc_path = TEST_DATA_FOLDER + "/" + path.dirname(file_path) + "/" + path.basename(file_path)[:-len(NORTH_EXT)] + ".txt"
    tc = load_test_case(tc_path) or DEFAULT_TEST_CASE


    if len(tc.argv) != 0:
        output = cmd_run_echoed([sys.executable, "north.py", "-a", assembler, "-r", "-rA", *tc.argv, "-o", "output", file_path], input=tc.stdin, capture_output=True)
    else:
        output = cmd_run_echoed([sys.executable, "north.py", "-a", assembler, "-r", "-o", "output", file_path], input=tc.stdin, capture_output=True)
    print("[INFO] Saving output to %s" % tc_path)
    save_test_case(tc_path,
                   tc.argv, tc.stdin,
                   output.returncode, output.stdout, output.stderr)


def update_output_for_folder(folder: str):
    for entry in os.scandir(folder):
        if entry.is_file() and entry.path.endswith(NORTH_EXT):
            update_output_for_file(entry.path)


def usage(exe_name: str):
    print("Usage: ./test.py [ASSEMBLER] [SUBCOMMAND]")
    print("  Run or update the tests. The default [SUBCOMMAND] is 'run'.")
    print()
    print("  ASSEMBLER:")
    print("    Optionally specify the assembler to use. Valid options are fasm and nasm. Default is fasm.")  
    print()
    print("  SUBCOMMAND:")
    print("    run [TARGET]")
    print("      Run the test on the [TARGET]. The [TARGET] is either a *.north file or ")
    print("      folder with *.north files. The default [TARGET] is './tests/'.")
    print()
    print("    update [SUBSUBCOMMAND]")
    print("      Update the input or output of the tests.")
    print("      The default [SUBSUBCOMMAND] is 'output'")
    print()
    print("      SUBSUBCOMMAND:")
    print("        input <TARGET> [ARGV]")
    print("          Update the input of the <TARGET>. The <TARGET> can only be")
    print("          a *.north file. [ARGV] is an optional list of arguments to pass to the program.")
    print()
    print("        output [TARGET]")
    print("          Update the output of the [TARGET]. The [TARGET] is either a *.north")
    print("          file or folder with *.north files. The default [TARGET] is")
    print("          './tests/'")
    print()
    print("    full (synonyms: all)")
    print("      Check ./tests/ and ./examples/")
    print()
    print("    help")
    print("      Print this message to stdout and exit with 0 code.")

if __name__ == '__main__':
    exe_name, *argv = sys.argv
    subcommand = "run"
    assembler = "fasm"

    if len(argv) > 0:
        subcommand, *argv = argv

    if subcommand == "fasm" or subcommand == "nasm":
        assembler = subcommand
        subcommand = "run"
        if len(argv) > 0:
            subcommand, *argv = argv
    
    if subcommand == 'update' or subcommand == 'record':
        subsubcommand = 'output'
        if len(argv) > 0:
            subsubcommand, *argv = argv

        if subsubcommand == 'output':
            target = './tests/'

            if len(argv) > 0:
                target, *argv = argv

            if path.isdir(target):
                update_output_for_folder(target)
            elif path.isfile(target):
                update_output_for_file(target)
            else:
                assert False, 'unreachable'
        elif subsubcommand == 'input':
            if len(argv) == 0:
                usage(exe_name)
                print("[ERROR] no file is provided for `%s %s` subcommand" % (subcommand, subsubcommand), file=sys.stderr)
                exit(1)
            file_path, *argv = argv
            update_input_for_file(file_path, argv)
        else:
            usage(exe_name)
            print("[ERROR] unknown subcommand `%s %s`. Available commands are `%s input` or `%s output`" % (subcommand, subsubcommand, subcommand, subcommand), file=sys.stderr)
            exit(1)
    elif subcommand == 'run' or subcommand == 'test':
        target = './tests/'

        if len(argv) > 0:
            target, *argv = argv

        if path.isdir(target):
            run_test_for_folder(target)
        elif path.isfile(target):
            run_test_for_file(target)
        else:
            # TODO: `./test.py run non-existing-file` fails with 'unreachable'
            assert False, 'unreachable'
    elif subcommand == 'full' or subcommand == 'all':
        run_test_for_folder('./tests/')
        run_test_for_folder('./examples/')
    elif subcommand == 'help':
        usage(exe_name)
    else:
        usage(exe_name)
        print("[ERROR] unknown subcommand `%s`" % subcommand, file=sys.stderr)
        exit(1);
