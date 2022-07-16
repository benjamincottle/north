use easy_process::{self};
use std::fs::{self, File};
use std::path::{PathBuf, Path};
use std::io::{self, BufRead, Read, Write};

#[derive(Debug)]
struct TestCase {
    argv: Vec<Vec<u8>>,
    stdin: Vec<u8>,
    return_code: i32,
    stdout: Vec<u8>, 
    stderr: Vec<u8>,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase {
            argv: vec![],
            stdin: vec![],
            return_code: 0i32,
            stdout: vec![],
            stderr: vec![], 
        }
    }
}

#[derive(Debug, Clone)]
struct RunStats {
    passed: i32,
    failed: i32,
    failed_files: Vec<String>,
}

impl Default for RunStats {
    fn default() -> RunStats {
        RunStats {
            passed: 0,
            failed: 0,
            failed_files: vec![],
        }
    }
}

fn read_int_field(input_data: Vec<u8>, field_name: &str) -> (Vec<u8>, i32) {
    let mut cursor = io::Cursor::new(input_data);    
    let mut buf = vec![];
    cursor.read_until(b'\n', &mut buf).unwrap();
    let mut line = buf.clone();
    buf.clear();
    line.pop();
    let field = [":i ".as_bytes(), field_name.as_bytes(), " ".as_bytes()].concat();
    let field_len = field.len();
    let (_, right) = line.split_at(field_len);
    let int: i32 = right.iter().map(|&x| x as char).collect::<String>().parse().unwrap();
    cursor.read_to_end(&mut buf).unwrap();
    let test_case_data = buf.clone();
    buf.clear();
    (test_case_data, int)
}

fn write_int_field(mut f: &File, name: &[u8], value: i32) {
    f.write(b":i ").unwrap();
    f.write(name).unwrap();
    f.write(b" ").unwrap();
    f.write(value.to_string().as_bytes()).unwrap();
    f.write(b"\n").unwrap();
}

fn read_blob_field(input_data: Vec<u8>, field_name: &str) -> (Vec<u8>, Vec<u8>) {
    let (test_case_data, field_size) = read_int_field(input_data.clone(), field_name);
    let mut cursor = io::Cursor::new(test_case_data);
    let mut buf = vec![];
    let mut field_buf = vec![0; field_size as usize];
    cursor.read_exact(&mut field_buf).unwrap();
    let blob = field_buf.clone(); 
    let mut nl_buf = vec![0; 1];
    cursor.read_exact(&mut nl_buf).unwrap();
    field_buf.clear();
    cursor.read_to_end(&mut buf).unwrap();
    let test_case_data = buf.clone();
    buf.clear();
    (test_case_data, blob)
}

fn write_blob_field(mut f: &File, name: &[u8], blob: &[u8]) {
    f.write(b":b ").unwrap();
    f.write(name).unwrap();
    f.write(b" ").unwrap();
    f.write(blob.len().to_string().as_bytes()).unwrap();
    f.write(b"\n").unwrap();
    f.write(blob).unwrap();
    f.write(b"\n").unwrap();
}

fn load_test_case(file_path: &str) -> Option<TestCase> {
    if !Path::new(file_path).exists() {
        return Some(TestCase::default());
    }
    let test_case_data = &fs::read(file_path).unwrap();
    let (mut test_case_data, argc) = read_int_field(test_case_data.clone(), "argc");
    let mut argv: Vec<Vec<u8>> = Vec::new();
    let mut blob: Vec<u8>;
    for index in 0..argc {
        (test_case_data, blob) = read_blob_field(test_case_data.clone(), format!("arg{}", index).as_str());
        argv.push(blob);
    }
    let (test_case_data, stdin) = read_blob_field(test_case_data.clone(), "stdin");
    let (test_case_data, return_code) = read_int_field(test_case_data.clone(), "returncode");
    let (test_case_data, stdout) = read_blob_field(test_case_data.clone(), "stdout");
    let (_test_case_data, stderr) = read_blob_field(test_case_data.clone(), "stderr");
    Some(TestCase {
        argv,
        stdin,
        return_code,
        stdout,
        stderr,
    })
}

fn save_test_case(file_path: &str, test_case: &TestCase) {
    let mut f = fs::File::create(file_path).unwrap();
    write_int_field(&mut f, b"argc", test_case.argv.len() as i32);
    for index in 0..test_case.argv.len() {
        write_blob_field(&mut f, format!("arg{}", index).as_bytes(), &test_case.argv[index]);
    }
    write_blob_field(&mut f, b"stdin", &test_case.stdin);
    write_int_field(&mut f, b"returncode", test_case.return_code);
    write_blob_field(&mut f, b"stdout", &test_case.stdout);
    write_blob_field(&mut f, b"stderr", &test_case.stderr);
}

fn update_input_for_file(file_path: &str, argv: &Vec<String>) {
    let test_data_folder = "./_test_artifacts";
    let file_path = Path::new(file_path);
    let parent = Path::new(file_path).parent().unwrap().to_str().unwrap();
    let dirname = test_data_folder.to_owned() + "/" + parent;
    let dirname = Path::new(&dirname).components().map(|x| x.as_os_str().to_str().unwrap()).collect::<Vec<&str>>().join("/");
    fs::create_dir_all(Path::new(&dirname)).unwrap();
    let tc_path = dirname.clone() + "/" + file_path.file_stem().unwrap().to_str().unwrap() + ".txt";
    let argv = argv.iter().map(|x| x.as_bytes().to_vec()).collect::<Vec<Vec<u8>>>();
    let tc = load_test_case(&tc_path).unwrap_or_default();
    println!("[INFO] Provide the stdin for the test case. Press ^D when you are done...");
    let mut new_stdin: String = String::new();
    io::stdin().read_to_string(&mut new_stdin).unwrap();
    let new_stdin = new_stdin.as_bytes().to_vec();
    println!("\n[INFO] Saving input to {}", tc_path);
    save_test_case(&tc_path, &TestCase {argv: argv, stdin: new_stdin, return_code: tc.return_code, stdout: tc.stdout, stderr: tc.stderr});
}

fn update_output_for_file(file_path: &str) {
    let test_data_folder = "./_test_artifacts";
    let file_path = Path::new(file_path);
    let parent = Path::new(file_path).parent().unwrap().to_str().unwrap();
    let dirname = test_data_folder.to_owned() + "/" + parent;
    let case_name = file_path.file_stem().unwrap().to_str().unwrap();
    let dirname = Path::new(&dirname).components().map(|x| x.as_os_str().to_str().unwrap()).collect::<Vec<&str>>().join("/");
    fs::create_dir_all(Path::new(&dirname)).unwrap();
    let tc_path = dirname.clone() + "/" + file_path.file_stem().unwrap().to_str().unwrap() + ".txt";
    let tc = load_test_case(&tc_path).unwrap_or_default();
    let mut output_stdout: Vec<u8>;
    let mut output_stderr: Vec<u8>;
    let mut output_code: i32;
    let compile_cmd = "./target/debug/northc ".to_owned() + "-o " + case_name + " " + file_path.to_str().unwrap();
    let compile_cmd = easy_process::run(&compile_cmd);
    match compile_cmd {
        Ok(output) => {
            output_code = 0;
            output_stdout = output.stdout.as_bytes().to_vec();
            output_stderr = output.stderr.as_bytes().to_vec();
        },
        Err(easy_process::Error::Io(io_err)) => panic!("unexpected I/O Error: {:?}", io_err),
        Err(easy_process::Error::Failure(ex, output)) => {
            output_code = ex.code().unwrap();
            output_stdout = output.stdout.as_bytes().to_vec();
            output_stderr = output.stderr.as_bytes().to_vec();
        }
    }
    if output_code == 0 {
        let argv = tc.argv.iter().map(|x| x.iter().map(|&x| x as char).collect::<String>()).collect::<Vec<String>>();
        let execute_cmd = "./".to_owned() + &case_name + " " + &argv.join(" ");
        let execute_cmd = easy_process::run_with_stdin(&execute_cmd, |stdin| {
            std::io::Write::write_all(stdin, &tc.stdin)?;
            easy_process::Result::Ok(())
        });
        match execute_cmd {
            Ok(output) => {
                output_code = 0;
                output_stdout = output.stdout.as_bytes().to_vec();
                output_stderr = output.stderr.as_bytes().to_vec();
            },
            Err(easy_process::Error::Io(io_err)) => panic!("unexpected I/O Error: {:?}", io_err),
            Err(easy_process::Error::Failure(ex, output)) => {
                output_code = ex.code().unwrap();
                output_stdout = output.stdout.as_bytes().to_vec();
                output_stderr = output.stderr.as_bytes().to_vec();
            }
        }
        fs::remove_file("./".to_owned() + &case_name).unwrap();
    };
    println!("[INFO] Saving output to {}", tc_path);
    save_test_case(&tc_path, &TestCase {argv: tc.argv, stdin: tc.stdin, return_code: output_code, stdout: output_stdout, stderr: output_stderr});
}
  
fn run_test_case(case_name: &str, stats: &mut RunStats) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_path = "./_test_artifacts/tests/".to_string();
    file_path.push_str(case_name);
    file_path.push_str(".txt");
    let test_case = load_test_case(file_path.as_str()).unwrap();
    let input_file = PathBuf::from("./tests/".to_owned() + case_name + ".north");
    let mut output_stdout: Vec<u8>;
    let mut output_stderr: Vec<u8>;
    let mut output_code: i32;
    let compile_cmd = "./target/debug/northc ".to_owned() + "-o " + case_name + " " + input_file.to_str().unwrap();
    let compile_cmd = easy_process::run(&compile_cmd);
    match compile_cmd {
        Ok(output) => {
            output_code = 0;
            output_stdout = output.stdout.as_bytes().to_vec();
            output_stderr = output.stderr.as_bytes().to_vec();
        },
        Err(easy_process::Error::Io(io_err)) => panic!("unexpected I/O Error: {:?}", io_err),
        Err(easy_process::Error::Failure(ex, output)) => {
            output_code = ex.code().unwrap();
            output_stdout = output.stdout.as_bytes().to_vec();
            output_stderr = output.stderr.as_bytes().to_vec();
        }
    }
    if output_code != 0 {
        if output_code != test_case.return_code || output_stdout != test_case.stdout || output_stderr != test_case.stderr {
            stats.failed += 1;
            stats.failed_files.push(case_name.to_string());
        } else {
            stats.passed += 1;
        }
    } else {
        let argv = test_case.argv.iter().map(|x| x.iter().map(|&x| x as char).collect::<String>()).collect::<Vec<String>>();
        let execute_cmd = "./".to_owned() + &case_name + " " + &argv.join(" ");
        let execute_cmd = easy_process::run_with_stdin(&execute_cmd, |stdin| {
            std::io::Write::write_all(stdin, &test_case.stdin)?;
            easy_process::Result::Ok(())
        });
        match execute_cmd {
            Ok(output) => {
                output_code = 0;
                output_stdout = output.stdout.as_bytes().to_vec();
                output_stderr = output.stderr.as_bytes().to_vec();
            },
            Err(easy_process::Error::Io(io_err)) => panic!("unexpected I/O Error: {:?}", io_err),
            Err(easy_process::Error::Failure(ex, output)) => {
                output_code = ex.code().unwrap();
                output_stdout = output.stdout.as_bytes().to_vec();
                output_stderr = output.stderr.as_bytes().to_vec();
            }
        }
        fs::remove_file("./".to_owned() + &case_name).unwrap();
        if output_code != test_case.return_code || output_stdout != test_case.stdout || output_stderr != test_case.stderr {
            stats.failed += 1;
            stats.failed_files.push(case_name.to_string());
        } else {
            stats.passed += 1;
        }
    };
    Ok(())
}

fn update_output_for_folder(folder: &str) {
    for entry in fs::read_dir(folder).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() && entry.path().to_str().unwrap().ends_with(".north") {
            update_output_for_file(entry.path().to_str().unwrap());
        }
    }
}

fn run_test_for_folder(folder: &str, stats: &mut RunStats) {
    for entry in fs::read_dir(folder).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() && entry.path().to_str().unwrap().ends_with(".north") {
            run_test_case(entry.path().file_stem().unwrap().to_str().unwrap(), stats).unwrap();
        }
    }
    if stats.failed != 0 {
        println!("Passed: {}, Failed: {}", stats.passed, stats.failed);
        println!("Failed tests: {}", stats.failed_files.join(", "));
        println!("Run cargo test for more details");
    }
}

fn usage() {
    println!("Usage: cargo case [COMMAND]");
    println!("  Run or update the integration tests. The default [COMMAND] is `run`");
    println!();
    println!("  COMMAND:");
    println!("    run (synonym: test) [TARGET]:");
    println!("      Run the test on [TARGET]: either a `*.north` file or a folder");
    println!("      containing `*.north` files. The default [TARGET] is `./tests/`");
    println!();
    println!("    update (synonym: record) [SUBCOMMAND]");
    println!("      Update `input` or `output` of the integration tests");
    println!("      The default [SUBCOMMAND] is `output`");
    println!();
    println!("      SUBCOMMAND:");
    println!("        input <TARGET> [ARGV]");
    println!("          Update the input of the <TARGET>. The <TARGET> can only be a");
    println!("          `*.north` file. [ARGV] is an optional list of arguments to"); 
    println!("          pass to <TARGET>");
    println!();
    println!("        output [TARGET]");
    println!("          Update the output of the [TARGET]. The [TARGET] is either a");
    println!("          `*.north` file or folder with `*.north` files");
    println!("          The default [TARGET] is `./tests/`");
    println!();
    println!("    help (synonyms: --help, -h)");
    println!("      Print this help message and exit");
}

fn main() {
    let mut argv: Vec<String> = std::env::args().collect();
    argv.remove(0);
    let mut command = "run".to_owned();
    let mut subcommand;
    if argv.len() > 0 {
        if argv[0] != "case".to_owned() {
            println!("[ERROR] cargo-case is designed to be run by cargo"); 
            println!();
            println!("Put `cargo-case` in your `$PATH` (like ~/bin/) and run via `cargo case`"); 
            println!("from inside the north project directory instead.");
            println!();
            usage();
            std::process::exit(1);
        } else {
            argv.remove(0);
        }
     }
    if argv.len() > 0 {
       command = argv.remove(0)
    }
    if command == "update".to_owned() || command == "record".to_owned() {
        subcommand = "output".to_owned();
        if argv.len() > 0 {
            subcommand = argv.remove(0);
        }
        if subcommand == "output".to_owned() {
            let mut target = "./tests".to_owned();
            if argv.len() > 0 {
                target = argv.remove(0);
            }
            if fs::metadata(Path::new(&target)).unwrap().is_dir() {
                update_output_for_folder(&target);
            } else if fs::metadata(Path::new(&target)).unwrap().is_file() {
                update_output_for_file(&target);
            } else {
                panic!("{} is not a file or directory\n", target);
            }
        } else if subcommand == "input".to_owned() {
            if argv.len() == 0 {
                println!("[ERROR] no file is provided for `{} {}` command", command, subcommand);
                println!();
                usage();
                std::process::exit(1);
            }
            let target = argv.remove(0);
            update_input_for_file(&target, &argv)
        }
    } else if command == "run".to_owned() || command == "test".to_owned() {
        let mut stats = RunStats::default();
        let mut target = "./tests".to_owned();
        if argv.len() > 0 {
            target = argv.remove(0);
        }
        if Path::new(&target).is_dir() {
            run_test_for_folder(&target, &mut stats);
        } else if Path::new(&target).is_file() {
            run_test_case(Path::new(&target).file_stem().unwrap().to_str().unwrap(), &mut stats).unwrap();
        } else {
            println!("[ERROR] {} is not a file or directory", target);
            println!();
            usage();
            std::process::exit(1);

        }
    } else if command == "help".to_owned() || command == "--help".to_owned() || command == "-h".to_owned() {
        usage();
        std::process::exit(0);
    } else {
        println!("[ERROR] unknown command: {}", command);
        usage();
        std::process::exit(1);
    }
}
