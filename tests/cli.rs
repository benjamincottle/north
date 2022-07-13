use subprocess::{Exec, Redirection, ExitStatus};
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::io::{self, BufRead, Read};
use pretty_assertions::{assert_eq, assert_ne};

macro_rules! function_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        // Find and cut the rest of the path
        match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        }
    }};
}

struct TestCase {
    argv: Vec<Vec<u8>>,
    stdin: Vec<u8>,
    return_code: subprocess::ExitStatus,
    stdout: Vec<u8>, 
    stderr: Vec<u8>,
}

fn read_int_field(input_data: Vec<u8>, field_name: &str) -> (Vec<u8>, u32) {
    let mut cursor = io::Cursor::new(input_data);    
    let mut buf = vec![];
    cursor.read_until(b'\n', &mut buf).unwrap();
    let mut line = buf.clone();
    buf.clear();
    line.pop();
    let field = [":i ".as_bytes(), field_name.as_bytes(), " ".as_bytes()].concat();
    let field_len = field.len();
    let (_, right) = line.split_at(field_len);
    let int: u32 = right.iter().map(|&x| x as char).collect::<String>().parse().unwrap();
    cursor.read_to_end(&mut buf).unwrap();
    let test_case_data = buf.clone();
    buf.clear();
    (test_case_data, int)
}

fn read_blob_field(input_data: Vec<u8>, field_name: &str) -> (Vec<u8>, Vec<u8>) {
    let (test_case_data, field_size) = read_int_field(input_data.clone(), field_name);
    let mut cursor = io::Cursor::new(test_case_data);
    let mut buf = vec![];
    let mut field_buf = vec![0; field_size as usize];
    cursor.read_exact(&mut field_buf).unwrap();
    let blob = field_buf.clone(); 
    cursor.read_until(b'\n', &mut field_buf).unwrap();
    field_buf.clear();
    cursor.read_to_end(&mut buf).unwrap();
    let test_case_data = buf.clone();
    buf.clear();
    (test_case_data, blob)
}

fn load_test_case(file_path: &str) -> Option<TestCase> {
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
    let return_code = ExitStatus::Exited(return_code);
    Some(TestCase {
        argv,
        stdin,
        return_code,
        stdout,
        stderr,
    })
}

fn run_test_case(case_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_path = "./_test_artifacts/tests/".to_string();
    file_path.push_str(case_name);
    file_path.push_str(".txt");
    let test_case = load_test_case(file_path.as_str()).unwrap();
    let input_file = PathBuf::from("./tests/".to_owned() + case_name + ".north");
    let compile_cmd = Exec::cmd("./target/debug/northc")
        .args(&["-o", case_name, input_file.to_str().unwrap()])
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Pipe)
        .capture()?;
    let compile_cmd_stdout = compile_cmd.stdout;
    let compile_cmd_stderr = compile_cmd.stderr;
    let compile_cmd_code = compile_cmd.exit_status;
    if !compile_cmd_code.success() {
        assert_eq!(true, predicate::eq(compile_cmd_code).eval(&test_case.return_code));
        assert_eq!(true, predicate::eq(compile_cmd_stdout).eval(&test_case.stdout));
        assert_eq!(true, predicate::eq(compile_cmd_stderr).eval(&test_case.stderr));
    } else {
        let argv = test_case.argv.iter().map(|x| x.iter().map(|&x| x as char).collect::<String>()).collect::<Vec<String>>();
        let execute_cmd = Exec::cmd("./".to_owned() + &case_name)
            .args(&argv)
            .stdin(test_case.stdin)
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .capture()?;
        assert_eq!(true, predicate::eq(execute_cmd.exit_status).eval(&test_case.return_code));
        assert_eq!(true, predicate::eq(execute_cmd.stdout).eval(&test_case.stdout));
        assert_eq!(true, predicate::eq(execute_cmd.stderr).eval(&test_case.stderr));
    };
    fs::remove_file("./".to_owned() + &case_name)?;
    Ok(())
}

#[test]
fn input_file_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = Exec::cmd("./target/debug/northc")
        .arg("404.north")
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Pipe)
        .capture()?;
    let stdout = cmd.stdout;
    let stderr = cmd.stderr;
    let code = cmd.exit_status;
    assert_ne!(code, ExitStatus::Exited(0));
    assert_eq!(stdout, "".as_bytes().to_vec());
    assert_eq!(stderr, "ERROR input file `404.north` not found\n".as_bytes().to_vec());
    Ok(())
}

#[test]
fn input_file_is_directory() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = Exec::cmd("./target/debug/northc")
        .arg("./tests")
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Pipe)
        .capture()?;
    let stdout = cmd.stdout;
    let stderr = cmd.stderr;
    let code = cmd.exit_status;
    assert_ne!(code, ExitStatus::Exited(0));
    assert_eq!(stdout, "".as_bytes().to_vec());
    assert_eq!(stderr, "ERROR input file `tests` not a file\n".as_bytes().to_vec());
    Ok(())
}

#[test]
fn argc_argv() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn arithmetic() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn bitwise() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn character_literal() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn comments() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn comparison() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn control_flow_if() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn control_flow_while() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn functions() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_character_literal_1() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_character_literal_2() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_empty_input() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_10() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_11() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_12() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_13() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_14() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_1() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_2() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_3() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_4() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_5() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_6() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_7() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_8() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_function_9() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_keyword() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_keyword_whitespace_1() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_keyword_whitespace_2() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_last_newline() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_1() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_2() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_3() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_4() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_5() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_6() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_7() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_8() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_preprocessor_9() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_string_literal() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_10() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_11() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_12() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_13() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_14() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_15() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_1() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_2() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_3() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_4() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_5() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_6() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_7() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_8() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn invalid_unmatched_9() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn memory() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn preprocessor_1() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn preprocessor_2() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn preprocessor_3() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn preprocessor_4() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn preprocessor_5() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn preprocessor_6() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn stack_operations() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn string_literal() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}

#[test]
fn system() -> Result<(), Box<dyn std::error::Error>> {
    run_test_case(function_name!())?;
    Ok(())
}
