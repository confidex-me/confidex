use cfdex::{
    cli::Args,
    protocol::{Code, Failure},
    runtime,
};
use clap::Parser;
use std::io::Write;

fn main() -> std::process::ExitCode {
    let json = std::env::args_os().any(|arg| arg == "--json");
    let result = match Args::try_parse() {
        Ok(args) => runtime::harden()
            .map_err(runtime::io_failure)
            .and_then(|_| cfdex::cli::run(args)),
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            };
        }
        Err(_) => Err(Failure {
            code: Code::Input,
            message: "Invalid arguments. Run cfdex --help.".into(),
        }),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = std::io::stderr().lock();
            if json {
                let _ = writeln!(
                    stderr,
                    "{}",
                    serde_json::json!({"version":1,"error":{"code":error.code,"message":error.message}})
                );
            } else {
                let _ = writeln!(stderr, "{}", error.message);
            }
            std::process::ExitCode::from(error.code.exit() as u8)
        }
    }
}
