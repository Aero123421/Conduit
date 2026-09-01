fn main() {
    if let Err(error) = conduit_cli::run() {
        eprintln!("conduit: {error}");
        std::process::exit(error.exit_code());
    }
}
