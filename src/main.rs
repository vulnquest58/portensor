use clap::Parser;

use portensor::Cli;

fn main() {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("portensor: cannot start async runtime: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = runtime.block_on(portensor::run(cli)) {
        if !error.is_silent() {
            eprintln!("portensor: {error}");
        }
        std::process::exit(error.exit_code());
    }
}
