use clap::Parser;

fn main() {
    if let Err(error) = antiban::tray::run(antiban::tray::Options::parse()) {
        eprintln!("ERROR: {error:#}");
        std::process::exit(1);
    }
}
