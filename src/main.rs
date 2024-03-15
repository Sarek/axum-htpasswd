mod cli;

fn main() {
    #[cfg(feature="cli")]
    cli::run();
}
