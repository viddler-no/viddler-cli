use clap::Shell;

include!("src/cli.rs");

fn main() {
    let mut app = cli_app();
    let home_dir = match dirs::home_dir() {
        Some(home_dir) => home_dir,
        None => {
            println!("Couldn't resolve home directory for completions when building cli");
            std::process::exit(1);
        }
    };
    app.gen_completions("vid", Shell::Bash, home_dir);
}
