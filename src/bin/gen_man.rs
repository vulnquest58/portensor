//! Man-page generator - run with `cargo run --bin gen_man` to produce
//! `man/rayscan.1` plus one page per subcommand from the clap command
//! definition.
//!
//! This binary is not shipped in the final package; it is a build-time helper.
//! The generated man pages are committed to `man/` and installed via
//! `make install`.

use std::fs;

use clap::{Command, CommandFactory};
use clap_mangen::Man;
use rayscan::Cli;

fn main() {
    fs::create_dir_all("man").expect("failed to create man/ directory");

    let cmd = Cli::command().disable_help_subcommand(true);
    let mut top = cmd.clone();
    top.build();
    let mut file = fs::File::create("man/rayscan.1").expect("failed to create man/rayscan.1");
    Man::new(top)
        .render(&mut file)
        .expect("failed to render man page");

    render_children(&cmd, "rayscan");
    println!("Generated man pages in man/");
}

fn render_children(cmd: &Command, prefix: &str) {
    for sub in cmd.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        let name = format!("{prefix}-{}", sub.get_name());
        let mut sub_cmd = sub.clone().display_name(name.clone());
        sub_cmd.build();
        let path = format!("man/{name}.1");
        let mut file = fs::File::create(&path)
            .unwrap_or_else(|error| panic!("failed to create {path}: {error}"));
        Man::new(sub_cmd)
            .render(&mut file)
            .unwrap_or_else(|error| panic!("failed to render {path}: {error}"));
        render_children(sub, &name);
    }
}
