//! Man-page generator - run with `cargo run --bin gen_man` to produce
//! `man/portensor.1` plus one page per subcommand from the clap command
//! definition.
//!
//! This binary is not shipped in the final package; it is a build-time helper.
//! The generated man pages are committed to `man/` and installed via
//! `make install`.

use std::fs;

use clap::{Command, CommandFactory};
use clap_mangen::Man;
use portensor::Cli;

fn main() {
    fs::create_dir_all("man").expect("failed to create man/ directory");

    let cmd = Cli::command().disable_help_subcommand(true);
    let mut top = cmd.clone();
    top.build();
    let mut buffer = Vec::new();
    Man::new(top)
        .render(&mut buffer)
        .expect("failed to render man page");
    write_man("man/portensor.1", buffer);

    render_children(&cmd, "portensor");
    println!("Generated man pages in man/");
}

fn write_man(path: &str, buffer: Vec<u8>) {
    let rendered = String::from_utf8(buffer).expect("man page was not valid UTF-8");
    let mut cleaned = String::with_capacity(rendered.len());
    for line in rendered.lines() {
        cleaned.push_str(line.trim_end());
        cleaned.push('\n');
    }
    fs::write(path, cleaned).unwrap_or_else(|error| panic!("failed to write {path}: {error}"));
}

fn render_children(cmd: &Command, prefix: &str) {
    for sub in cmd.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        let name = format!("{prefix}-{}", sub.get_name());
        let mut sub_cmd = sub.clone().display_name(name.clone());
        sub_cmd.build();
        let path = format!("man/{name}.1");
        let mut buffer = Vec::new();
        Man::new(sub_cmd)
            .render(&mut buffer)
            .unwrap_or_else(|error| panic!("failed to render {path}: {error}"));
        write_man(&path, buffer);
        render_children(sub, &name);
    }
}
