use clap::Parser;
mod publisher;

#[derive(Parser)]
struct Cli {
    command: String,
    event: String
}

fn main() {
    let args = Cli::parse();

    if args.command == "publish" {
        publisher::publish(args.event);
    }
}
