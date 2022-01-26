use clap::Parser;
mod publisher;
mod event;

#[derive(Parser)]
struct Cli {
    command: String,
    event: String
}

fn main() {
    let args = Cli::parse();

    if args.command == "publish" {
        // publish signed event
        publisher::publish(args.event);
    } else if args.command == "post" {
        // create signed event, then publish
        let event = event::create_event();
        // publisher::publish(event);
    }
}
