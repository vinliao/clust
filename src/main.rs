use clap::Parser;
mod publisher;
mod event;
mod getter;

#[derive(Parser)]
struct Cli {
    command: String,
    content: String
}

fn main() {
    let args = Cli::parse();

    if args.command == "publish" {
        // publish signed event
        publisher::publish(args.content);
    } else if args.command == "post" {
        // create signed event, then publish
        let event = event::create_event(args.content);
        publisher::publish(event);
    } else if args.command == "get" {
        getter::get_event();
    }
}
