// unfinished
// create event from scratch, with signatures and all

#[derive(Debug)]
struct Event {
    pubkey: String,
    message: String,
}

#[derive(Debug)]
struct Cli {
    command: String,
    event: Event,
}

// maybe make this public, then return the serialized struct
fn create_event() {
    let command = std::env::args().nth(1).expect("no command given");
    let message = std::env::args().nth(2).expect("no message given");

    let event = Event {
        pubkey: "013fa0".to_string(),
        message: message,
    };

    println!("{:?}", event);

    let args = Cli {
        command: command,
        event: event, 
    };
    
    println!("{:?}", args);
}
