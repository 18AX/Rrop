use clap::Parser;

#[derive(Parser, Default, Debug)]
#[clap(version)]
struct Arguments {
    binary: String,
    #[clap(takes_value = false, short, long)]
    /// generate a ropchain
    ropchain: bool,
}

fn main() {
    let args = Arguments::parse();

    println!("Arguments {:?}", args);
}
