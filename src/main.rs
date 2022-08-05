use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let config = Config::new(&args).unwrap_or_else(|err| {
        println!("Invalid args {}", err);
        process::exit(1);
    });

    println!("binary: {}", config.binary_path);
}

struct Config
{
    binary_path: String
}

impl Config
{
    fn new(args: &[String]) -> Result<Config, &'static str>
    {
        if args.len() < 2
        {
            return Err("Not enough arguments");
        }

        let binary_path = args[1].clone();
        Ok(Config{binary_path})
    }
}