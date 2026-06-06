use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "mealyctl", about = "Mealy local administration CLI")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Doctor,
    Paths,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Doctor => {
            println!("mealyctl ok");
        }
        Command::Paths => {
            let paths = mealy_platform::MealyPaths::resolve()?;
            println!("config: {}", paths.config_dir.display());
            println!("data: {}", paths.data_dir.display());
            println!("cache: {}", paths.cache_dir.display());
        }
    }

    Ok(())
}
