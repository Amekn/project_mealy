use clap::Parser;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(name = "mealyd", about = "Mealy local daemon")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7341")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(args.listen).await?;

    tracing::info!(listen = %args.listen, "mealyd listening");
    axum::serve(listener, mealy_server::router()).await?;

    Ok(())
}
