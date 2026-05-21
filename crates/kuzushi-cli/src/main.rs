use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    kuzushi_cli::run().await
}
