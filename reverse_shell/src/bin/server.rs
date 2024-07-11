use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

async fn handle_client(
    mut stream: tokio::net::TcpStream,
    mut rx: mpsc::Receiver<String>,
) -> io::Result<()> {
    let mut buffer = [0; 512];

    loop {
        if let Some(command) = rx.recv().await {
            if command.trim().is_empty() {
                continue;
            }

            stream.write_all(command.as_bytes()).await?;

            let bytes_read = stream.read(&mut buffer).await?;
            if bytes_read == 0 {
                println!("Connection closed");
                return Ok(());
            }

            print!("{}", String::from_utf8_lossy(&buffer[..bytes_read]));
        } else {
            break;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:4444").await?;
    println!("Listening on 0.0.0.0:4444");

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New connection: {}", addr);

        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(handle_client(stream, rx));

        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        while reader.read_line(&mut line).await? != 0 {
            let _ = tx.send(line.clone()).await;
            line.clear();
        }
    }
}
