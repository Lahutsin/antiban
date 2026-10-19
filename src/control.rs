use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    thread,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Status {
        allow4: bool,
        allow6: bool,
        addresses: usize,
        network: crate::network::NetworkStatus,
    },
    Quit,
    Stopped,
    Failure {
        message: String,
    },
}

pub fn send(stream: &mut UnixStream, message: &Message) -> Result<()> {
    serde_json::to_writer(&mut *stream, message)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

pub struct Control {
    stream: UnixStream,
    state: Arc<AtomicU8>,
}

impl Control {
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).context("Cannot connect to tray control socket")?;
        let input = stream.try_clone()?;
        let state = Arc::new(AtomicU8::new(0));
        let reader_state = state.clone();
        thread::spawn(move || {
            let result = (|| -> Result<()> {
                let mut line = String::new();
                BufReader::new(input).take(4096).read_line(&mut line)?;
                if serde_json::from_str::<Message>(&line)? != Message::Quit {
                    bail!("Expected a Quit control message");
                }
                Ok(())
            })();
            match result {
                Ok(()) => reader_state.store(1, Ordering::SeqCst),
                Err(error) => {
                    eprintln!("Tray control disconnected or invalid: {error:#}");
                    reader_state.store(2, Ordering::SeqCst);
                }
            }
        });
        Ok(Self { stream, state })
    }

    pub fn running(&self) -> bool {
        self.state.load(Ordering::SeqCst) == 0
    }

    pub fn quit_requested(&self) -> bool {
        self.state.load(Ordering::SeqCst) == 1
    }

    pub fn send(&mut self, message: &Message) -> Result<()> {
        send(&mut self.stream, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn status_and_quit_protocol_roundtrip() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let message = Message::Status {
            allow4: true,
            allow6: false,
            addresses: 12,
            network: Default::default(),
        };
        send(&mut sender, &message).unwrap();
        let mut line = String::new();
        BufReader::new(receiver).read_line(&mut line).unwrap();
        assert_eq!(serde_json::from_str::<Message>(&line).unwrap(), message);
        assert!(serde_json::from_str::<Message>(r#"{"type":"execute","command":"id"}"#).is_err());
    }

    #[test]
    fn explicit_quit_is_distinct_from_disconnection() {
        let path =
            std::env::temp_dir().join(format!("antiban-control-test-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let control = Control::connect(&path).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        send(&mut peer, &Message::Quit).unwrap();
        for _ in 0..100 {
            if !control.running() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(control.quit_requested());
        drop(control);
        let control = Control::connect(&path).unwrap();
        let (peer, _) = listener.accept().unwrap();
        drop(peer);
        for _ in 0..100 {
            if !control.running() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!control.running());
        assert!(!control.quit_requested());
        std::fs::remove_file(path).unwrap();
    }
}
