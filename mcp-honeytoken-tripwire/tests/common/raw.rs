// Copyright (c) 2026 msaleme. Licensed under the MIT License.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct Connection(BufReader<TcpStream>);
impl Connection {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(url)?;
        let address = url
            .socket_addrs(|| None)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing socket address"))?;
        anyhow::ensure!(
            address.ip().is_loopback(),
            "raw test must target local gateway only"
        );
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(8)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self(BufReader::new(stream)))
    }
    pub fn send(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.0.get_mut().write_all(bytes)?;
        Ok(())
    }
    pub fn response(&mut self) -> anyhow::Result<(u16, Vec<u8>)> {
        let mut line = String::new();
        self.0.read_line(&mut line)?;
        let status = line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("missing response status"))?
            .parse()?;
        let mut length = None;
        let mut chunked = false;
        loop {
            line.clear();
            anyhow::ensure!(self.0.read_line(&mut line)? > 0, "truncated headers");
            if line == "\r\n" {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                anyhow::bail!("invalid response header");
            };
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse::<usize>()?);
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.trim().eq_ignore_ascii_case("chunked");
            }
        }
        let mut body = Vec::new();
        if chunked {
            loop {
                line.clear();
                self.0.read_line(&mut line)?;
                let size =
                    usize::from_str_radix(line.trim().split(';').next().unwrap_or_default(), 16)?;
                anyhow::ensure!(body.len() + size <= 65536, "response exceeds fixture bound");
                if size == 0 {
                    loop {
                        line.clear();
                        anyhow::ensure!(self.0.read_line(&mut line)? > 0, "truncated trailers");
                        if line == "\r\n" {
                            break;
                        }
                    }
                    break;
                }
                let offset = body.len();
                body.resize(offset + size, 0);
                self.0.read_exact(&mut body[offset..])?;
                let mut crlf = [0; 2];
                self.0.read_exact(&mut crlf)?;
                anyhow::ensure!(&crlf == b"\r\n", "invalid chunk terminator");
            }
        } else if let Some(length) = length {
            anyhow::ensure!(length <= 65536, "response exceeds fixture bound");
            body.resize(length, 0);
            self.0.read_exact(&mut body)?;
        } else {
            anyhow::ensure!(
                status == 204 || status == 304,
                "unframed response cannot prove connection reuse"
            );
        }
        Ok((status, body))
    }
}
