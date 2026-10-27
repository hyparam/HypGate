//! Command parsing without configuration reads or external effects.
use std::{net::SocketAddr, time::Duration};
use gateway_runtime::disk_log::Rotation;

pub(crate) const HELP: &str = "HypGate — an AI gateway with a verified audit core

Usage:
  hypgate CONFIG.json NEW_LOG [127.0.0.1:8080] [--log-max-bytes N] [--log-max-age-seconds N]
  hypgate scan LOG
  hypgate ship CONFIG.json LOG
  hypgate --help
  hypgate --version

The listen address must be loopback. NEW_LOG must not exist.
Logs rotate at 128 MiB or 24 hours by default, on the next record.
Numbered segments append .000001, .000002, etc. to NEW_LOG; none are deleted.
scan and ship follow numbered segments from the original LOG path.
scan prints record metadata without body payloads or changes to the log.
ship uploads a finished log using the configuration's shipping section.";

pub(crate) enum Command<'a> {
    Help,
    Version,
    Scan {
        log: &'a str,
    },
    Ship {
        root: &'a str,
        log: &'a str,
    },
    Serve {
        root: &'a str,
        log: &'a str,
        address: SocketAddr,
        rotation: Rotation,
    },
}

impl<'a> Command<'a> {
    pub(crate) fn parse(args: &'a [String]) -> Result<Self, &'static str> {
        match args {
            [flag] if flag == "--help" || flag == "-h" => Ok(Self::Help),
            [flag] if flag == "--version" || flag == "-V" => Ok(Self::Version),
            [command, rest @ ..] if command == "scan" => match rest {
                [log] => Ok(Self::Scan { log }),
                _ => Err("usage: hypgate scan LOG"),
            },
            [command, rest @ ..] if command == "ship" => match rest {
                [root, log] => Ok(Self::Ship { root, log }),
                _ => Err("usage: hypgate ship CONFIG.json LOG"),
            },
            [root, log, rest @ ..] => {
                let mut rest = rest;
                let address: SocketAddr = if let Some((value, tail)) = rest.split_first().filter(|(value, _)| !value.starts_with("--")) {
                    let address = value.parse().map_err(|_| "invalid listen address")?;
                    rest = tail;
                    address
                } else { "127.0.0.1:8080".parse().map_err(|_| "invalid listen address")? };
                let mut rotation = Rotation::default();
                let (mut bytes_set, mut age_set) = (false, false);
                while !rest.is_empty() {
                    let [flag, value, tail @ ..] = rest else { return Err("rotation option requires a value"); };
                    let value: u64 = value.parse().map_err(|_| "invalid rotation limit")?;
                    match flag.as_str() {
                        "--log-max-bytes" if !bytes_set && value > 56 => {
                            rotation.max_bytes = value; bytes_set = true;
                        }
                        "--log-max-age-seconds" if !age_set && value > 0 => {
                            rotation.max_age = Duration::from_secs(value); age_set = true;
                        }
                        _ => return Err("invalid or duplicate rotation option"),
                    }
                    rest = tail;
                }
                if !address.ip().is_loopback() {
                    return Err("listen address must be loopback; use a trusted TLS reverse proxy for remote clients");
                }
                Ok(Self::Serve {
                    root,
                    log,
                    address,
                    rotation,
                })
            }
            _ => Err("usage: hypgate CONFIG.json NEW_LOG [127.0.0.1:8080]; see --help"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Rotation, &'static str> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        match Command::parse(&args)? {
            Command::Serve { rotation, .. } => Ok(rotation),
            _ => Err("expected serve"),
        }
    }
    #[test]
    fn rotation_defaults_and_overrides() {
        let default = parse(&["config", "log"]).unwrap();
        assert_eq!(default.max_bytes, 128 * 1024 * 1024);
        assert_eq!(default.max_age, Duration::from_secs(86400));
        for address in [None, Some("127.0.0.1:0")] {
            let mut args = vec!["config", "log"];
            args.extend(address);
            args.extend(["--log-max-age-seconds", "10", "--log-max-bytes", "1024"]);
            let rotation = parse(&args).unwrap();
            assert_eq!(rotation.max_bytes, 1024);
            assert_eq!(rotation.max_age, Duration::from_secs(10));
        }
    }
    #[test]
    fn invalid_rotation_flags_are_rejected() {
        for flags in [
            vec!["--log-max-bytes"], vec!["--log-max-bytes", "56"],
            vec!["--log-max-bytes", "-1"], vec!["--log-max-bytes", "18446744073709551616"],
            vec!["--log-max-age-seconds", "0"], vec!["--log-max-age-seconds", "NaN"],
            vec!["--log-max-bytes", "128", "--log-max-bytes", "256"],
            vec!["--unknown", "10"],
        ] {
            let mut args = vec!["config", "log"];
            args.extend(flags);
            assert!(parse(&args).is_err());
        }
    }
}
