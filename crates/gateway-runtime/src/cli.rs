//! Command parsing without configuration reads or external effects.
use std::net::SocketAddr;

pub(crate) const HELP: &str = "HypGate — an AI gateway with a verified audit core

Usage:
  hypgate ROOT.json ROUTES.json NEW_LOG [127.0.0.1:8080]
  hypgate scan LOG
  hypgate ship ROOT.json LOG
  hypgate --help
  hypgate --version

The listen address must be loopback. NEW_LOG must not exist.
scan prints record metadata without body payloads or changes to the log.
ship uploads a finished log using the root policy's shipping configuration.";

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
        routes: &'a str,
        log: &'a str,
        address: SocketAddr,
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
                _ => Err("usage: hypgate ship ROOT.json LOG"),
            },
            [root, routes, log, rest @ ..] if rest.len() <= 1 => {
                let address: SocketAddr = rest
                    .first()
                    .map(String::as_str)
                    .unwrap_or("127.0.0.1:8080")
                    .parse()
                    .map_err(|_| "invalid listen address")?;
                if !address.ip().is_loopback() {
                    return Err("listen address must be loopback; use a trusted TLS reverse proxy for remote clients");
                }
                Ok(Self::Serve {
                    root,
                    routes,
                    log,
                    address,
                })
            }
            _ => Err("usage: hypgate ROOT.json ROUTES.json NEW_LOG [127.0.0.1:8080]; see --help"),
        }
    }
}
