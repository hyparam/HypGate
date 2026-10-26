//! Executable checks of the serve driver against a scripted runtime. The
//! proofs cover every allowed trace; these pin the concrete sequences of
//! effects the production server performs.
use crate::serve_driver::*;

struct Fake {
    flags: Vec<bool>,
    accepts: Vec<Accepted>,
    admits: Vec<bool>,
    drains: Vec<bool>,
    log_ok: bool,
    calls: Vec<String>,
}
impl Fake {
    fn new(flags: &[bool], accepts: &[Accepted], admits: &[bool], drains: &[bool], log_ok: bool) -> Self {
        Fake { flags: flags.iter().rev().copied().collect(), accepts: accepts.iter().rev().copied().collect(),
            admits: admits.iter().rev().copied().collect(), drains: drains.iter().rev().copied().collect(), log_ok, calls: Vec::new() }
    }
    fn note(&mut self, call: impl Into<String>) { self.calls.push(call.into()); }
}
impl Effects for Fake {
    fn triggered(&mut self) -> bool { let b = self.flags.pop().expect("scripted flag"); self.note(format!("triggered={b}")); b }
    fn accept(&mut self) -> Accepted { let a = self.accepts.pop().expect("scripted accept"); self.note(format!("accept={a:?}")); a }
    fn admit_connection(&mut self) -> bool { let ok = self.admits.pop().expect("scripted admit"); self.note(format!("admit={ok}")); ok }
    fn serve_connection(&mut self) { self.note("serve"); }
    fn discard_connection(&mut self) { self.note("discard"); }
    fn stop_accepting(&mut self) { self.note("stop"); }
    fn close_workers(&mut self) { self.note("close_workers"); }
    fn wait_drained(&mut self, window: Window) -> bool { let ok = self.drains.pop().expect("scripted drain"); self.note(format!("wait({window:?})={ok}")); ok }
    fn cancel_live(&mut self) { self.note("cancel"); }
    fn close_log(&mut self) -> bool { self.note("close_log"); self.log_ok }
}

fn calls(fake: &Fake) -> Vec<&str> { fake.calls.iter().map(String::as_str).collect() }

#[test]
fn serves_each_accepted_connection_after_rechecking_the_flag_then_drains() {
    let mut fake = Fake::new(&[false, false, false, false, false, true], &[Accepted::Connection, Accepted::Interrupted, Accepted::Connection],
        &[true, false], &[true], true);
    let driven = serve(&mut fake);
    assert!(driven.accept_ok && driven.log_ok);
    assert_eq!(calls(&fake), [
        "triggered=false", "accept=Connection", "triggered=false", "admit=true", "serve",
        "triggered=false", "accept=Interrupted",
        "triggered=false", "accept=Connection", "triggered=false", "admit=false",
        "triggered=true", "stop", "close_workers", "wait(Drain)=true", "close_log",
    ]);
}

#[test]
fn a_socket_accepted_after_the_trigger_is_discarded_not_served() {
    let mut fake = Fake::new(&[false, true], &[Accepted::Connection], &[], &[true], true);
    let driven = serve(&mut fake);
    assert!(driven.accept_ok);
    assert_eq!(calls(&fake), ["triggered=false", "accept=Connection", "triggered=true", "discard", "stop", "close_workers", "wait(Drain)=true", "close_log"]);
}

#[test]
fn an_accept_failure_still_drains_and_is_reported() {
    let mut fake = Fake::new(&[false], &[Accepted::Failed], &[], &[true], true);
    let driven = serve(&mut fake);
    assert!(!driven.accept_ok && driven.log_ok);
    assert_eq!(calls(&fake), ["triggered=false", "accept=Failed", "stop", "close_workers", "wait(Drain)=true", "close_log"]);
}

#[test]
fn an_undrained_window_cancels_live_exchanges_and_waits_once_more() {
    let mut fake = Fake::new(&[true], &[], &[], &[false, false], false);
    let driven = serve(&mut fake);
    assert!(driven.accept_ok && !driven.log_ok);
    assert_eq!(calls(&fake), ["triggered=true", "stop", "close_workers", "wait(Drain)=false", "cancel", "wait(Cancel)=false", "close_log"]);
}

#[test]
fn a_drained_window_never_cancels() {
    let mut fake = Fake::new(&[true], &[], &[], &[true], true);
    serve(&mut fake);
    assert!(!fake.calls.iter().any(|c| c == "cancel"));
    assert_eq!(fake.calls.last().map(String::as_str), Some("close_log"));
}
