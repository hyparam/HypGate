//! Evidence required to cancel a duplex exchange. Receive-side observations
//! alone cannot establish that the peer cannot receive a response.
use vstd::prelude::*;

verus! {
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Observation {
    Data, EndOfInput, RetryRead, ReadFault,
    ConnectionReset, DeliveryFailed, Shutdown,
}

/// Independent duplex/environment model. A failed delivery or an operator
/// shutdown authorizes aborting work without claiming the peer has gone away.
pub ghost struct World {
    pub peer_sends: bool,
    pub peer_receives: bool,
    pub delivery_failed: bool,
    pub shutdown: bool,
}

/// Trusted observation contract. Buffered data and generic read errors say
/// nothing about the peer's receive side. EOF closes only its sending side.
pub open spec fn compatible(observation: Observation, world: World) -> bool {
    match observation {
        Observation::EndOfInput => !world.peer_sends,
        Observation::ConnectionReset => !world.peer_sends && !world.peer_receives,
        Observation::DeliveryFailed => world.delivery_failed,
        Observation::Shutdown => world.shutdown,
        _ => true,
    }
}
pub open spec fn authorized(world: World) -> bool {
    !world.peer_receives || world.delivery_failed || world.shutdown
}
/// Evidence must justify cancellation in EVERY world it could describe,
/// rather than merely in one possible interpretation of that observation.
pub open spec fn sufficient(observation: Observation) -> bool {
    forall|world: World| compatible(observation, world) ==> authorized(world)
}
pub open spec fn receive_only(observation: Observation) -> bool {
    matches!(observation, Observation::Data | Observation::EndOfInput | Observation::RetryRead | Observation::ReadFault)
}
pub open spec fn history_compatible(history: Seq<Observation>, world: World) -> bool {
    forall|i: int| 0 <= i < history.len() ==> compatible(#[trigger] history[i], world)
}

/// Only this module can construct a permit. Runtime socket cancellation
/// consumes one; an EOF or ambiguous read error can never produce one.
/// ```compile_fail
/// use gateway_core::cancellation::{Observation, Permit};
/// let forged = Permit { observation: Observation::EndOfInput };
/// ```
pub struct Permit { observation: Observation }
impl Permit {
    pub closed spec fn evidence(&self) -> Observation { self.observation }
}
pub enum Decision { Continue, StopWatching, Cancel(Permit) }

pub fn decide(observation: Observation) -> (out: Decision)
    ensures
        (out is Cancel) == sufficient(observation),
        match out {
            Decision::Cancel(permit) => permit.evidence() == observation && sufficient(permit.evidence()),
            Decision::Continue => observation == Observation::Data || observation == Observation::RetryRead,
            Decision::StopWatching => observation == Observation::EndOfInput || observation == Observation::ReadFault,
        },
{
    proof {
        // A concrete countermodel rules out every ambiguous observation.
        let receiving = World { peer_sends: false, peer_receives: true, delivery_failed: false, shutdown: false };
        if observation == Observation::Data || observation == Observation::EndOfInput
            || observation == Observation::RetryRead || observation == Observation::ReadFault {
            assert(compatible(observation, receiving));
            assert(!authorized(receiving));
            assert(!sufficient(observation));
        }
    }
    match observation {
        Observation::Data | Observation::RetryRead => Decision::Continue,
        Observation::EndOfInput | Observation::ReadFault => Decision::StopWatching,
        Observation::ConnectionReset | Observation::DeliveryFailed | Observation::Shutdown =>
            Decision::Cancel(Permit { observation }),
    }
}

/// Repeating or mixing receive-side observations never strengthens them into
/// evidence of a failed receive side. This covers arbitrarily long histories,
/// including data followed by EOF, repeated timeouts, and generic read faults.
pub proof fn receive_only_history(history: Seq<Observation>)
    requires forall|i: int| 0 <= i < history.len() ==> receive_only(#[trigger] history[i]),
    ensures exists|world: World| !authorized(world) && history_compatible(history, world),
{
    let world = World { peer_sends: false, peer_receives: true, delivery_failed: false, shutdown: false };
    assert(forall|i: int| 0 <= i < history.len() ==> compatible(#[trigger] history[i], world));
    assert(!authorized(world) && history_compatible(history, world));
}

/// Composition with a truthful adapter: any permit selected from a compatible
/// observation history authorizes cancellation in the actual world.
pub proof fn cancellation_is_justified(history: Seq<Observation>, world: World, permit: Permit)
    requires sufficient(permit.evidence()), history.contains(permit.evidence()),
        forall|i: int| 0 <= i < history.len() ==> compatible(#[trigger] history[i], world),
    ensures authorized(world),
{
    let i = choose|i: int| 0 <= i < history.len() && history[i] == permit.evidence();
    assert(compatible(history[i], world));
}
}
