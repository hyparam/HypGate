//! Actual production HTTP mailbox item and its cleanup payload projection.
use vstd::prelude::*;
use crate::{output_frame::OutputFrame, mailbox::{Mailbox, Cleanup}};
verus! {
pub enum HttpMessage { Data(OutputFrame), End }
impl HttpMessage {
    pub open spec fn valid(&self) -> bool {
        match self { Self::Data(frame) => frame.valid(), Self::End => true }
    }
    pub open spec fn payload(&self) -> Seq<u8> {
        match self { Self::Data(frame) => frame.contents(), Self::End => Seq::empty() }
    }
    pub fn into_payload(self) -> (out: Option<Vec<u8>>)
        requires self.valid(),
        ensures match out {
            Some(bytes) => matches!(self, Self::Data(_)) && bytes@ == self.payload() && bytes.len() <= 16384,
            None => matches!(self, Self::End) && self.payload().len() == 0,
        },
    {
        match self { Self::Data(frame) => Some(frame.into_vec()), Self::End => None }
    }
    pub proof fn payload_bound(&self)
        requires self.valid(),
        ensures self.payload().len() <= 16384,
    {
        match self { Self::Data(frame) => frame.payload_bound(), Self::End => {} }
    }
}
pub open spec fn message_bytes(value: Option<HttpMessage>) -> nat {
    match value { Some(message) => message.payload().len(), None => 0 }
}
pub open spec fn valid_message(value: Option<HttpMessage>) -> bool {
    match value { Some(message) => message.valid(), None => true }
}
pub open spec fn cleanup_bytes(cleanup: &Cleanup<HttpMessage>) -> nat {
    if cleanup.finished() { 0 } else { message_bytes(cleanup.original()) }
}
// Applies to the actual queued item, including the zero-payload End marker.
pub proof fn queued_payload_bound(queue: &Mailbox<HttpMessage>)
    requires queue.valid(), valid_message(queue.item()),
    ensures message_bytes(queue.item()) <= queue.retained_count() * 16384,
{
    match queue.item() { Some(message) => message.payload_bound(), None => {} }
}
// Extraction does not erase the original message; only reported completed
// destruction removes its charge. The closed mailbox cannot hold a second item.
pub proof fn closing_payload_bound(queue: &Mailbox<HttpMessage>, cleanup: &Cleanup<HttpMessage>)
    requires queue.valid(), !queue.receiver_open(), cleanup.valid(), valid_message(cleanup.original()),
    ensures message_bytes(queue.item()) + cleanup_bytes(cleanup) <= 16384,
        !cleanup.finished() ==> cleanup_bytes(cleanup) == message_bytes(cleanup.original()),
{
    queue.slot_bound();
    match cleanup.original() { Some(message) => message.payload_bound(), None => {} }
}
}
