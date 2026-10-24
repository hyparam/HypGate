use gateway_core::{http_message::HttpMessage, mailbox::Mailbox, output_frame::OutputFrame};
#[test]
fn actual_http_message_moves_its_payload_and_charge_through_receiver_cleanup() {
    for end in [false, true] {
        let mut queue = Mailbox::new();
        let message = if end { HttpMessage::End } else { HttpMessage::Data(OutputFrame::copy_prefix(b"data", 4)) };
        assert!(queue.push(message).is_ok());
        queue.close_sender();
        let mut cleanup = queue.close_receiver_charged();
        assert!(!queue.is_full());
        assert_eq!(cleanup.retained_count(), 1); // End has an item charge but zero payload
        let message = cleanup.begin().unwrap();
        assert_eq!(cleanup.retained_count(), 1);
        match message {
            HttpMessage::Data(frame) => { assert!(!end); assert_eq!(frame.into_vec(), b"data"); },
            HttpMessage::End => assert!(end),
        }
        assert!(cleanup.finish());
        assert_eq!(cleanup.retained_count(), 0);
        assert!(queue.push(HttpMessage::End).is_err());
    }
}
#[test]
fn normal_dequeue_moves_the_exact_frame_out_of_the_application_slot() {
    let mut queue = Mailbox::new();
    assert!(queue.push(HttpMessage::Data(OutputFrame::copy_prefix(b"abcdef", 3))).is_ok());
    let frame = match queue.pop().unwrap() { HttpMessage::Data(frame) => frame, HttpMessage::End => panic!("data expected") };
    assert!(!queue.is_full());
    assert!(queue.push(HttpMessage::End).is_ok());
    assert_eq!(frame.into_vec(), b"abc");
}
