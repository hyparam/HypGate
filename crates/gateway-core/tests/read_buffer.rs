use gateway_core::read_buffer::ReadBuffer;

#[test]
fn consumed_prefix_remains_charged_until_final_byte() {
    let mut buffer = ReadBuffer::new(8);
    assert!(buffer.load(b"abcdefgh"));
    assert_eq!(buffer.peek(3), b"abc");
    assert!(buffer.consume(3));
    assert_eq!(buffer.len(), 5);
    assert_eq!(buffer.retained_bytes(), 8);
    assert_eq!(buffer.peek(5), b"defgh");
    assert!(!buffer.load(b"x"));
    assert!(!buffer.consume(6));
    assert_eq!(buffer.peek(5), b"defgh");
    assert_eq!(buffer.retained_bytes(), 8);
    assert!(buffer.consume(5));
    assert_eq!(buffer.retained_bytes(), 0);
    assert!(buffer.is_empty());
    assert!(buffer.load(b"xy"));
    assert_eq!(buffer.peek(2), b"xy");
}

#[test]
fn empty_and_oversized_frames_do_not_retain_payload() {
    let mut buffer = ReadBuffer::new(2);
    assert!(!buffer.load(b"abc"));
    assert_eq!(buffer.retained_bytes(), 0);
    assert!(buffer.load(b""));
    assert!(buffer.consume(0));
    assert_eq!(buffer.retained_bytes(), 0);
    let mut zero = ReadBuffer::new(0);
    assert!(!zero.load(b"a"));
    assert!(zero.load(b""));
}
