use gateway_core::output_frame::{OutputFrame, MAX_OUTPUT_FRAME};
#[test]
fn frame_detaches_exact_bounded_prefix_for_all_limit_edges() {
    let input: Vec<u8> = (0..MAX_OUTPUT_FRAME + 31).map(|i| (i % 251) as u8).collect();
    for length in [0, 1, 17, MAX_OUTPUT_FRAME, input.len()] {
        for limit in [0, 1, 16, MAX_OUTPUT_FRAME - 1, MAX_OUTPUT_FRAME, usize::MAX] {
            let frame = OutputFrame::copy_prefix(&input[..length], limit);
            let count = length.min(limit).min(MAX_OUTPUT_FRAME);
            assert_eq!(frame.len(), count);
            let bytes = frame.into_vec();
            assert_eq!(bytes, input[..count]);
            assert_eq!(bytes.capacity(), count);
        }
    }
}
#[test]
fn frame_does_not_borrow_or_retain_the_original_allocation() {
    let mut input = vec![7; 1024 * 1024];
    let frame = OutputFrame::copy_prefix(&input, 3);
    input.fill(9);
    drop(input);
    assert_eq!(frame.into_vec(), vec![7; 3]);
}
