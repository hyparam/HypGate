use gateway_core::scope::{self, Effects};
struct Scope { output: Result<(), u32>, events: Vec<&'static str> }
impl Effects for Scope {
    type Output = Result<(), u32>;
    fn body(&mut self) -> Self::Output { self.events.push("body"); self.output }
    fn cleanup(&mut self) { self.events.push("cleanup"); }
}
#[test]
fn every_return_cleans_up_in_order_without_changing_the_result() {
    for output in [Ok(()), Err(0), Err(u32::MAX)] {
        let mut scope = Scope { output, events: vec![] };
        assert_eq!(scope::run(&mut scope), output);
        assert_eq!(scope.events, ["body", "cleanup"]);
    }
}
