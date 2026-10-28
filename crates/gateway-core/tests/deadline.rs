use gateway_core::deadline::{Io, run};

struct Effect { now: u128, finish: u128, budgets: Vec<u128> }
impl Io for Effect {
    type Output = ();
    fn now(&mut self) -> u128 { self.now }
    fn perform(&mut self, budget: u128) { self.budgets.push(budget); self.now = self.finish; }
}

#[test]
fn retries_share_the_original_end_and_expiry_prevents_io() {
    let mut effect = Effect { now: 10, finish: 40, budgets: vec![] };
    assert_eq!(run(&mut effect, 100), Some(()));
    effect.finish = 99;
    assert_eq!(run(&mut effect, 100), Some(()));
    effect.finish = 100;
    assert_eq!(run(&mut effect, 100), None);
    assert_eq!(run(&mut effect, 100), None);
    assert_eq!(effect.budgets, [90, 60, 1]);
}

#[test]
fn a_successful_but_late_effect_is_rejected() {
    let mut effect = Effect { now: 1, finish: 101, budgets: vec![] };
    assert_eq!(run(&mut effect, 100), None);
    assert_eq!(effect.budgets, [99]);
}

#[test]
fn descendants_cannot_renew_the_root_even_on_overflow() {
    use gateway_core::deadline::Budget;
    let root = Budget::new(100);
    let child = root.limit(10, 40);
    assert_eq!(child.end_value(), 50);
    let descendant = child.limit(40, u128::MAX);
    assert_eq!(descendant.end_value(), 50);
    let mut effect = Effect { now: 45, finish: 49, budgets: vec![] };
    assert_eq!(descendant.run(&mut effect), Some(()));
    assert_eq!(effect.budgets, [5]);
    effect.now = 50;
    assert_eq!(descendant.run(&mut effect), None);
    assert_eq!(effect.budgets, [5]);
}
