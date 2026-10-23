Require Export New.generatedproof.verified_gateway.experiment.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : gateway.Assumptions}.
Collection W := sem + package_sem.
Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) gateway := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) gateway := build_get_is_pkg_init_wf.

Lemma wp_Cancel (s : loc) (v : gateway.Stream.t) :
  {{{ is_pkg_init gateway ∗ s ↦ v }}}
    s @! (go.PointerType gateway.Stream) @! "Cancel" #()
  {{{ RET #(); s ↦ (v <|gateway.Stream.Closed' := true|>) }}}.
Proof.
  wp_start as "Hs". wp_auto. wp_end.
Qed.

Lemma wp_FailLog (s : loc) (v : gateway.Stream.t) :
  {{{ is_pkg_init gateway ∗ s ↦ v }}}
    s @! (go.PointerType gateway.Stream) @! "FailLog" #()
  {{{ RET #(); s ↦
    (if v.(gateway.Stream.Strict') then
      (v <|gateway.Stream.LogFailed' := true|> <|gateway.Stream.Closed' := true|>)
     else (v <|gateway.Stream.LogFailed' := true|>)) }}}.
Proof.
  wp_start as "Hs". wp_auto.
  simpl. destruct v.(gateway.Stream.Strict') eqn:Hstrict; wp_auto; wp_end.
  iEval (simpl; rewrite Hstrict) in "Hs". iExact "Hs".
Qed.

Lemma wp_Send_closed (s : loc) (v : gateway.Stream.t) (count : w64) :
  v.(gateway.Stream.Closed') = true ->
  {{{ is_pkg_init gateway ∗ s ↦ v }}}
    s @! (go.PointerType gateway.Stream) @! "Send" #count
  {{{ RET #false; s ↦ v }}}.
Proof.
  intros Hclosed. wp_start as "Hs". wp_auto.
  rewrite Hclosed. wp_auto. wp_end.
Qed.

End proof.

Print Assumptions wp_Cancel.
Print Assumptions wp_FailLog.
Print Assumptions wp_Send_closed.
