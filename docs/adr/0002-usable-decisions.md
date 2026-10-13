# Decisions: only a usable decision is ground truth, and a well-formed one still answers its ticket

A human decision is read in two places that want different things from it. The ticket flow asks "has a human answered this key?"; calibration, the Alternative Annotator Test and the shadow-phase false-positive rate ask "may this ruling be counted as truth?". Each place used to apply its own rule: calibration labels applied two contradicting decisions on one key, the false-positive rate counted any file in `calib/decisions/` (unbound, untrained, hand-written), and only the AAT excluded contradictions.

One rule now serves all of them, in two levels. A **well-formed** decision is a record that is consistent with itself: a true or false positive, a decision event, and a key that is both its file name and the v2 queue key of its own fields. A **usable** decision is well-formed, bound to the report it is compared with (same target, revision and context; a report missing any of the three binds nothing), has no contradicting decision on its key, and comes from an adjudicator who held a valid training record on the day of the decision whenever training is required. Only usable decisions count as ground truth. Any well-formed decision, usable or not, answers its ticket, so the key is not queued again; a file that is not well-formed answers nothing, and the key is ticketed again with a warning.

Training is judged when the decision is read, from the training register and the decision day, not from the `adjudicator_trained` flag the sync wrote into the record: that flag is a copy anyone can edit, while the register is checked for pass marks and expiry. Judging on the decision day means a later expiry does not void a decision that was sound when it was made.

## Considered options

- **Untrained decisions are not decisions at all:** rejected. The GitHub ticket is closed, so every review would file the key again and the queue would fill with duplicates. G-13 and the sync warning list these decisions so that a trained adjudicator can rule again.
- **Trust the training flag in the record:** rejected, because editing one boolean would make an untrained ruling ground truth.
- **Count unbound decisions in the false-positive rate (the repository's whole history):** rejected. The baseline describes the reviews it is given, and decisions on old revisions speak about findings those reviews do not hold.

How a usable decision settles its finding when the same content is reviewed again is recorded in docs/adr/0003-human-resolution.md.
