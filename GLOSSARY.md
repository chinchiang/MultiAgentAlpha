# MARA review

MARA reviews a repository with several model families in six layers; this glossary fixes the words for what is sent to a model, what comes back, and what humans decide about it.

## Untrusted data

**Fence**:
The tagged region of a prompt that holds data under review; everything inside it is data, never instructions, and only what lies outside it is trusted.
_Avoid_: wrapper, sandbox, boundary

**Repository data**:
Text taken from the repository under review (file contents, file names, routes, and the repository summary built from them), shown to a model only inside the fence.
_Avoid_: bundle (the bundle is one rendering of it), source

**Derived data**:
What a model derived from repository data and a later prompt shows again: context facts (to reviewers) and findings (to skeptic, red team, judge). It carries verified, hence real and attacker-writable, repository quotes, so it is untrusted and fenced like repository data.
_Avoid_: finding view, finding JSON, trusted context

**Exchange**:
One prompt sent to one model and its reply, classified into a reply outcome and screened for the canary.
_Avoid_: call, request, round trip

**Canary**:
A random token planted inside the fence as a fake instruction, to detect a model that follows data as instructions.
_Avoid_: honeypot, tripwire

**Canary echo**:
A reply that repeats the canary token without naming the planted file: the model followed the planted instruction.
_Avoid_: canary hit, injection success

**Canary report**:
A reply that names the token together with the planted file: the model noticed the injection and reported it, which is resistance, not an echo.
_Avoid_: canary citation

## Replies

**Reply outcome**:
The single classification of one reply: ok, truncation, unparseable reply, empty reply, refusal or error (no reply at all). Recorded once for every reply; see docs/adr/0001-reply-outcome-accounting.md.

**Extraction role**:
A role that produces new items from repository data (reviewer, context); an empty reply from it is an abstention.

**Ballot role**:
A role that rules on given findings one by one (skeptic, red team, judge); an empty reply from it is invalid output, since a ballot cannot abstain.
_Avoid_: verdict role

**Truncation**:
A reply the vendor stopped at the output limit; a budget problem, never charged to the model, and never evidence of a canary echo.
_Avoid_: cut-off for unparseable replies

**Unparseable reply**:
A reply that ended normally but is not the structured answer asked for; invalid output, charged to the model.
_Avoid_: truncated, malformed

**Empty reply**:
A reply that ended normally with no text; read by role (abstention for extraction roles, invalid output for ballot roles).

**Refusal**:
A reply the vendor or model marked as declining to answer; counted as an abstention, separate from invalid output.
_Avoid_: block, rejection

## Human decisions

**Jury outcome**:
What the pipeline itself concluded about a finding from the judges, skeptic, tools and evidence tier: accepted, rejected, or needing a human. It is kept as the pipeline concluded it even when a human later decides, because calibration measures the pipeline, not the human.
_Avoid_: consensus (the weighted score is one input), verdict

**Final outcome**:
A finding's outcome after human decisions: a usable decision's ruling where there is one, the jury outcome otherwise. The gate, scores, report, human queue, code-scanning results and PSIRT hand-off follow it.
_Avoid_: consensus, override result

**Human-resolved finding**:
A finding whose final outcome comes from a usable decision rather than the jury: the human ruling stands in either direction, while tool results stay subject to their own triage.
_Avoid_: overridden finding (the jury outcome is not discarded)

**Decision**:
One adjudicator's ruling, true positive or false positive, on one human-queue key (人工裁決). A well-formed decision is one whose record is internally consistent, whoever made it and whatever it is later compared with.
_Avoid_: adjudication, label (a label is a calibration sample's answer key), verdict (a judge's vote)

**Adjudicator**:
The person who made a decision, named by the decision event on the ticket.
_Avoid_: reviewer (a model role), annotator

**Bound decision**:
A decision on the same target, revision and context as a given review report, so it speaks about exactly the finding that report holds.
_Avoid_: matching decision, applied decision

**Usable decision**:
A well-formed, bound decision with no contradicting decision on its key, made by a trained adjudicator whenever training is required; the only kind of decision that counts as ground truth (calibration labels, the Alternative Annotator Test, false-positive rates). A decision that is well-formed but not usable still answers its ticket: the key is not queued again.
_Avoid_: valid decision (ambiguous between well-formed and usable)
