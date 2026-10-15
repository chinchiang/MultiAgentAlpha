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

**Reply record**:
What one exchange's reply counts for: its role and family, its reply outcome, canary echoes and reports, invalid items, whether it was voided as a whole, the role's own counts and its tokens. `mara.audit` turns every record into the audit counters by one table; see docs/adr/0008-reply-accounting.md.

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
A reply that ended normally with no answer, neither as text nor as structured data (an aside may still hold some text); read by role (abstention for extraction roles, invalid output for ballot roles).

**Refusal**:
A reply the vendor or model marked as declining to answer; counted as an abstention, separate from invalid output.
_Avoid_: block, rejection

## Human decisions

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
A well-formed, bound decision with no contradicting decision on its key, made by a trained adjudicator whenever training is required; the only kind of decision that counts as ground truth (calibration labels, the Alternative Annotator Test, false-positive rates). A decision that is well-formed but not usable still answers its ticket: no new ticket is filed for its key.
_Avoid_: valid decision (ambiguous between well-formed and usable)

**Jury outcome**:
What the pipeline itself concluded about a finding from the judges, skeptic, tools and evidence tier: accepted, rejected, dropped, or needing a human.
_Avoid_: consensus (the weighted score is one input to it), verdict

**Rejected finding**:
A finding with enough evidence to stand (any tier but D) that the jury did not accept: the pipeline's own rejection, the kind the Alternative Annotator Test checks.
_Avoid_: dropped finding, false positive (that is a human ruling)

**Dropped finding**:
A finding at evidence tier D that needs no human: too little support, or refuted by the skeptic and not carried by the jury. It is out on the evidence, not on the jury's vote.
_Avoid_: rejected finding

**Rejection review**:
The human look at every rejected finding that policy P8 requires until the Alternative Annotator Test passes. The finding enters the human queue, its jury outcome stays rejected, and the review is not incomplete because of it.
_Avoid_: needing a human (that outcome is undecided; a rejection under review is decided)

**Final outcome**:
A finding's outcome once human decisions are taken into account: the ruling of a usable decision where one exists, the jury outcome otherwise. It takes the jury outcome's values; a true-positive ruling makes it accepted, a false-positive ruling rejected.
_Avoid_: override result

**Human-resolved finding**:
A finding whose final outcome is the ruling of a usable decision rather than the jury outcome.
_Avoid_: overridden finding (the jury outcome still exists beside it)

## Reviews

**Review scope**:
What one review covered: the whole target (full) or the files changed against a base together with the modules related to them (incremental); unknown for a report written before reviews recorded their scope. Scores of reviews with different scopes cannot be compared.
_Avoid_: mode (the provider mode is a different thing), diff review

**Review status**:
Whether a review can stand as a conclusion: complete, or incomplete together with its incomplete reasons. An incomplete review has no overall score.
_Avoid_: run status, success

**Incomplete reason**:
One thing that keeps a review from standing as a conclusion: coverage or a required tool missing, a model reply that failed, a finding whose final outcome still needs a human, a tool result nobody has triaged. A rejection review is not one.
_Avoid_: error (an error is one kind of reply outcome), failure

**Gate**:
Whether a review's result lets the change merge, and when it does not, the gate reasons: the review is incomplete, a blocking finding, or a dimension score below the minimum. A blocked gate is enforced only in the blocking rollout phase, or for one review when the operator asks for it (`--fail-on-gate`); otherwise it is recorded but not enforced, and the report records which.
_Avoid_: check (a CI check is a different thing), pass/fail

**Blocking finding**:
A finding whose final outcome is accepted and whose evidence tier and severity meet the gate's blocking rules; while the human queue is tightened, an accepted tier C finding at the severity floor blocks too, since no human will look at it.
_Avoid_: blocker, critical finding (severity alone does not block)

## Exports

**Finding detail**:
Anything that singles out one finding: its file, line, quote, title, claim, CWE or finding id (finding 明細). Counts of findings per dimension are not finding detail.
_Avoid_: details, raw findings

**Score summary**:
The export of one review report that carries only its dimension scores, overall score, review status and pseudonyms of what was reviewed, and no finding detail; the only part of an in-country review that may go to a team outside the country (分數彙總).
_Avoid_: aggregate report, redacted report (nothing is masked; the summary is built from an allowlist)

**Summary pseudonym**:
A keyed hash that stands in for the reviewed target or its revision in a score summary: the same under the same key from one export to the next, so the receiving team can follow a target over time, and not reversible without the key, which stays in the country.
_Avoid_: anonymised ID (the in-country team can map it back), hashed ID (an unkeyed hash can be confirmed from a list of candidates)

## Workbench

**Workbench**:
The local web page `mara serve` serves on a loopback address (評估工作台), from which reviews are started, followed and read; a view on `mara review`, never a second way to review. See docs/adr/0006-local-web-workbench.md.
_Avoid_: dashboard (it also starts reviews), web app, portal

**Workbench demo**:
The read-only copy of the workbench page on GitHub Pages (docs/workbench/, 唯讀展示): a snapshot of one offline review of the seeded fixture by the mock providers, answered from data in the page itself. It starts nothing and talks to no server.
_Avoid_: online workbench, hosted workbench (there is none: the workbench runs only on a loopback address)

**Run**:
One `mara review` subprocess the workbench started, with its own output directory holding the request, the argv, the roles and models of the config at launch, the child's output and every report it wrote. A run is finished only when its progress record says the reports were written; its exit code alone cannot tell a blocked gate from a usage error.
_Avoid_: job (a job is an environment task such as installing the tools), review (the review is what the run performs)

**Progress record**:
The file `mara review --progress-file` keeps rewriting while a review runs: its nine stages, each pending, running, done, skipped or failed, and the newest pipeline log lines. A view of the review, never evidence: nothing reads it back into a report.
_Avoid_: status file, log
