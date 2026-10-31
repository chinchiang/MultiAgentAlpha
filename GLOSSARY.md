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
What one exchange's reply counts for: its role and family, its reply outcome, canary echoes and reports, invalid items, whether it is a voided reply, the role's own counts and its tokens. `mara.audit` turns every record into the audit counters by one table; see docs/adr/0008-reply-accounting.md.

**Voided reply**:
A reply none of whose items count: its reply outcome is not ok, it echoes the canary, or its answer is not of the shape the role asks for. Its reply outcome and canary echo still count.
_Avoid_: discarded reply, rejected reply (rejected is a jury outcome)

**Invalid item**:
One item of a reply that is not of the shape its role asks for, or an answer with no items where items were asked for; invalid output, charged to the model.
_Avoid_: bad item, malformed finding (a finding is only what a reviewer reports)

**Extraction role**:
A role that produces new items from repository data (reviewer, context); an empty reply from it is an abstention.

**Ballot role**:
A role that rules on given findings one by one (skeptic, red team, judge); an empty reply from it is invalid output, since a ballot cannot abstain.
_Avoid_: verdict role

**Reviewer round**:
The part of a review in which every reviewer reports findings on each batch of the bundle for each dimension, one exchange each, unless the secret preflight blocked source egress. The findings are numbered in the order of their place, never the order the reviewers answered, so consecutive ids do not show which findings one exchange returned; then the findings of one dimension at the same place, equally verified, are merged into one, kept with every family that found it. Its result is what the ballot round rules on.
_Avoid_: L2 (a layer number, not a concept), review (the review is every stage, the tools and the reports included)

**Ballot round**:
The part of a review in which every ballot role rules on the deduplicated findings: the skeptic, then the red team on the findings the skeptic did not refute, then each judge in a forward and a mirrored reverse pass. A voided reply worth it is asked once more. Its result, the ballots (the skeptic's verdicts, the red team's notes and the judges' votes), is what the jury outcome is scored from.
_Avoid_: L3/L4 (layer numbers, not a concept), jury round (the jury is the judges alone)

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

**Reviewed content**:
The exact target, revision and content bundle a review examined (受審內容). Decisions and human queue items bind to reviewed content so a ruling on one revision or bundle never settles a finding on another.
_Avoid_: review identity, context identity, report identity

**Queue key**:
The identity of one place in one reviewed content that a decision binds to: the reviewed content, and the file, line and weakness of the finding. A decision under one queue key never settles a finding under another.
_Avoid_: finding id (a finding's id is only unique within one review), fingerprint

**Decision**:
One adjudicator's ruling, true positive or false positive, on one queue key (人工裁決). A well-formed decision is one whose record is internally consistent, whoever made it and whatever it is later compared with.
_Avoid_: adjudication, label (a label is a calibration sample's answer key), verdict (a skeptic's or judge's ruling on one finding)

**Adjudicator**:
The person who made a decision, named by the decision event on the ticket.
_Avoid_: reviewer (a model role), annotator

**Bound decision**:
A decision on the same reviewed content as a given review, so it speaks about exactly the finding that review holds.
_Avoid_: matching decision, applied decision

**Usable decision**:
A well-formed, bound decision with no contradicting decision on its key, made by a trained adjudicator whenever training is required; the only kind of decision that counts as ground truth (calibration labels, the Alternative Annotator Test, false-positive rates). A decision that is well-formed but not usable still answers its ticket: no new ticket is filed for its key.
_Avoid_: valid decision (ambiguous between well-formed and usable)

**Jury**:
The judges of a review as their votes are counted: one judge family each, the weight each family's vote carries, the discount on a vote from a family among the finding's finders, and how many families independent of its finders a finding needs for a quorum.
_Avoid_: panel (the panel is every model the config names, reviewers included), judges (the judges are the models; the jury is how their votes count)

**Jury signals**:
What the pipeline measures about one finding before it concludes anything: its evidence tier, weighted score and CVSS severity, whether its provenance is verified, whether the skeptic refuted it or left it unchallenged, whether enough independent judges voted, whether every judge family gave both passes, and their agreement and position consistency. They come from the finding's ballots, its finders, the tool evidence and the jury; the jury outcome is decided from them alone.
_Avoid_: consensus (the weighted score is one of them), votes (the votes are one input)

**Jury outcome**:
What the pipeline itself concluded about a finding from the judges, skeptic, tools and evidence tier: accepted, rejected, dropped, or needing a human.
_Avoid_: consensus (the weighted score is one input to it), verdict

**Rejected finding**:
A finding with enough evidence to stand (any tier but D) that the jury did not accept: the pipeline's own rejection, the kind the Alternative Annotator Test checks.
_Avoid_: dropped finding, false positive (that is a human ruling)

**Dropped finding**:
A finding at evidence tier D that needs no human: too little support, or refuted by the skeptic and not carried by the jury. It is out on the evidence, not on the jury's vote.
_Avoid_: rejected finding

**Human queue**:
The findings of one review a human must look at: every finding needing a human and every finding in rejection review, unless a usable decision already resolved it; each under its queue key, with its human reasons.
_Avoid_: review queue, triage list, tickets (a ticket is how one queue item reaches a human)

**Human reason**:
One reason a finding needs a human: a jury signal that fell short, a rejection review, or a decision on it that is not usable.
_Avoid_: incomplete reason (that is the review's, not the finding's), why

**Rejection review**:
The human look at every rejected finding that policy P8 requires until the Alternative Annotator Test passes. The finding enters the human queue, its jury outcome stays rejected, and the review is not incomplete because of it.
_Avoid_: needing a human (that outcome is undecided; a rejection under review is decided)

**Queue tightening**:
What the human queue does while its ticket backlog is over the limit: the agreement a finding needs to avoid a human rises, and tier C findings are left to the jury unless the config keeps them queued. Fewer findings reach a human, and those tier C ones block the gate instead. It never loosens on its own.
_Avoid_: throttling, backpressure

**Final outcome**:
A finding's outcome once human decisions are taken into account: the ruling of a usable decision where one exists, the jury outcome otherwise. It takes the jury outcome's values; a true-positive ruling makes it accepted, a false-positive ruling rejected.
_Avoid_: override result

**Human-resolved finding**:
A finding whose final outcome is the ruling of a usable decision rather than the jury outcome.
_Avoid_: overridden finding (the jury outcome still exists beside it)

## Tools

**Tool evidence**:
What the deterministic tools reported on one review's target: each tool's run, whether it ran to completion, and the results it reported, a scan that did not complete included.
_Avoid_: L0 results, tool findings (a finding is what a reviewer reports), SARIF (one format the results come in)

**Required tool**:
A deterministic tool that scans at least one of the dimensions a review covers; the review is incomplete unless every required tool ran.
_Avoid_: enabled tool (a tool can run without being required)

**Tool alert**:
A tool result at level error or warning: it can corroborate a finding and, until the tool's own triage suppresses it, keeps the review incomplete. A note is information, not an alert.
_Avoid_: blocking tool result (a blocking finding is a gate rule), tool finding

**Corroboration**:
A tool alert's independent support for a finding: at the same place, for the same weakness, from a tool that scans the finding's dimension. A corroborated finding has evidence tier A.
_Avoid_: tool match, confirmation (a judge's vote is not corroboration)

## Reviews

**Review invocation**:
One call of `mara review`: the target, the config, the provider mode, the output directory and the options it is given, the usage errors it can meet, and what it leaves, the reports in its output directory and an exit code. The command line, the pipeline and the workbench share one definition of it, so a usage error's message is worded once: the command line shows it on the option at fault, the workbench after its code's label, at times with the config file's name before it or cut short.
_Avoid_: launch (the workbench's request that becomes one), arguments, command line (the invocation is the same from the workbench)

**Usage error**:
A review invocation whose options cannot make a review, named with the option at fault: a config or output path inside the target, a config not found or that fails to load, a provider mode its models do not have, or another option's value the review cannot use (an unreadable PSIRT event, a base that is not a git ref). The command line exits 2 on it, which a blocked gate also does; the workbench names the ones it can check before it starts a run.
_Avoid_: refusal (a model's declined reply), rejection (a jury outcome), launch error

**Review scope**:
What one review covered: the whole target (full) or the files changed against a base together with the modules related to them (incremental); unknown for a report written before reviews recorded their scope. Scores of reviews with different scopes cannot be compared.
_Avoid_: mode (the provider mode is a different thing), diff review

**Provider mode**:
Whether a review's models are mock providers, which replay canned answers and ask no model, or live providers, which send each exchange to a real model; every model the config names must be of the review's provider mode, and the report records it. A config whose models mix both is mixed, and no review runs on it, whichever mode is asked. A mock review scores seeded material, so its score summary is exported only on explicit request.
_Avoid_: mode alone (the review scope is a different thing)

**Review facts**:
What a review gathered, stage by stage, that its review status and gate are decided from: whether the bundle covered the target, whether source egress was blocked, whether every required tool ran, whether the context view is missing, whether the ML-BOM signature verified, which audit counters make it incomplete, the rollout phase and whether the operator asked to enforce the gate.
_Avoid_: inputs, state

**Review status**:
Whether a review can stand as a conclusion: complete, or incomplete together with its incomplete reasons. An incomplete review has no overall score.
_Avoid_: run status, success

**Incomplete reason**:
One thing that keeps a review from standing as a conclusion: coverage or a required tool missing, a model reply that failed, a finding whose final outcome still needs a human, a tool alert. A rejection review is not one.
_Avoid_: error (an error is one kind of reply outcome), failure

**Gate**:
Whether a review's result lets the change merge, and when it does not, the gate reasons: the review is incomplete, a blocking finding, or a dimension score below the minimum. A blocked gate is enforced only in the blocking rollout phase, or for one review when the operator asks for it (`--fail-on-gate`); otherwise it is recorded but not enforced, and the report records which.
_Avoid_: check (a CI check is a different thing), pass/fail

**Blocking finding**:
A finding whose final outcome is accepted and whose evidence tier and severity meet the gate's blocking rules; while the human queue is tightened, an accepted tier C finding at the severity floor blocks too, since no human will look at it.
_Avoid_: blocker, critical finding (severity alone does not block)

**Bias audit**:
The report's counts and statistics of how the review went: every exchange's reply outcomes and canary echoes by role and family, what the pipeline dropped, merged or excluded on the way, the jury's agreement and position flips, and the exchange version the counts follow. It holds no report metadata: the rollout phase, the human queue's tightening and the ML-BOM and model-evaluation status are fields of the report of their own.
_Avoid_: audit alone (the Alternative Annotator Test and the governance checks are audits too), report metadata (the rest of the report)

**Report metadata**:
What a report records about the circumstances of its review rather than about how the review went: the rollout phase, the human queue's tightening, the ML-BOM status and signature, and the model families' red-team evaluations. Each is a field of the report of its own, none is in the bias audit, and a report written before a value was recorded reads it as not recorded.
_Avoid_: bias audit, config (the config is what was asked for; the metadata are what was in force)

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
The local web page that `mara` alone, or `mara serve` with its options, serves on a loopback address (評估工作台), from which reviews are started, followed and read; a view on `mara review`, never a second way to review. See docs/adr/0006-local-web-workbench.md.
_Avoid_: dashboard (it also starts reviews), web app, portal

**Workbench demo**:
The read-only copy of the workbench page on GitHub Pages (docs/workbench/, 唯讀展示): a snapshot of one offline review of the seeded fixture by the mock providers, answered from data in the page itself. It starts nothing and talks to no server.
_Avoid_: online workbench, hosted workbench (there is none: the workbench runs only on a loopback address)

**Run**:
One `mara review` subprocess the workbench started for one review invocation, with its own output directory holding the request, the argv, the roles and models of the config at launch, the child's output and every report it wrote. A run is finished only when its progress record says the reports were written; its exit code alone cannot tell a blocked gate from a usage error.
_Avoid_: job (a job is an environment task such as installing the tools), review (the review is what the run performs)

**Progress record**:
The file `mara review --progress-file` keeps rewriting while a review runs: its nine stages, each pending, running, done, skipped or failed, and the newest pipeline log lines. A view of the review, never evidence: nothing reads it back into a report.
_Avoid_: status file, log
