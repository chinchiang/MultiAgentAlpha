# MARA review

MARA reviews a repository with several model families in six layers; this glossary fixes the words for what is sent to a model and what comes back.

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
