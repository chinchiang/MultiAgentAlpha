"""The local web workbench (`mara serve`; GLOSSARY.md: workbench, run; docs/adr/0006-local-web-workbench.md).

A loopback-only HTTP server from the standard library and one self-contained page: launch a white-box review,
follow its stages live, read its findings, roles, models and gaps, and check the L0 tools and model endpoints.
Reviews run as `mara review` subprocesses, so every refusal of the command line (workspace anchors, policies P1-P8,
mock/live consistency) still decides; the workbench only collects their inputs and reads their outputs.

The package itself holds no code; each of its modules says whether it is pure.
"""
