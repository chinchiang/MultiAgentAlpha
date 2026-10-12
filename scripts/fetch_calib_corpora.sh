#!/usr/bin/env sh
# Fetch the public labelled corpora for a live calibration run (not committed to this repo), each pinned to
# the commit of a release tag; see scripts/fetch_calib_corpora.py. Labels for these corpora must be authored
# by a human (file, line, CWE); see calib/README.md.
set -eu
exec python3 "$(dirname "$0")/fetch_calib_corpora.py" "$@"
