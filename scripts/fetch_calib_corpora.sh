#!/usr/bin/env sh
# Fetch the public labelled corpora for a live calibration run (not committed to this repo).
# Labels for these corpora must be authored by a human (file, line, CWE); see calib/README.md.
set -eu
mkdir -p calib/corpora
[ -d calib/corpora/juice-shop ] || git clone --depth 1 https://github.com/juice-shop/juice-shop calib/corpora/juice-shop
[ -d calib/corpora/WebGoat ]    || git clone --depth 1 https://github.com/WebGoat/WebGoat calib/corpora/WebGoat
echo "corpora ready under calib/corpora/ (add labels.json to each before running mara review)"
