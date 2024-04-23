#!/bin/bash
# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4 is Open-Source, Licensed under BSD 3-Clause
# JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T) are licenced under the FoxIO License 1.1. For full license text, see the repo root.

echo "fetching zmap sources"
git clone https://github.com/zmap/zmap
cd zmap
git checkout v4.0.0-RC1
git status

cp ../probe_modules.c src/probe_modules/
cp ../module_ja4tscan.c src/probe_modules/

echo 'building using cmake...'
cmake -DEXTRA_PROBE_MODULES=probe_modules/module_ja4tscan.c && make install

echo "You can now run python3 ja4tscan.py"

