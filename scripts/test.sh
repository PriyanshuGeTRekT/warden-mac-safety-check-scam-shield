#!/bin/bash
# Runs the unit tests. On Command Line Tools-only machines SwiftPM sometimes forgets to pass the
# Swift Testing macro plugin to the compiler; passing it explicitly is harmless everywhere else.
cd "$(dirname "$0")/.."
PLUGIN=/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
if [ -d "$PLUGIN" ]; then exec swift test -Xswiftc -plugin-path -Xswiftc "$PLUGIN" "$@"; else exec swift test "$@"; fi
