#!/bin/bash
# sandbox shim: the real tools/mkiso.sh now works unchanged here
exec bash /home/claude/deloxy-core/tools/mkiso.sh "$1" "${2:-/tmp/deloxy.iso}" >/dev/null
