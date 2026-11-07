#!/bin/zsh
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
cd "$HOME/caswell-cancel" || exit 1
exec /opt/homebrew/bin/uv run cc daily >> data/logs/daily.log 2>&1
