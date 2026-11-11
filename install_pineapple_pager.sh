#!/bin/bash
#
# install_pineapple_pager.sh - forwarder
#
# The real, maintained Pineapple Pager installer lives at
# scripts/install_pineapple_pager.sh. This wrapper stays at the repo root for
# backward compatibility (older docs and muscle memory) and simply execs it so
# there is a single source of truth.
#
# Usage: ./install_pineapple_pager.sh [pager-ip]
#
HERE="$(cd "$(dirname "$0")" && pwd)"
exec bash "${HERE}/scripts/install_pineapple_pager.sh" "$@"
