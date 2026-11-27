# integrations

Companion tools that connect VEYRS to the outside world:

- `veyrs-agent/` — the scan agent: a standard-library Python worker that runs scanners where the targets are and streams results back, with its own systemd unit.
- `fleet-import/collect_fleet.py` — builds an inventory payload over SSH for `veyrs import-inventory`.
- `systemd/` — the intel-sync timer and service, which run `scripts/sync-intel.sh` hourly.

See each subdirectory's README and `docs/ARCHITECTURE.md`.
