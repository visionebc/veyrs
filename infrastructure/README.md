# infrastructure

Deployment files for a host, installed by `install.sh` or by hand:

- `nginx-veyrs-console.conf` — the nginx vhost serving the console and proxying the API.
- `systemd/` — units for the API (`veyrs-api`), the daily digest, and the self-updater (`veyrs-updater`, path and service).
- `backup/` — PostgreSQL dump, dump verification and replication-check units and scripts (`veyrs-pgdump`, `veyrs-pgverify`, `veyrs-replcheck`).

Intel-feed refresh timers live in `integrations/systemd/`. See `docs/ARCHITECTURE.md`.
