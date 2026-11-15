# migrations

There is no Alembic and there are no migration files. The SQLAlchemy models
are the schema.

`python -m veyrs init-db` creates missing tables, then runs the column
reconciler (`sync-schema`), which adds missing columns, single-column indexes
and foreign keys and widens a `VARCHAR`, then applies the RLS policies and seeds
the built-in roles and catalogues. It is idempotent: run it on every deploy. It
never drops, renames, narrows or retypes anything; a destructive change is
hand-written SQL, reviewed and run in a maintenance window.

See `docs/DATABASE.md` §5.
