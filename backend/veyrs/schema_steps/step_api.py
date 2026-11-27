"""Schema steps owned by the API workstream.

compliance_frameworks used to carry ONE global UNIQUE (slug, version). A custom
framework created by one organization therefore collided with another
organization's (a 409 that also revealed the other tenant's catalogue), and
nothing stopped an organization from shadowing a built-in. Uniqueness is now
scoped: built-ins (organization_id IS NULL) stay unique per (slug, version),
custom frameworks are unique per (organization_id, slug, version).
"""

STEPS: list[tuple[str, str]] = [
    ("compliance_frameworks_drop_global_unique", """
        ALTER TABLE compliance_frameworks
            DROP CONSTRAINT IF EXISTS uq_compliance_frameworks_slug
    """),
    ("compliance_frameworks_drop_global_unique_default_name", """
        ALTER TABLE compliance_frameworks
            DROP CONSTRAINT IF EXISTS compliance_frameworks_slug_version_key
    """),
    ("compliance_frameworks_unique_builtin", """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_compliance_frameworks_builtin
            ON compliance_frameworks (slug, version)
            WHERE organization_id IS NULL
    """),
    ("compliance_frameworks_unique_per_org", """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_compliance_frameworks_org
            ON compliance_frameworks (organization_id, slug, version)
            WHERE organization_id IS NOT NULL
    """),
]
