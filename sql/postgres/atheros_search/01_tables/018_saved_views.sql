-- object: atheros_search_saved_views
-- depends_on: atheros_search_guarded_identity_confirmation
--
-- Personal, versioned graph views for the Integration Console. Each row is
-- owned by one immutable Keycloak subject; the owning subject is never
-- returned to clients or written to logs. Rows are only created, read,
-- updated and deleted by the Atheros Search runtime account.

CREATE TABLE IF NOT EXISTS atheros_search.saved_views (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_subject  VARCHAR(255) NOT NULL,
  surface        VARCHAR(32) NOT NULL,
  name           VARCHAR(80) NOT NULL,
  view_version   INTEGER NOT NULL DEFAULT 1,
  state          JSONB NOT NULL,
  revision       BIGINT NOT NULL DEFAULT 1,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT saved_views_surface_ck CHECK (surface = 'graph_projection'),
  CONSTRAINT saved_views_view_version_ck CHECK (view_version = 1),
  CONSTRAINT saved_views_revision_ck CHECK (revision > 0),
  CONSTRAINT saved_views_name_ck CHECK (name = btrim(name) AND length(btrim(name)) BETWEEN 1 AND 80),
  CONSTRAINT saved_views_state_object_ck CHECK (
    jsonb_typeof(state) = 'object'
    AND state ? 'filters'
    AND jsonb_typeof(state -> 'filters') = 'object'
    AND (NOT (state ? 'visible_node_kinds') OR jsonb_typeof(state -> 'visible_node_kinds') = 'array')
    AND (NOT (state ? 'visible_edge_kinds') OR jsonb_typeof(state -> 'visible_edge_kinds') = 'array')
  )
);

-- Names are unique per owner and surface, compared case-insensitively.
CREATE UNIQUE INDEX IF NOT EXISTS saved_views_owner_surface_name_uq
  ON atheros_search.saved_views (owner_subject, surface, lower(name));

CREATE INDEX IF NOT EXISTS saved_views_owner_surface_idx
  ON atheros_search.saved_views (owner_subject, surface, updated_at DESC);
