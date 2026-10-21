-- Saved views and hidden list columns, per person and page (roles spec §10).
CREATE TABLE console_saved_views (
    view_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    page text NOT NULL CHECK (page ~ '^[a-z][a-z-]{0,31}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    query text NOT NULL CHECK (length(query) <= 1000),
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX console_saved_views_name_unique
    ON console_saved_views (user_id, page, lower(name));
CREATE TABLE console_list_columns (
    user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    page text NOT NULL CHECK (page ~ '^[a-z][a-z-]{0,31}$'),
    hidden text[] NOT NULL CHECK (cardinality(hidden) <= 32),
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, page)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON console_saved_views, console_list_columns TO "openvibes-console";
