# Database schema overview

`db.create_all()` creates these tables for the challenge baseline. For production schema evolution, introduce Alembic/Flask-Migrate migrations.

## users

- `id` primary key
- `name`, `email` (unique), `password_hash`
- `role`: `admin`, `owner`, `viewer`
- `active`: disabled accounts cannot continue using an existing session on their next request
- `created_at`

## documents

- `id` primary key; `owner_id` references users
- `name`, `category`, opaque `storage_key`
- `sha256`, `size_bytes`, `content_type`
- `created_at`, `updated_at`, nullable `deleted_at` for soft deletion

The original filename is never used as the disk storage path. `storage_key` is a random UUID-like key stored outside the static web directory.

## document_permissions

- `document_id`, `user_id` with unique constraint as a pair
- `permission` restricted to `read` or `edit`
- `granted_by`, `granted_at`

A grant applies to one document and one named active user. There is no folder inheritance in this design.

## audit_logs

- Actor ID and actor email snapshot, action, document ID, target user ID
- outcome, detail, request ID, timestamp
- `previous_hash`, `entry_hash`

The `entry_hash` is SHA-256 over canonical JSON of the row fields, including the previous row hash. This detects a changed row or broken sequence unless an attacker can rewrite the entire table and recompute the chain. Export signed checkpoints to a separately controlled immutable destination for stronger assurance.
