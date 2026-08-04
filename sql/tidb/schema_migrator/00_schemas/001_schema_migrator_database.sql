-- object: schema_migrator_database
-- depends_on:
-- Runtime identities are provisioned outside this migration.

CREATE DATABASE IF NOT EXISTS schema_migrator
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE schema_migrator;
