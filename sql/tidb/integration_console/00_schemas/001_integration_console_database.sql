-- object: integration_console_database
-- depends_on:
-- Runtime identities are provisioned outside this migration.

CREATE DATABASE IF NOT EXISTS integration_console
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE integration_console;
