-- object: atheros_search_database
-- depends_on:
-- Runtime identities are provisioned outside this migration.

CREATE DATABASE IF NOT EXISTS atheros_search
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE atheros_search;
