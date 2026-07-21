-- object: octopus_core_database
-- depends_on:
-- Runtime identities are provisioned outside this migration.

CREATE DATABASE IF NOT EXISTS octopus_core
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE octopus_core;
