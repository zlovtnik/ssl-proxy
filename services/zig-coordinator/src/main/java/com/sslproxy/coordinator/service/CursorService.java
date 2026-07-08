package com.sslproxy.coordinator.service;

import org.springframework.stereotype.Service;

/**
 * Manages cursors for Redpanda streams via Postgres.
 * Ensures every configured stream has a cursor before the main loop starts.
 */
@Service
public class CursorService {

    private final DatabaseService db;

    public CursorService(DatabaseService db) {
        this.db = db;
    }

    /**
     * Ensures cursors exist for all configured streams.
     * Returns the primary stream cursor value.
     */
    public String ensureCursors() {
        return db.ensureAllCursors().orElseThrow();
    }
}
