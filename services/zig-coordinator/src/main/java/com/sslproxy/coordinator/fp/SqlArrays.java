package com.sslproxy.coordinator.fp;

import io.vavr.control.Try;
import org.jooq.lambda.Unchecked;
import org.postgresql.util.PGobject;

import java.sql.Array;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

public final class SqlArrays {

    private SqlArrays() {}

    @FunctionalInterface
    public interface CheckedArrayFunction<T> {
        T apply(Array array) throws Exception;
    }

    public static <T> Try<T> withJsonbArray(Connection conn,
                                            List<String> values,
                                            CheckedArrayFunction<T> fn) {
        return Try.withResources(() -> new CloseableArray(conn.createArrayOf(
                        "jsonb",
                        values.stream()
                                .map(Unchecked.function(SqlArrays::toPgJsonb))
                                .toArray()
                )))
                .of(closeableArray -> fn.apply(closeableArray.array()));
    }

    public static <T> Try<T> withTextArray(Connection conn,
                                           List<String> values,
                                           CheckedArrayFunction<T> fn) {
        return Try.withResources(() -> new CloseableArray(conn.createArrayOf(
                        "text",
                        values.toArray(new String[0])
                )))
                .of(closeableArray -> fn.apply(closeableArray.array()));
    }

    private static PGobject toPgJsonb(String json) throws SQLException {
        if (json == null) {
            return null;
        }
        PGobject object = new PGobject();
        object.setType("jsonb");
        object.setValue(json);
        return object;
    }

    private record CloseableArray(Array array) implements AutoCloseable {
        @Override
        public void close() throws SQLException {
            array.free();
        }
    }
}
