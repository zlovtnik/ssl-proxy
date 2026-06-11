package com.sslproxy.coordinator.fp;

import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

public sealed interface DbResult<T> permits DbResult.Ok, DbResult.Empty, DbResult.Err {

    record Ok<T>(T value) implements DbResult<T> {}

    record Empty<T>() implements DbResult<T> {}

    record Err<T>(String operation, Throwable cause) implements DbResult<T> {}

    @FunctionalInterface
    interface CheckedSupplier<T> {
        T get() throws Exception;
    }

    @FunctionalInterface
    interface CheckedRunnable {
        void run() throws Exception;
    }

    static <T> DbResult<T> of(CheckedSupplier<T> supplier, String operation) {
        try {
            T value = supplier.get();
            return value == null ? new Empty<>() : new Ok<>(value);
        } catch (Exception e) {
            return new Err<>(operation, e);
        }
    }

    static DbResult<Void> run(CheckedRunnable runnable, String operation) {
        try {
            runnable.run();
            return new Ok<>(null);
        } catch (Exception e) {
            return new Err<>(operation, e);
        }
    }

    default <U> DbResult<U> map(Function<? super T, ? extends U> mapper) {
        return switch (this) {
            case Ok<T> ok -> {
                U value = mapper.apply(ok.value());
                yield value == null ? new Empty<>() : new Ok<>(value);
            }
            case Empty<T> ignored -> new Empty<>();
            case Err<T> err -> new Err<>(err.operation(), err.cause());
        };
    }

    default DbResult<T> onSuccess(Consumer<? super T> consumer) {
        if (this instanceof Ok<T> ok) {
            consumer.accept(ok.value());
        }
        return this;
    }

    default DbResult<T> onFailure(Consumer<Err<T>> consumer) {
        if (this instanceof Err<T> err) {
            consumer.accept(err);
        }
        return this;
    }

    default T orElse(T fallback) {
        return switch (this) {
            case Ok<T> ok -> ok.value();
            case Empty<T> ignored -> fallback;
            case Err<T> ignored -> fallback;
        };
    }

    default T orElseGet(Supplier<? extends T> supplier) {
        return switch (this) {
            case Ok<T> ok -> ok.value();
            case Empty<T> ignored -> supplier.get();
            case Err<T> ignored -> supplier.get();
        };
    }

    default T orElseThrow() {
        return switch (this) {
            case Ok<T> ok -> ok.value();
            case Empty<T> ignored -> throw new NoSuchElementException("Empty database result");
            case Err<T> err -> throw new RuntimeException(err.operation(), err.cause());
        };
    }

    default Optional<T> toOptional() {
        return switch (this) {
            case Ok<T> ok -> Optional.ofNullable(ok.value());
            case Empty<T> ignored -> Optional.empty();
            case Err<T> ignored -> Optional.empty();
        };
    }
}
