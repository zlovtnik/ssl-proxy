package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

final class JsonFields {

    private JsonFields() {}

    static long rowSequence(int index, String context) {
        return Math.addExact(index, 1);
    }

    static String rawJson(ObjectMapper objectMapper, JsonNode row, String context) {
        try {
            return objectMapper.writeValueAsString(row);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("encode raw " + context + " json: " + e.getMessage(), e);
        }
    }

    static String requiredString(JsonNode row, String field, String context) {
        return optionalString(row, field)
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IllegalArgumentException(context + " row missing " + field));
    }

    static java.util.Optional<String> optionalString(JsonNode row, String field) {
        JsonNode value = row.get(field);
        if (value == null || value.isNull()) {
            return java.util.Optional.empty();
        }
        if (!value.isTextual()) {
            return java.util.Optional.empty();
        }
        String text = value.asText().trim();
        return text.isEmpty() ? java.util.Optional.empty() : java.util.Optional.of(text);
    }

    static String stringAlias(JsonNode row, String first, String second, String context) {
        return optionalString(row, first)
                .or(() -> optionalString(row, second))
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IllegalArgumentException(context + " row missing " + first + "/" + second));
    }

    static long requiredLong(JsonNode row, String field, String context) {
        return optionalLong(row, field)
                .orElseThrow(() -> new IllegalArgumentException(context + " row missing numeric " + field));
    }

    static java.util.Optional<Long> optionalLong(JsonNode row, String field) {
        JsonNode value = row.get(field);
        if (value == null || value.isNull() || !value.isNumber()) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(value.longValue());
    }

    static long longAlias(JsonNode row, String first, String second, String context) {
        return optionalLong(row, first)
                .or(() -> optionalLong(row, second))
                .orElseThrow(() -> new IllegalArgumentException(context + " row missing numeric " + first + "/" + second));
    }

    static java.util.Optional<Long> nestedLong(JsonNode row, String object, String field) {
        JsonNode parent = row.get(object);
        if (parent == null || parent.isNull()) {
            return java.util.Optional.empty();
        }
        return optionalLong(parent, field);
    }

    static java.util.Optional<Double> optionalDouble(JsonNode row, String field) {
        JsonNode value = row.get(field);
        if (value == null || value.isNull() || !value.isNumber()) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(value.doubleValue());
    }

    static java.util.Optional<Double> nestedDouble(JsonNode row, String object, String field) {
        JsonNode parent = row.get(object);
        if (parent == null || parent.isNull()) {
            return java.util.Optional.empty();
        }
        return optionalDouble(parent, field);
    }

    static long boolFlag(JsonNode row, String field) {
        JsonNode value = row.get(field);
        return value != null && value.isBoolean() && value.asBoolean() ? 1L : 0L;
    }

    static OffsetDateTime requiredTimestamp(JsonNode row, String field, String context) {
        return parseTimestamp(requiredString(row, field, context), field);
    }

    static OffsetDateTime timestampAlias(JsonNode row, String first, String second, String context) {
        String value = optionalString(row, first)
                .or(() -> optionalString(row, second))
                .orElseThrow(() -> new IllegalArgumentException(context + " row missing " + first + "/" + second));
        return parseTimestamp(value, first);
    }

    static java.util.Optional<OffsetDateTime> optionalTimestamp(JsonNode row, String field) {
        return optionalString(row, field).map(value -> parseTimestamp(value, field));
    }

    static OffsetDateTime parseTimestamp(String value, String field) {
        try {
            return OffsetDateTime.parse(value).withOffsetSameInstant(ZoneOffset.UTC);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("decode " + field + " timestamp: " + e.getMessage(), e);
        }
    }

    static String jsonArrayString(ObjectMapper objectMapper, JsonNode row, String field) {
        JsonNode value = row.get(field);
        if (value == null || value.isNull()) {
            return "[]";
        }
        if (value.isTextual()) {
            return value.asText();
        }
        if (!value.isArray()) {
            throw new IllegalArgumentException(field + " must be a JSON array or string");
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("encode " + field + ": " + e.getMessage(), e);
        }
    }
}
