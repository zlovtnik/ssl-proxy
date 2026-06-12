package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.annotation.JsonProperty;

public record OracleResult(
        @JsonProperty("job_id") String jobId,
        @JsonProperty("batch_id") String batchId,
        @JsonProperty("status") String status,
        @JsonProperty("row_count") int rowCount,
        @JsonProperty("checksum") String checksum,
        @JsonProperty("retryable") boolean retryable,
        @JsonProperty("error_class") String errorClass,
        @JsonProperty("error_text") String errorText,
        @JsonProperty("finished_at") String finishedAt
) {
    public static OracleResult success(String jobId, String batchId, int rowCount, String checksum, String finishedAt) {
        return new OracleResult(jobId, batchId, "success", rowCount, checksum, false, "", "", finishedAt);
    }

    public static OracleResult failure(
            String jobId,
            String batchId,
            OracleErrorClass errorClass,
            String errorText,
            String finishedAt
    ) {
        return new OracleResult(
                jobId == null ? "" : jobId,
                batchId == null ? "" : batchId,
                "failed",
                0,
                "",
                errorClass == OracleErrorClass.RETRYABLE,
                errorClass.wireValue(),
                errorText == null ? "" : errorText,
                finishedAt
        );
    }
}
