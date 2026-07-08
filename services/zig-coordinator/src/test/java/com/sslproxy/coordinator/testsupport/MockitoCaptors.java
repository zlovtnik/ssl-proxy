package com.sslproxy.coordinator.testsupport;

import com.sslproxy.coordinator.service.DatabaseService;
import org.mockito.ArgumentCaptor;

import java.util.List;

public final class MockitoCaptors {

    private MockitoCaptors() {
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    public static ArgumentCaptor<List<DatabaseService.ScanRequestRecord>> scanRequestRecordListCaptor() {
        return ArgumentCaptor.forClass((Class) List.class);
    }
}
