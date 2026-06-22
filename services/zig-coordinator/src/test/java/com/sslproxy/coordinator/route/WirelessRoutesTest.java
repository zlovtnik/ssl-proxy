package com.sslproxy.coordinator.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.ProducerTemplate;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WirelessRoutesTest {

    private final WirelessRoutes routes = new WirelessRoutes(
            CoordinatorProperties.DEFAULTS,
            mock(DatabaseService.class),
            new ObjectMapper(),
            mock(ProducerTemplate.class)
    );

    @Test
    void replyingHandlerRethrowsHandlerFailure() {
        var processor = routes.replyingHandler(
                payload -> {
                    throw new IllegalStateException("database unavailable");
                },
                "wireless.reply",
                "test_reply"
        );

        assertThrows(IllegalStateException.class, () -> processor.process(exchangeWithBody("{}")));
    }

    @Test
    void voidHandlerRethrowsHandlerFailure() {
        var processor = routes.voidHandler(payload -> {
            throw new IllegalStateException("database unavailable");
        });

        assertThrows(IllegalStateException.class, () -> processor.process(exchangeWithBody("{}")));
    }

    @Test
    void invalidReplyTopicFallsBackToConfiguredDefault() {
        assertEquals(
                "wireless.reply",
                routes.resolveReplyTopic("{\"reply_topic\":\"bad?brokers=example:9092\"}", "wireless.reply")
        );
    }

    @Test
    void validReplyTopicIsAccepted() {
        assertEquals(
                "wireless.mac.lookup.reply",
                routes.resolveReplyTopic("{\"reply_topic\":\"wireless.mac.lookup.reply\"}", "wireless.reply")
        );
    }

    @Test
    void sensorInboxReplyTopicIsAccepted() {
        assertEquals(
                "_INBOX.atheros_sensor.12345.7",
                routes.resolveReplyTopic(
                        "{\"reply_topic\":\"_INBOX.atheros_sensor.12345.7\"}",
                        "wireless.reply"
                )
        );
    }

    @Test
    void validButUnapprovedReplyTopicFallsBackToConfiguredDefault() {
        assertEquals(
                "wireless.reply",
                routes.resolveReplyTopic("{\"reply_topic\":\"wireless.attacker.reply\"}", "wireless.reply")
        );
    }

    @Test
    void nullReplyDoesNotPublish() throws Exception {
        ProducerTemplate producerTemplate = mock(ProducerTemplate.class);
        WirelessRoutes localRoutes = new WirelessRoutes(
                CoordinatorProperties.DEFAULTS,
                mock(DatabaseService.class),
                new ObjectMapper(),
                producerTemplate
        );
        var processor = localRoutes.replyingHandler(payload -> null, "wireless.reply", "test_reply");

        processor.process(exchangeWithBody("{}"));

        verify(producerTemplate, never()).sendBody(anyString(), anyString());
    }

    private Exchange exchangeWithBody(String body) {
        Exchange exchange = mock(Exchange.class);
        Message message = mock(Message.class);
        when(exchange.getIn()).thenReturn(message);
        when(message.getBody(String.class)).thenReturn(body);
        return exchange;
    }
}
