package com.yevsieiev.authstarter.event;

import com.yevsieiev.authstarter.event.service.LoginMetricsCounter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;

@Slf4j
@RequiredArgsConstructor
public class AuthEventHandler {

    private final LoginMetricsCounter loginMetricsCounter;

    @EventListener(AuthSuccessEvent.class)
    public void handleAuthSuccess(AuthSuccessEvent event) {
        loginMetricsCounter.increment();
        log.info("User logged in: {}, total: {}", event.getUsername(), loginMetricsCounter.getCount());
    }
}
