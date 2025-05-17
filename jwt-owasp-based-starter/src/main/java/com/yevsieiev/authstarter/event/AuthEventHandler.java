package com.yevsieiev.authstarter.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;

@Slf4j
public class AuthEventHandler {

    @EventListener(AuthSuccessEvent.class)
    public void handleAuthSuccess(AuthSuccessEvent event) {
        log.info("User {} successfully authenticated at {}",
                event.getUsername(),
                event.getTimestamp()
        );
    }
}
