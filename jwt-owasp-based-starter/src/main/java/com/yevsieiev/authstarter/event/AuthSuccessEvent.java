package com.yevsieiev.authstarter.event;

import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

@Getter
@Setter
public class AuthSuccessEvent extends ApplicationEvent {
    private String username;
    private Instant eventTime;

    public AuthSuccessEvent(Object source, String username) {
        super(source);
        this.username = username;
        this.eventTime = Instant.now();
    }
}