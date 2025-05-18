package com.yevsieiev.authstarter.event.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicLong;
@Service
public class LoginMetricsCounter {

    AtomicLong loginCounter = new AtomicLong(0);
    public void increment() {
        loginCounter.incrementAndGet();
    }

    public long getCount() {
        return loginCounter.get();
    }

    public void reset() {
        loginCounter.set(0);
    }
}
