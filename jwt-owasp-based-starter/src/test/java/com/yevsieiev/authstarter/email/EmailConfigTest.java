package com.yevsieiev.authstarter.email;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.javamail.JavaMailSender;

import static org.junit.jupiter.api.Assertions.*;
@SpringBootTest
class EmailConfigTest {

    private JavaMailSender mailSender;

    EmailConfigTest(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }


}