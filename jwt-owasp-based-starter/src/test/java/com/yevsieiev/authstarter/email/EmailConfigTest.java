package com.yevsieiev.authstarter.email;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.javamail.JavaMailSender;

@SpringBootTest
class EmailConfigTest {

    private JavaMailSender mailSender;

    EmailConfigTest(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }


}