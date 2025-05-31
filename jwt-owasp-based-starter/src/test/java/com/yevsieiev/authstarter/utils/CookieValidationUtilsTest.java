package com.yevsieiev.authstarter.utils;

import com.yevsieiev.authstarter.config.JwtProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CookieValidationUtilsTest {
    @Mock
    private JwtProperties jwtProperties;
    @Mock
    private JwtTokenProvider jwtTokenProvider;

    private CookieValidationUtils cookieValidationUtils;

    @Mock
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        cookieValidationUtils = new CookieValidationUtils(jwtProperties, jwtTokenProvider);
    }

  void validateFingerprintCookie_shouldNotThrowForValidCookie() {

  }
  void validateFingerprintCookie_shouldThrowForInvalidCookie() {
  }

  void validateFingerprintCookie_shouldThrowForMissingCookie() {

  }


}