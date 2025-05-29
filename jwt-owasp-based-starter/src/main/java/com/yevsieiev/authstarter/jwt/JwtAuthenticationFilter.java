package com.yevsieiev.authstarter.jwt;

import com.yevsieiev.authstarter.utils.CookieValidationUtils;
import com.yevsieiev.authstarter.utils.JwtTokenProvider;
import com.yevsieiev.authstarter.utils.TokenValidationUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter for JWT authentication.
 */

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final CookieValidationUtils cookieValidationUtils;
    private final TokenValidationUtils tokenValidationUtils;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        log.debug("Request to: {} | Authorization header: {}", request.getRequestURI(), authHeader);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            final String cipheredToken = authHeader.substring(7);
            log.info("Processing request to: {}", request.getRequestURI());
            log.info("Token present: {}", cipheredToken != null);

            if (!tokenValidationUtils.validateToken(cipheredToken, request)) {
                throw new AuthenticationCredentialsNotFoundException("Invalid token");
            }
            log.info("Token validation passed");
            if (!cookieValidationUtils.isValidCookie(request, cipheredToken)) {
                log.warn("Cookie validation failed for request to: {}", request.getRequestURI());
                throw new AuthenticationCredentialsNotFoundException("Invalid or missing fingerprint cookie");
            }
            log.info("Cookie validation passed");

            String username = jwtTokenProvider.getUsernameFromToken(cipheredToken);
            log.info("Username extracted from token: {}", username);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                log.info("User details loaded for username: {}", username);

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                log.info("Authentication token created");

                SecurityContextHolder.getContext().setAuthentication(authToken);
                log.info("Authentication token set to security context");
                log.debug("JwtAuthenticationFilter successfully passed request");
            }

        } catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
            return;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Before proceeding to next filter - Authentication present: {}, is authenticated: {}",
                auth != null, auth != null && auth.isAuthenticated());
        filterChain.doFilter(request, response);
        log.info("=== JWT Filter END ===");
        log.debug("JwtAuthenticationFilter successfully passed request");
    }
}