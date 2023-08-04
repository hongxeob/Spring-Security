package com.prgrms.devcourse.ssmcsecurity6.config;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OddAdminVoter implements AccessDecisionVoter<FilterInvocation> {

    static final Pattern PATTERN = Pattern.compile("[0-9]+$");
    private final RequestMatcher requestMatcher;

    public OddAdminVoter(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return false;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation fi, Collection<ConfigAttribute> attributes) {
        HttpServletRequest request = fi.getRequest();
        //URL 이 /admin 인가?
        if (!requiresAuthorization(request)) {
            return ACCESS_GRANTED;
        }

        User user = (User) authentication.getPrincipal();
        String name = user.getUsername();

        Matcher matcher = PATTERN.matcher(name);
        if (matcher.find()) {
            int num = toInts(matcher.group(), 0);
            if (num % 2 == 1) {
                return ACCESS_GRANTED;
            }
        }
        return ACCESS_DENIED;
    }

    private boolean requiresAuthorization(HttpServletRequest request) {
        return requestMatcher.matches(request);
    }

    private static int toInts(String str, int defaultValue) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
