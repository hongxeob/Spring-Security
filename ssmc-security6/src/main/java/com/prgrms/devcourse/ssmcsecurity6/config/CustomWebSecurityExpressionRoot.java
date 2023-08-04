package com.prgrms.devcourse.ssmcsecurity6.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomWebSecurityExpressionRoot extends WebSecurityExpressionRoot {

    static final Pattern PATTERN = Pattern.compile("[0-9]+$");

    public CustomWebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
        super(a, fi);
    }

    public boolean isOddAdmin() {
        User user = (User) getAuthentication().getPrincipal();
        String name = user.getUsername();

        Matcher matcher = PATTERN.matcher(name);
        if (matcher.find()) {
            int num = toInts(matcher.group(), 0);
            return num % 2 == 1;
        }
        return false;
    }

    private static int toInts(String str, int defaultValue) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
