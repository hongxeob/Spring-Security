package com.prgrms.devcource.user;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class LoginRequest {

    private String principal;
    private String credential;

    protected LoginRequest() {
    }

    public LoginRequest(String principal, String credential) {
        this.principal = principal;
        this.credential = credential;
    }
}
