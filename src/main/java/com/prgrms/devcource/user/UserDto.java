package com.prgrms.devcource.user;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class UserDto {

    private final String token;
    private final String username;
    private final String group;

    public UserDto(String token, String username, String group) {
        this.token = token;
        this.username = username;
        this.group = group;
    }
}
