package com.prgrms.devcource.user;

import com.prgrms.devcource.jwt.JwtAuthentication;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class UserRestController {

    private final UserService userService;

    @GetMapping("/user/me")
    public UserDto me(@AuthenticationPrincipal JwtAuthentication authentication) {
        return userService.findByUsername(authentication.username)
                .map(user -> new UserDto(
                        authentication.token, authentication.username, user.getGroup().getName()
                ))
                .orElseThrow(()
                        -> new IllegalArgumentException("유저를 찾을 수 없습니다" + authentication.username));
    }
}
