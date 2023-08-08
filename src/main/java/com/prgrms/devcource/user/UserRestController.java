package com.prgrms.devcource.user;

import com.prgrms.devcource.jwt.JwtAuthentication;
import com.prgrms.devcource.jwt.JwtAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class UserRestController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/user/login")
    public UserDto login(@RequestBody LoginRequest request) {
        JwtAuthenticationToken authToken = new JwtAuthenticationToken(request.getPrincipal(), request.getCredential());

        Authentication resultToken = authenticationManager.authenticate(authToken);

        JwtAuthenticationToken authenticated = (JwtAuthenticationToken) resultToken;
        JwtAuthentication principal = (JwtAuthentication) authenticated.getPrincipal();
        User user = (User) authenticated.getDetails();

        return new UserDto(principal.token, principal.username, user.getGroup().getName());
    }

    @GetMapping("/user/me")
    public UserDto me(@AuthenticationPrincipal JwtAuthentication jwtAuthentication) {
        return userService.findByLoginId(jwtAuthentication.username)
                .map(user -> new UserDto(
                        jwtAuthentication.token, jwtAuthentication.username, user.getGroup().getName()
                ))
                .orElseThrow(()
                        -> new IllegalArgumentException("유저를 찾을 수 없습니다" + jwtAuthentication.username));
    }
}
