package com.prgrms.devcource.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByLoginId(username)
                .map(
                        user -> User.builder()
                                .username(user.getLoginId())
                                .password(user.getPasswd())
                                .authorities(user.getGroup().getAuthorities())
                                .build())
                .orElseThrow(() -> new UsernameNotFoundException("유저를 찾을 수 없습니다.. => " + username));
    }
}
