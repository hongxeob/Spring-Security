package com.prgrms.devcource.user;


import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Service
@RequiredArgsConstructor
public class UserService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        checkArgument(isNotEmpty(username), "Username을 제공하세요.");

        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
        checkArgument(isNotEmpty(provider), "provider must me provided");
        checkArgument(isNotEmpty(providerId), "providerId must me provided");

        return userRepository.findByProviderAndProviderId(provider, providerId);
    }

    @Transactional
    public User join(OAuth2User oAuth2User, String provider) {
        checkArgument(oAuth2User != null, "oauth2User must me provided");
        checkArgument(isNotEmpty(provider), "provider must me provided");

        String providerId = oAuth2User.getName();

        return findByProviderAndProviderId(provider, providerId)
                .map(user -> {
                    log.warn("이미 존재하는 사용자 {} 입니다. provider => {}, providerId => {}", user, provider, providerId);
                    return user;
                })
                .orElseGet(() -> {
                    Map<String, Object> attributes = oAuth2User.getAttributes();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
                    checkArgument(properties != null, "OAuth2User properties is empty");

                    String nickname = (String) properties.get("nickname");
                    String profileImage = (String) properties.get("profile_image");
                    Group group = groupRepository.findByName("USER_GROUP")
                            .orElseThrow(() -> new IllegalStateException("Could not found group for USER_GROUP"));
                    return userRepository.save(
                            new User(nickname, provider, providerId, profileImage, group)
                    );
                });
    }
}
