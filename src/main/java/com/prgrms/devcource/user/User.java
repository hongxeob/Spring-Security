package com.prgrms.devcource.user;

import lombok.Getter;
import lombok.ToString;

import javax.persistence.*;

import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Optional.ofNullable;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Entity
@Table(name = "users")
@Getter
@ToString
public class User {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "provider")
    private String provider;

    @Column(name = "provider_id")
    private String providerId;

    @Column(name = "profile_image")
    private String profileImage;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

    protected User() {/*no-op*/}

    public User(String username, String provider, String providerId, String profileImage, Group group) {
        checkArgument(isNotEmpty(username), "username must be provided.");
        checkArgument(isNotEmpty(provider), "provider must be provided.");
        checkArgument(isNotEmpty(providerId), "providerId must be provided.");
        checkArgument(group != null, "group must be provided.");

        this.username = username;
        this.provider = provider;
        this.providerId = providerId;
        this.profileImage = profileImage;
        this.group = group;
    }

    public Optional<String> getProfileImage() {
        return ofNullable(profileImage);
    }
}
