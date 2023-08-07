package com.prgrms.devcource.user;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "groups")
@Getter
public class Group {

    @Id
    @Column(name = "id")
    private Long id;

    @Column(name = "name")
    private String name;

    @OneToMany(mappedBy = "group")
    private List<GroupPermission> permissions = new ArrayList<>();

    public List<GrantedAuthority> getAuthorities() {
        return permissions.stream()
                .map(groupPermission -> new SimpleGrantedAuthority(groupPermission.getPermission().getName()))
                .collect(Collectors.toList());
    }
}
