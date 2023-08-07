package com.prgrms.devcource.user;

import lombok.Getter;
import lombok.ToString;

import javax.persistence.*;

@Entity
@Table(name = "users")
@Getter
@ToString
public class User {

    @Id
    @Column(name = "id")
    private Long id;

    @Column(name = "login_id")
    private String loginId;

    @Column(name = "passwd")
    private String passwd;

    @ManyToOne(optional = false)
    @JoinColumn(name = "group_id")
    private Group group;

}
