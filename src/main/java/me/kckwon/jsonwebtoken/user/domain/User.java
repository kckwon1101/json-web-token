package me.kckwon.jsonwebtoken.user.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@NoArgsConstructor
@Entity
@Table(name = "\"user\"")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator="user_id_seq")
    @Column(name="user_id", updatable = false, nullable = false)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column
    private String password;

    @Column
    private Role role;

    @Builder
    public User(String name, String password, Role role) {
        this.name = name;
        this.password = password;
        this.role = role;
    }
}

