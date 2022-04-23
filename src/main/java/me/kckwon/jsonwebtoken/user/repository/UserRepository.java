package me.kckwon.jsonwebtoken.user.repository;

import me.kckwon.jsonwebtoken.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
