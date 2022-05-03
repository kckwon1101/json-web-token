package me.kckwon.jsonwebtoken.user.controller;

import lombok.RequiredArgsConstructor;
import me.kckwon.jsonwebtoken.user.domain.User;
import me.kckwon.jsonwebtoken.user.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/user")
public class UserController {

    private final UserRepository userRepository;

    @GetMapping
    public ResponseEntity<List<User>> getList() {
        return ResponseEntity.ok(userRepository.findAll());
    }
}
