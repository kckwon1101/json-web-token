package me.kckwon.jsonwebtoken;

import lombok.RequiredArgsConstructor;
import me.kckwon.jsonwebtoken.user.domain.User;
import me.kckwon.jsonwebtoken.user.repository.UserRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class DatabaseInitializer implements ApplicationListener<ApplicationReadyEvent> {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent applicationReadyEvent) {
        userRepository.save(
                User.builder()
                        .name("kckwon")
                        .password(passwordEncoder.encode("1234"))
                        .build()
        );
    }

}
