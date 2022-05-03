package me.kckwon.jsonwebtoken.security;

import lombok.RequiredArgsConstructor;
import me.kckwon.jsonwebtoken.user.domain.User;
import me.kckwon.jsonwebtoken.user.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    @Transactional
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = userRepository.findByName(name)
                .orElseThrow(() -> new UsernameNotFoundException("해당 사용자를 찾을 수 없습니다 : " + name));

        return UserPrincipal.create(user);
    }
}
