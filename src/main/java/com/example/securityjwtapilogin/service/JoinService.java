package com.example.securityjwtapilogin.service;

import com.example.securityjwtapilogin.domain.User;
import com.example.securityjwtapilogin.dto.UserJoinRequest;
import com.example.securityjwtapilogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void join(UserJoinRequest request) {
        Boolean isExist = userRepository.existsByUsername(request.getUsername());
        if (isExist) {
            new IllegalArgumentException("이미 존재하는 아이디 입니다.");
        }
        User createdUser = new User(
                request.getUsername(),
                bCryptPasswordEncoder.encode(request.getPassword())
        );
        userRepository.save(createdUser);
    }
}
