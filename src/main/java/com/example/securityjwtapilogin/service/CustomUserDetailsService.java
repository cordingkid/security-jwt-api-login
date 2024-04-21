package com.example.securityjwtapilogin.service;

import com.example.securityjwtapilogin.domain.User;
import com.example.securityjwtapilogin.dto.CustomUserDetails;
import com.example.securityjwtapilogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // DB에서 조회
        User foundUser = userRepository.findByUsername(username);

        if (foundUser == null) { throw new UsernameNotFoundException("존재하지 않는 회원입니다."); }

        //UserDetails에 담아서 return하면 AutneticationManager가 검증 함
        return new CustomUserDetails(foundUser);
    }


}
