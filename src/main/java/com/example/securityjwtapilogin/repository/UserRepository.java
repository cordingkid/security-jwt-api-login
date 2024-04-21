package com.example.securityjwtapilogin.repository;

import com.example.securityjwtapilogin.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Boolean existsByUsername(String username);

    // username을 받아 DB 테이블에서 회원을 조회하는 메소드 작성
    User findByUsername(String username);
}
