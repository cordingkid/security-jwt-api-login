package com.example.securityjwtapilogin.controller;

import com.example.securityjwtapilogin.dto.UserJoinRequest;
import com.example.securityjwtapilogin.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public ResponseEntity<Void> join(@RequestBody UserJoinRequest request) {
        System.out.println("request.getUsername() = " + request.getUsername());
        joinService.join(request);
        return ResponseEntity.ok().build();
    }
}
