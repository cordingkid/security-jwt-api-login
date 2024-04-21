package com.example.securityjwtapilogin.dto;

import lombok.*;

@Data
public class UserJoinRequest {

    private String username;
    private String password;
}
