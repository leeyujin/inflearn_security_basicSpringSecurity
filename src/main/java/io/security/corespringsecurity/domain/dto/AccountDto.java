package io.security.corespringsecurity.domain.dto;

import lombok.Data;

// client 에게 전달받는 유저
@Data
public class AccountDto {
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
