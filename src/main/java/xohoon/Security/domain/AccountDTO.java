package xohoon.Security.domain;

import lombok.Data;

@Data
public class AccountDTO {
    private Long Id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
