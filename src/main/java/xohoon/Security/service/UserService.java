package xohoon.Security.service;

import xohoon.Security.domain.dto.AccountDTO;
import xohoon.Security.domain.entity.Account;

import java.util.List;

public interface UserService {
    void createUser(Account account);

    void modifyUser(AccountDTO accountDto);

    List<Account> getUsers();

    AccountDTO getUser(Long id);

    void deleteUser(Long idx);

    void order();
}