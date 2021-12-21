package xohoon.Security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import xohoon.Security.domain.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
    Account findByUsername(String username);
}
