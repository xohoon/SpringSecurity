package xohoon.Security.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import xohoon.Security.domain.entity.AccessIp;

public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {

    AccessIp findByIpAddress(String IpAddress);
}
