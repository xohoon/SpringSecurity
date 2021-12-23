package xohoon.Security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import xohoon.Security.domain.entity.RoleHierarchy;

public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

    RoleHierarchy findByChildName(String roleName);
}
