package xohoon.Security.security.init;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import xohoon.Security.service.RoleHierarchyService;
import xohoon.Security.service.SecurityResourceService;

@Component
public class SecurityInitializer implements ApplicationRunner {

//    @Autowired
//    private SecurityResourceService securityResourceService;
    @Autowired
    private RoleHierarchyService roleHierarchyService;
    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    @Override
    @Transactional
    public void run(ApplicationArguments args) throws Exception{
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        roleHierarchy.setHierarchy(allHierarchy);
//        securityResourceService.setRoleHierarchy();
    }
}
