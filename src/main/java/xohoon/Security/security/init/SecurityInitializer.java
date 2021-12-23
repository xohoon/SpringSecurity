package xohoon.Security.security.init;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import xohoon.Security.service.SecurityResourceService;

@Component
public class SecurityInitializer implements ApplicationRunner {

    @Autowired
    private SecurityResourceService securityResourceService;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {

        securityResourceService.setRoleHierarchy();
    }
}
