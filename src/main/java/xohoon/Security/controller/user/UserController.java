package xohoon.Security.controller.user;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import xohoon.Security.domain.dto.AccountDTO;
import xohoon.Security.domain.entity.Account;
import xohoon.Security.repository.RoleRepository;
import xohoon.Security.security.token.AjaxAuthenticationToken;
import xohoon.Security.service.UserService;

import java.security.Principal;
@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepository roleRepository;

    @GetMapping(value="/users")
    public String createUser() throws Exception {

        return "user/login/register";
    }

    @PostMapping(value="/users")
    public String createUser(AccountDTO accountDto) throws Exception {

        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(accountDto.getPassword()));

        userService.createUser(account);

        return "redirect:/";
    }

    @GetMapping("/order")
    public String order(){
        userService.order();
        return "user/mypage";
    }

    @GetMapping(value="/mypage")
    public String myPage(@AuthenticationPrincipal Account account, Authentication authentication, Principal principal) throws Exception {
        userService.order();
        return "user/mypage";
//        String username1 = account.getUsername();
//
//        Account account2 = (Account) authentication.getPrincipal();
//        String username2 = account2.getUsername();
//
//        Account account3 = null;
//        if (principal instanceof UsernamePasswordAuthenticationToken) {
//            account3 = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
//
//        }else if(principal instanceof AjaxAuthenticationToken){
//            account3 = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
//        }
//
//        String username3 = account3.getUsername();
//
//        Account account4 = (Account) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//        String username4 = account4.getUsername();
    }

}
