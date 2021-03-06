package xohoon.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

//@Configuration
//@EnableWebSecurity
//public class SecurityConfigDoc extends WebSecurityConfigurerAdapter {
    public class SecurityConfigDoc {

//    @Autowired
    UserDetailsService userDetailsService;

//    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception { // 메모리로 사용자 생성
        auth.inMemoryAuthentication().withUser("xohoon").password("{noop}1212").roles("USER"); // noop -> 암호화 하지 않는다
        auth.inMemoryAuthentication().withUser("sys").password("{nope}1212").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{nope}1212").roles("ADMIN");
    }

//    @Override
    public void configure(WebSecurity web) throws Exception {
        // 보안필터를 전혀 거치지 않음 (permitAll 은 보안필터를 거쳐서 통과됨)
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

//    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("WHAT THE..");
        /*
        * 인가정책
        * */
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        /*
        * 인가정책 - 권한 설정 (구체적인 경로 후 큰 범위 경로가 뒤로 오도록 설정)
        * */
        http // 선언적 방식 -> 서비스는 동적 방식으로 변경
                .antMatcher("/test/**") // 해당 경로의 권한 설정
                .authorizeRequests()
                        .antMatchers("/login").permitAll()
                        .antMatchers("/test/login", "/test/users/**").permitAll() // 해당 경로에서는 인가 심사
                        .antMatchers("/test/mypage").hasRole("USER") // USER 권한 가져야함
                        .antMatchers("/test/admin/pay").access("hasRole('ADMIN')") // 세부 경로 설정 후
                        .antMatchers("/test/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // 큰 범위 경로 설정
                        .anyRequest().authenticated(); // 위 인증을 제외한 모든 요청은 인증을 받은 사용자만 접근 가능

        /*
        * 인증정책 -> Form 인증
        * */
        http.formLogin() // 기본 로그인 폼. Form 인증(properties 에 아이디 비밀번호 설정 가능)
//                .loginPage("/loginPage") // 사용자가 정의하는 로그인 페이지
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // Front ID Parameter name set
                .passwordParameter("pwd") // Front PW Parameter name set
                .loginProcessingUrl("/login_proc") // 로그인 Form Action url name set
                .successHandler(new AuthenticationSuccessHandler() { // 로그인 성공 후 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl(); // 접근을 시도했던 세션에 저장된 페이지 기억
                        response.sendRedirect(redirectUrl); // 인증 완료 후 가려고 했던 페이지로 이동

                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception = " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();

        /*
        * 인증정책 - csrf token 인증
        * */
        http.csrf() // -> default
//                .disable() // 비활성화
        ;

        /*
        * 인증정책 - logout (기본적으로 FORM POST 방식)
        * */
        http.logout() // 로그아웃 처리
                .logoutUrl("/logout") // 로그아웃 처리 URL
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동 페이지
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                }) // 로그아웃 핸들러
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }) // 로그아웃 성공 후 핸들러
                .deleteCookies("remember-me") // 로그아웃 후 쿠키 삭제;

        /*
        * 인증정책 - remember me
        * */
            .and().rememberMe() // remember-me 기능 활성화
                .rememberMeParameter("remember") // 파라미터 명 변경 default -> remember-me
                .tokenValiditySeconds(3600) // second 단위로 만료 기간 설정 default -> 14일
                .alwaysRemember(false) // remember-me 기능 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);

        /*
        * 인증정책 - 동시 세션 제어
        * */

        http.sessionManagement() // 세션 제어 활성화
                .maximumSessions(1) // 최대 허용 가능 세션 수, -1 -> 무제한 허용
                .maxSessionsPreventsLogin(false) //동시 로그인 차단, default -> false 기존 세션 만료
//                .expiredUrl() // 세셩 만료 시 이동 할 페이지
        ;

        /*
         * 인증정책 - 세션 고정 보호
         * */
//        http.sessionManagement()
//                .sessionFixation().changeSessionId(); // default, none, migrateSession, newSession

        /*
        * 인증정책 - 세션 정책
        * */
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 항상 세션 생성
//                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요시 생성(default)
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 생성하지 않지만 이미 존재하면 사용
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 생성하지 않고 존재해도 사용 하지 않음
        ;

        /*
         * 인증/인가 정책 - 예외처리
         * */
        http.exceptionHandling() // 예외처리 기능 활성화
                .authenticationEntryPoint(new AuthenticationEntryPoint() { // 인증 예외 발생시
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { // 인가 예외 발생시
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });


    }
}
