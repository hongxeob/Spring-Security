package com.prgrms.devcource.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}user123").roles("USER")
                .and()
                .withUser("admin").password("{noop}admin123").roles("ADMIN");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
                /**
                 * remember me 설정
                 */
            .rememberMe() // 사용자가 로그인한 후에도 장기간 인증을 유지할 수 있도록 하는 기능
                .rememberMeParameter("remember-me") // Remember Me 기능을 사용할 때 클라이언트에서 전달하는 파라미터 이름을 지정
                .tokenValiditySeconds(300) // Remember Me 기능으로 발급되는 토큰의 유효기간을 지정
                .and()
                /**
                 * 로그아웃
                 * */
            .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // 로그아웃 요청을 매칭하는 방법 - "/logout" 경로로 들어오는 요청이 로그아웃 요청으로 처리
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true) // 로그아웃시 세션을 무효화 할지 말지
                .clearAuthentication(true) // 로그아웃시 현재 사용자 인증 정보 삭제할지 말지
                .and();
    }
}
