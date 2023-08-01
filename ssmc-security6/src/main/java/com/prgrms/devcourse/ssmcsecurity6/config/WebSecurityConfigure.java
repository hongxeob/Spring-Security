package com.prgrms.devcourse.ssmcsecurity6.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User. builder()
                .username("user")
                .password("{noop}user123")
                .roles("USER").build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}admin123")
                .roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain exceptionSecurityFilterChan(HttpSecurity http) throws Exception {
        return http
                .requestMatchers((matchers) -> matchers.antMatchers("/assets/**"))
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll())
                .requestCache().disable()
                .securityContext().disable()
                .sessionManagement().disable()
                .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
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
                .rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
                .and()
                /**
                 * 로그아웃
                 */
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .and().build();
    }
}
