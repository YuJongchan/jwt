package it.aKMa.jwt.config;

import it.aKMa.jwt.config.auth.jwt.JwtAuthenticationFilter;
import it.aKMa.jwt.config.auth.jwt.JwtAuthorizationFilter;
import it.aKMa.jwt.filter.MyFilter3;
import it.aKMa.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // 시큐리티 실행전후로 해야 됨 일반 필터등록

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)// 세션 방식 로그인 사용 안함
                .and()
                .addFilter(corsFilter) // @CrossOrigin(인증 X), 필터에 등록 인증(O)

                .formLogin().disable() // 폼로그인 사용안함
                .httpBasic().disable() // http 로그인 방식 사용 안함

                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager 넘겨야함
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) // AuthenticationManager 넘겨야함

                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_MANAGER')")
                .anyRequest().permitAll();
    }
}
