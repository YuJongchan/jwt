package it.aKMa.jwt.config.auth.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import it.aKMa.jwt.config.auth.PrincipalDetails;
import it.aKMa.jwt.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// spring security 에서 UsernamePasswordAuthenticationFilter 있다.
// /login 요청해서 username, password 전송(post)
// UsernamePasswordAuthenticationFilter 동착함
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.debug("JwtAuthenticationFilter : 로그인 시도중");

        try {
            ObjectMapper om = new ObjectMapper();

            User user = om.readValue(request.getInputStream(), User.class);
            log.debug("user : {}", user.toString());

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDeatilsService 의 loadUserByusername() 함수 실행 정상이면 authentication 리턴
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session 영역에 저장됨 -> 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            // 정상 로그인 된거임
            // 권한 관리는 security가 대신 해주기 때문
            // 굳이 jwt 토큰 사용하면서 세션을 만든 이유가 없음 근데 단지 권한 처리 때문에 session 넣어준다
            log.debug("로그인 완료 principalDetails.getUser().getUsername() : {}", principalDetails.getUser().getUsername());

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        log.debug("===================================================");

        // 1. username, password 받는다
        // 2. 정상인지 로그인 시도를 한다. authenticaltionManager 로그인시도를 하면 PrincialDeatilsService 가 호출 한다.
        // 호출 하면 loadUserByUsername()함수 호출
        // 3. princiapDatils를 세션에 담고 (권한 관리를 위해서)
        // 4. jwt 토큰을 만들어서 응답해주면된다.

        return null;
    }

    // 인증이 정상적으로 되면 함수 실행
    // JWT 토큰 만듬됨 request 요청한 사용자에게 JWT 토큰 response 해주됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.debug("==================================================================");
        log.debug("========================      로그인 완료     ====================");
        log.debug("==================================================================");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String sign = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) // 완료 시간 10분
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));// 서버만 알아야할 키값

        log.debug("jwt token sign = {}", sign);


        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + sign);
    }
}
