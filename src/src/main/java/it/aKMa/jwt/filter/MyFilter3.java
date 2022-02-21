package it.aKMa.jwt.filter;

import it.aKMa.jwt.config.auth.jwt.JwtProperties;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        log.debug("필터 3");
        log.debug("method = " + request.getMethod());

        // 토큰 cos 만들어야함 id, pw 정상적으로 들어와서 로그인이 완료 되면 토큰 만들어주고 그걸 응답해준다.
        // 요청 때 마다 header에 Authorization에 value 토큰을 가지고 온다.
        // 그때 토큰이 넘어오면 토큰이 내가 만든 토큰이 맍는지만 검증만 하면됨 (RSA, HS256)
        if ("POST".equals(request.getMethod())) {
            String headerAuth = request.getHeader(JwtProperties.HEADER_STRING);

            log.debug("filter = " + headerAuth);

            if ("cos".equals(headerAuth)) {
                filterChain.doFilter(request, response);
            } else {
                PrintWriter outPrintWriter = response.getWriter();
                outPrintWriter.println("인증 안됨");
            }
        }
    }
}
