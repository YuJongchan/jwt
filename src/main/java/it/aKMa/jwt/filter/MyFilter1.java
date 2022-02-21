package it.aKMa.jwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import java.io.IOException;

@Slf4j
public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        log.debug("필터 1");
        log.debug("필터1");

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
