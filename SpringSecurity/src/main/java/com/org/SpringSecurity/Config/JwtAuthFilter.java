package com.org.SpringSecurity.Config;

import com.org.SpringSecurity.Model.Users;
import com.org.SpringSecurity.Repository.UserRepo;
import com.org.SpringSecurity.Security.JwtAuthUtil;
import com.org.SpringSecurity.Security.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtAuthUtil jwtService;
    @Autowired
    ApplicationContext context;
    @Autowired
    private  final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("incoming Request" + " " + " " + request.getRequestURI());

            String requestTokenauthHeader = request.getHeader("Authorization");
            if (requestTokenauthHeader == null || !requestTokenauthHeader.startsWith("Bearer")) {
                filterChain.doFilter(request, response);// move ahead in filter chain
                return;
            }
            String token = requestTokenauthHeader.split("Bearer ")[1];
            String userName = jwtService.extractUserName(token);

            if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(userName);

                if (jwtService.validateToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request, response);// move ahead in filter chain
        }
        catch (Exception ex){
                handlerExceptionResolver.resolveException(request,response,null,ex);
        }

    }
}