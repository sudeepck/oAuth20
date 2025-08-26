    package com.org.SpringSecurity.Config;

    import com.org.SpringSecurity.Security.OAuth2SuccessHandler;
    import lombok.RequiredArgsConstructor;
    import lombok.extern.slf4j.Slf4j;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.AuthenticationProvider;
    import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
    import org.springframework.security.config.Customizer;
    import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.config.http.SessionCreationPolicy;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
    import org.springframework.web.servlet.HandlerExceptionResolver;

    @Configuration
    @EnableWebSecurity //--> to remove default Login form
    @Slf4j
    @RequiredArgsConstructor
    public class SecurityConfig {

        @Autowired
        private  UserDetailsService userDetailsService;
        private final JwtAuthFilter jwtAuthFilter;
        @Autowired
        private OAuth2SuccessHandler oAuth2SuccessHandler;

        @Bean
        public SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {
            System.out.println("securityCongfig");
            return http
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(request -> request
                            .requestMatchers(
                                    "/auth/signup",
                                    "/auth/updatePassword",
                                    "/auth/login"
                            ).permitAll()
                            .anyRequest().authenticated())
                    .httpBasic(Customizer.withDefaults())
                    .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                    .oauth2Login(outh2 -> outh2.
                                    failureHandler((request, response, exception) ->{
                                        log.error("oAuth2 err : {}", exception.getMessage());
                                    })
                            .successHandler(oAuth2SuccessHandler)
                    )
                    .build();
        }

        @Bean
        public AuthenticationProvider authenticationProvider(){
            DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
            daoAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder(12));// not to use any password encoder;
            daoAuthenticationProvider.setUserDetailsService(userDetailsService);
            return  daoAuthenticationProvider;
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
            return  authenticationConfiguration.getAuthenticationManager();
        }
}
