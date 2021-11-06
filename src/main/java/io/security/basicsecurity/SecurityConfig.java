package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('SYS') or hasRole('ADMIN')")
                .anyRequest().authenticated()
        ;

        http
                .formLogin()
//                .defaultSuccessUrl("/login", true)
                .successHandler(
                        (httpServletRequest, httpServletResponse, authentication) -> {
                            HttpSessionRequestCache httpSessionRequestCache = new HttpSessionRequestCache();
                            SavedRequest request = httpSessionRequestCache.getRequest(httpServletRequest, httpServletResponse);
                            String redirectUrl = request.getRedirectUrl();
                            httpServletResponse.sendRedirect(redirectUrl);
                        })
        ;

        http
                .exceptionHandling()
              /*  .authenticationEntryPoint(
                        (httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendRedirect("/login")
                )*/
                .accessDeniedHandler(
                        (httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendRedirect("/denied")
                )
        ;
    }

}
