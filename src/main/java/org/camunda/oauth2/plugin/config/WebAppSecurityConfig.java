package org.camunda.oauth2.plugin.config;

import org.camunda.oauth2.plugin.filter.SpringSecurityAuthenticationProvider;
import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.context.request.RequestContextListener;

import java.util.Collections;

@ConditionalOnMissingClass("org.springframework.test.context.junit.jupiter.SpringExtension")
@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 15)
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring()
//                .antMatchers("/app/**", "/app/cockpit/**", "/api/engine/**", "/lib/**");
//    }

    private final KeycloakLogoutHandler keycloakLogoutHandler;

    WebAppSecurityConfig(KeycloakLogoutHandler keycloakLogoutHandler) {
        this.keycloakLogoutHandler = keycloakLogoutHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().ignoringAntMatchers("/api/**")
                .and()
                .requestMatchers().antMatchers("/**").and()
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/app/**", "/api/**", "/lib/**")
                                .authenticated()
                                .anyRequest()
                                .permitAll()
                )
                .oauth2Login()
                .and()
                .logout()
//                .addLogoutHandler(keycloakLogoutHandler)
                .logoutSuccessUrl("/");
        ;
    }

//    @Bean
//    public FilterRegistrationBean containerBasedAuthenticationFilter() {
//
//        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
//        filterRegistration.setFilter(new ContainerBasedAuthenticationFilter());
//        filterRegistration.setInitParameters(Collections.singletonMap("authentication-provider",
//                SpringSecurityAuthenticationProvider.class.getName()));
//        filterRegistration.setOrder(101);
//        filterRegistration.addUrlPatterns("/app/**");
//        return filterRegistration;
//    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Bean
    public FilterRegistrationBean containerBasedAuthenticationFilter(){

        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
        filterRegistration.setFilter(new ContainerBasedAuthenticationFilter());
        filterRegistration.setInitParameters(Collections.singletonMap("authentication-provider",
                "org.camunda.bpm.extension.keycloak.showcase.sso.KeycloakAuthenticationProvider"));
        filterRegistration.setOrder(101); // make sure the filter is registered after the Spring Security Filter Chain
        filterRegistration.addUrlPatterns("/app/*");
        return filterRegistration;
    }

    @Bean
    @Order(0)
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }
}
