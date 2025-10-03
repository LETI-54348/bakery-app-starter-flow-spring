package com.vaadin.starter.bakery.app.security;

import com.vaadin.flow.spring.security.VaadinAwareSecurityContextHolderStrategyConfiguration;
import com.vaadin.flow.spring.security.VaadinSecurityConfigurer;
import com.vaadin.starter.bakery.backend.data.entity.User;
import com.vaadin.starter.bakery.backend.repositories.UserRepository;
import com.vaadin.starter.bakery.ui.views.login.LoginView;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configures spring security, doing the following:
 * <li>Bypass security checks for static resources,</li>
 * <li>Restrict access to the application, allowing only logged in users,</li>
 * <li>Set up the login form,</li>
 * <li>Configures the {@link UserDetailsServiceImpl}.</li>
 *
 */
@EnableWebSecurity
@Configuration
@Import(VaadinAwareSecurityContextHolderStrategyConfiguration.class)
public class SecurityConfiguration {

	/**
	 * The password encoder to use when encrypting passwords.
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
	public CurrentUser currentUser(UserRepository userRepository) {
		final String username = SecurityUtils.getUsername();
		User user = username != null ? userRepository.findByEmailIgnoreCase(username) : null;
		return () -> user;
	}

    @Bean
    public SecurityFilterChain vaadinSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Allows access to static resources, bypassing Spring security.
                .authorizeHttpRequests(auth -> auth.requestMatchers(
                        // the robots exclusion standard
                        "/robots.txt",
                        // icons and images
                        "/icons/**",
                        "/images/**",
                        // (development mode) H2 debugging console
                        "/h2-console/**"
                ).permitAll())
                // Require login to access internal pages and configure login form.
                .with(VaadinSecurityConfigurer.vaadin(), vaadin -> vaadin.loginView(LoginView.class))
                .build();
	}

}
