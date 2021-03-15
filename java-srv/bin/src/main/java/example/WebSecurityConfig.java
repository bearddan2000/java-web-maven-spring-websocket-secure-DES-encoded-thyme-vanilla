package example;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/login").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login")
        .loginProcessingUrl("/login")
        .defaultSuccessUrl("/", true)
				.permitAll();
	}
	@Bean
	public PasswordEncoder passwordEncoder()
	{
		try {
			//Generate the secret key
			String password = "abcd1234";
			DESKeySpec key = new DESKeySpec(password.getBytes());
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			return new example.security.DESPasswordEncoder(keyFactory.generateSecret(key));
		} catch(Exception e) {}
		System.out.println("Using default.");
		return new BCryptPasswordEncoder();
	}

	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		UserDetails user =
			 User.withUsername("user")
				.password(passwordEncoder().encode("pass"))
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user);
	}
}
