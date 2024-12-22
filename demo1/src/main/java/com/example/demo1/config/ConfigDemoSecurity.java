package com.example.demo1.config;

import java.awt.image.renderable.ContextualRenderedImageFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Md4PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.example.demo1.config.Oauth2CustomValidator.Oauth2CustomeValidator;
import com.fasterxml.jackson.annotation.ObjectIdGenerators.UUIDGenerator;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import jakarta.annotation.PostConstruct;

@Configuration
public class ConfigDemoSecurity {

	@Bean
	@Order(1)
	public SecurityFilterChain oauthSecurityFilterChain(HttpSecurity security) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(security); // gives access token to client
		security.getConfigurer(OAuth2AuthorizationServerConfigurer.class).
		authorizationEndpoint(
		a -> a.authenticationProviders(getAuthorizationEndpointProviders())
		 ).
				oidc(Customizer.withDefaults()); // gives id token to client

		security.exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

		return security.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain ServeSecurityFilterChain(HttpSecurity security) throws Exception {
		return security.httpBasic().and().formLogin().and().authorizeHttpRequests().
				anyRequest().hasAuthority("write").and().build();
	}

	@Bean
	public UserDetailsService detailsService() {
		UserDetails u1 = User.withUsername("foo").password(encoder().encode("foo")).authorities("read")
				.build();
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(u1);
		return manager;
	}

	@Bean
	@Qualifier("ByCrptPasswodEncoder")
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	private Consumer<List<AuthenticationProvider>> getAuthorizationEndpointProviders() {
		return providers -> {
			for (AuthenticationProvider p : providers) {
				if (p instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider x) {
					x.setAuthenticationValidator(new Oauth2CustomeValidator());
				}
			}
		};
	}
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	@Bean 
	public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer(){
		return context -> context.getClaims().claim("foo", "foo");
		
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {

		RegisteredClient client = RegisteredClient.withId("1").clientId("1").clientName("foo").clientSecret("foo")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.authorizationGrantTypes(c -> c.addAll(List.of(AuthorizationGrantType.AUTHORIZATION_CODE,
						AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.REFRESH_TOKEN)))
				.redirectUri("https://docs.spring.io/spring-authorization-server/reference/getting-started.html")
				.tokenSettings(TokenSettings.builder().refreshTokenTimeToLive(Duration.ofMinutes(5)).build())
				.postLogoutRedirectUri("https://spring.io/").build();

		return new InMemoryRegisteredClientRepository(client);
	}



	@Bean
	public JWKSource<SecurityContext> jwkSetSource() throws NoSuchAlgorithmException {

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.genKeyPair();
		RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
		RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();

		RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString())
				.build();

		JWKSet set = new JWKSet(rsaKey);

		return new ImmutableJWKSet(set);
	}
	
}
