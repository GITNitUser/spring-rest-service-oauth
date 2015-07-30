/*
 * Copyright 2014-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package hello;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
public class OAuth2ServerConfiguration {

	private static final String RESOURCE_ID = "restservice";

	@Configuration
	@EnableResourceServer
	protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) {
			// @formatter:off
			resources
				.resourceId(RESOURCE_ID);
			// @formatter:on
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/users").hasRole("ADMIN")
					.antMatchers("/greeting").hasRole("USER")
					.antMatchers("/client_greeting").access("#oauth2.isClient()");
			// @formatter:on
		}
	}

	@Configuration
	@EnableAuthorizationServer
	protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

		private TokenStore tokenStore = new InMemoryTokenStore();

		@Autowired
		@Qualifier("authenticationManagerBean")
		private AuthenticationManager authenticationManager;
		@Autowired
		private CustomUserDetailsService userDetailsService;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			// @formatter:off
			endpoints
			.tokenStore(this.tokenStore)
			.authenticationManager(this.authenticationManager)
			.userDetailsService(userDetailsService);
			// @formatter:on
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients
				.inMemory()
					.withClient("user_member")
						.authorizedGrantTypes("password", "refresh_token" )
						.authorities("USER")
						.scopes("read", "write")
						.resourceIds(RESOURCE_ID)
					.and()
					.withClient("clientapp")
						.authorizedGrantTypes("client_credentials")
						.authorities("CLIENT")
						.scopes("read", "write")
						.resourceIds(RESOURCE_ID)
						.secret("123456")
					;
			    //client access sample
		        //  curl -X POST -vu clientapp:123456 http://localhost:8080/oauth/token -H "Accept: application/json" -d "grant_type=client_credentials"
			
			    //  after we recive token RECEIVED_TOKEN
			
			    //  curl http://localhost:8080/greeting -H "Authorization: Bearer RECEIVED_TOKEN"	
			    //  {"error":"access_denied","error_description":"Access is denied"}
			
			    //  curl http://localhost:8080/client_greeting -H "Authorization: Bearer RECEIVED_TOKEN"
			    //  {"id":2,"content":"Hello, Hello client app!"}
			
			
			
			
		        //user access sample
		        //  curl -X POST -vu user_member: http://localhost:8080/oauth/token -H "Accept: application/json" -d "password=spring&username=roy&grant_type=password"

			    //  after we recive token RECEIVED_TOKEN
			
			    //curl http://localhost:8080/client_greeting -H "Authorization: Bearer RECEIVED_TOKEN"
			    //{"error":"access_denied","error_description":"Access is denied"}
			
			    //  curl http://localhost:8080/greeting -H "Authorization: Bearer RECEIVED_TOKEN"
			    //  {"id":3,"content":"Hello, roy!"}
			
			// @formatter:on
		}

		@Bean
		@Primary
		public DefaultTokenServices tokenServices() {
			DefaultTokenServices tokenServices = new DefaultTokenServices();
			tokenServices.setSupportRefreshToken(true);
			tokenServices.setTokenStore(this.tokenStore);
			return tokenServices;
		}

	}

}
