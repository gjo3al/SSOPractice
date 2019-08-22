package com.example.demo;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

@SpringBootApplication
//@EnableJpaRepositories
//@EnableOAuth2Sso
@EnableAuthorizationServer
@EnableOAuth2Client
@RestController
//讓此設定的優先度低於@EnableResourceServer
@Order(200)
public class SsoPracticeApplication extends WebSecurityConfigurerAdapter {

	@Autowired
	  OAuth2ClientContext oauth2ClientContext;
	
//	@Autowired
//	UserRepository repo;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	  protected void configure(HttpSecurity http) throws Exception {
	    http
	      .antMatcher("/**")
	      .authorizeRequests()
	        .antMatchers( "/oauth/**","/login**","/error**")
	        .permitAll()
	      .anyRequest()
	        .authenticated()
	      .and()
	      //使用表單登入，不加任何設定代表使用預設值
	      	.formLogin()
	      	.permitAll()
	        //權限錯誤時，預設導向至
//	      .and().exceptionHandling()
//	      	.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//	        .and().oauth2Login()
	        .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
	        	//.addFilterAfter(new CustomUsernamePasswordAuthenticationFilter(), BasicAuthenticationFilter.class)
	        ;
	  }
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		UserBuilder users = User.builder();
		auth.inMemoryAuthentication()
		.withUser(users.username("test")
				.password(new BCryptPasswordEncoder().encode("123"))
				.roles("USER"));
	}

	private Filter ssoFilter() {
		  CompositeFilter filter = new CompositeFilter();
		  List<Filter> filters = new ArrayList<>();
		  filters.add(ssoFilter(facebook(), "/login/facebook"));
		  filters.add(ssoFilter(github(), "/login/github"));
		  filters.add(ssoFilter(google(), "/login/google"));
		  filter.setFilters(filters);
		  return filter;
		}
	
	private Filter ssoFilter(ClientResources client, String path) {
		  OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		  OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		  filter.setRestTemplate(template);
		  UserInfoTokenServices tokenServices = new UserInfoTokenServices(
		      client.getResource().getUserInfoUri(), client.getClient().getClientId());
		  tokenServices.setRestTemplate(template);
		  filter.setTokenServices(tokenServices);
		  return filter;
		}
	
	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
	  return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
	  return new ClientResources();
	}
	
	@Bean
	@ConfigurationProperties("google")
	public ClientResources google() {
	  return new ClientResources();
	}
	
	 @Bean
		public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
			FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
			registration.setFilter(filter);
			registration.setOrder(-100);
			return registration;
		}
	 
	 class ClientResources {

		  @NestedConfigurationProperty
		  private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

		  @NestedConfigurationProperty
		  private ResourceServerProperties resource = new ResourceServerProperties();

		  public AuthorizationCodeResourceDetails getClient() {
		    return client;
		  }

		  public ResourceServerProperties getResource() {
		    return resource;
		  }
		}
	
	 
	 @Configuration
	 @EnableResourceServer
	 protected static class ResourceServerConfiguration
	     extends ResourceServerConfigurerAdapter {
	   @Override
	   public void configure(HttpSecurity http) throws Exception {
	     http
	       .antMatcher("/me")
	       .authorizeRequests().anyRequest().authenticated();
	   }
	 }
	 
	 @RequestMapping({ "/user", "/me" })
	 public Map<String, String> user(Principal principal) {
	   Map<String, String> map = new LinkedHashMap<>();
	   map.put("name", principal.getName());
	   return map;
	 }
	
	public static void main(String[] args) {
		SpringApplication.run(SsoPracticeApplication.class, args);
	}
}
