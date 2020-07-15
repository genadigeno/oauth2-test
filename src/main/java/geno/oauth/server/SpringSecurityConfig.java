package geno.oauth.server;

import geno.oauth.server.data.UserRepository;
import geno.oauth.server.models.Role;
import geno.oauth.server.models.User;
import geno.oauth.server.security.basic.UserGrantedAuthority;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.annotation.PostConstruct;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private static List<String> clients = Arrays.asList("google", "facebook");
    //------------------------------------------------------------------------------------------------------------------

    private UserRepository userRepository;

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    private UserDetailsService userDetailsService;

    public UserRepository getUserRepository() {
        return userRepository;
    }

    @Autowired
    @Qualifier("userRepository")
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    //------------------------------------------------------------------------------------------------------------------

    @Override
    public void configure(WebSecurity web) throws Exception { super.configure(web); }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/", "/login", "/403").permitAll()
            .antMatchers("/home").hasAnyRole("USER", "ADMIN")
            .antMatchers("/admin/**").hasRole("ADMIN")
            .and().exceptionHandling().accessDeniedPage("/403")
            .and().oauth2Login().loginPage("/login")
                //.clientRegistrationRepository(clientRegistrationRepository())
                .userInfoEndpoint().userService(oAuth2UserService())
                .oidcUserService(oidUserService())
                .and().successHandler(oath2AuthenticationSuccessHandler())
            .and().formLogin()
                .loginPage("/login").loginProcessingUrl("/login").defaultSuccessUrl("/home")
                .permitAll()
            .and()
                .logout()
                .logoutSuccessHandler(logoutSuccessHandler())
            .permitAll();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth){
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    @Qualifier("bCryptPasswordEncoder")
    public PasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Qualifier("noopPasswordEncode")
    public PasswordEncoder noopPasswordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(noopPasswordEncoder());
        return authenticationProvider;
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(){
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                                   Authentication authentication) throws IOException, ServletException {

                if (authentication != null && authentication.getDetails() != null) {
                    try {
                        request.getSession().invalidate();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                response.setStatus(HttpServletResponse.SC_OK);
                response.sendRedirect("/");
            }
        };
    }

    @Bean
    public AuthenticationSuccessHandler oath2AuthenticationSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                Authentication authentication) throws IOException, ServletException {

                System.out.println("oath2AuthenticationSuccessHandler() has been called!");
                String userName = authentication.getName();
                System.out.println("[AuthenticationSuccessHandler] : User = " + userName);

                User user = userRepository.findByUserName(userName);
                if (user == null){
                    authentication.setAuthenticated(false);
                    request.getSession().invalidate();
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.sendRedirect("/");
                } else {
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.sendRedirect("/home");
                }
            }
        };
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidUserService(){
        return new OAuth2UserService<OidcUserRequest, OidcUser>() {
            @Override
            public OidcUser loadUser(OidcUserRequest oidcUserRequest) throws OAuth2AuthenticationException {
                Map<String, Object> additionalParameters = oidcUserRequest.getAdditionalParameters();
                Map<String, Object> claims = oidcUserRequest.getIdToken().getClaims();

                String email = (String) claims.get("email");

                return new OidcUser() {
                    @Override
                    public Map<String, Object> getClaims() {
                        return oidcUserRequest.getIdToken().getClaims();
                    }

                    @Override
                    public OidcUserInfo getUserInfo() {
                        return new OidcUserInfo(claims);
                    }

                    @Override
                    public OidcIdToken getIdToken() {
                        return oidcUserRequest.getIdToken();
                    }

                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        Role role = new Role();
                        role.setRole("ROLE_USER");
                        List<GrantedAuthority> grantedAuthorityList = new ArrayList<GrantedAuthority>();
                        grantedAuthorityList.add(new UserGrantedAuthority(role));
                        return grantedAuthorityList;
                    }

                    @Override
                    public Map<String, Object> getAttributes() {
                        return additionalParameters;
                    }

                    @Override
                    public String getName() {
                        return email != null ? email : "DEFAULT_USER";
                    }
                };
            }
        };
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService(){
        System.out.println(1);
        return new OAuth2UserService<OAuth2UserRequest, OAuth2User>() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
                System.out.println(2);
                return new OAuth2User() {
                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        Role role = new Role();
                        role.setRole("ROLE_USER");
                        List<GrantedAuthority> grantedAuthorityList = new ArrayList<GrantedAuthority>();
                        System.out.println();
                        grantedAuthorityList.add(new UserGrantedAuthority(role));
                        return grantedAuthorityList;
                    }

                    @Override
                    public Map<String, Object> getAttributes() {
                        return oAuth2UserRequest.getAdditionalParameters();
                    }

                    @Override
                    public String getName() {
                        return "username";
                    }
                };
            }
        };
    }
    //==================================================================================================================

    /*private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    public String googleClientId;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    public String googleSecretKey;

    @Value("${spring.security.oauth2.client.registration.facebook.client-id}")
    public String facebookClientId;
    @Value("${spring.security.oauth2.client.registration.facebook.client-secret}")
    public String facebookSecretKey;

    @PostConstruct
    public void init(){
        System.out.println("facebookClientId = " + facebookClientId);
        System.out.println("googleClientId = " + googleClientId);
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = new ArrayList<ClientRegistration>();
        registrations.add(getRegistration("facebook"));
        registrations.add(getRegistration("google"));

        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration(String client) {
//        String clientId = environment.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");
//        String clientSecret = environment.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");
//        if (clientId == null) { return null; }
        if (client.equals("google")) {
//            return CommonOAuth2Provider.GOOGLE.getBuilder(client).clientId(googleClientId).clientSecret(googleSecretKey).build();
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId("531089080960-vu0hlmfssab5s9g3qv401dohigc1s64j.apps.googleusercontent.com")
                    .clientSecret(googleSecretKey).build();
        }
        if (client.equals("facebook")) {
//            return CommonOAuth2Provider.FACEBOOK.getBuilder(client).clientId(facebookClientId).clientSecret(facebookSecretKey).build();
            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId("208223840483753")
                    .clientSecret(facebookSecretKey).build();
        }
        return null;
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }*/
}
