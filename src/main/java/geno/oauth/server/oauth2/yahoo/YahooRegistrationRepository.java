package geno.oauth.server.oauth2.yahoo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Repository;

//@Repository("yahooRegistrationRepository")
public class YahooRegistrationRepository implements ClientRegistrationRepository {

    @Value("${spring.security.oauth2.client.registration.yahoo.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.yahoo.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.yahoo.authorization-grant-type}")
    private String authorizationGrantType;

    @Value("${spring.security.oauth2.client.provider.yahoo.authorization-uri}")
    private String authorizationUri;

    @Value("${spring.security.oauth2.client.registration.yahoo.client-authentication-method}")
    private String clientAuthenticationMethod;

    @Value("${spring.security.oauth2.client.registration.yahoo.redirect-uri-template}")
    private String redirectUriTemplate;

    @Value("${spring.security.oauth2.client.registration.yahoo.scope}")
    private String scope;

    @Value("${spring.security.oauth2.client.provider.yahoo.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.provider.yahoo.user-info-authentication-method}")
    private String userInfoAuthenticationMethod;

    @Value("${spring.security.oauth2.client.provider.yahoo.user-info-uri}")
    private String userInfoUri;

    @Value("${spring.security.oauth2.client.provider.yahoo.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${spring.security.oauth2.client.provider.yahoo.user-name-attribute}")
    private String userNameAttributeName;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {

        return ClientRegistration
                .withRegistrationId("yahoo")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(new AuthorizationGrantType(authorizationGrantType))
                .authorizationUri(authorizationUri)
                .clientAuthenticationMethod(new ClientAuthenticationMethod(clientAuthenticationMethod))
                .jwkSetUri(jwkSetUri)
                .redirectUriTemplate(redirectUriTemplate)
                .registrationId("yahoo")
                .scope(scope.split(","))
                .userInfoAuthenticationMethod(new AuthenticationMethod(userInfoAuthenticationMethod))
                .userInfoUri(userInfoUri)
                .tokenUri(tokenUri)
                .userNameAttributeName(userNameAttributeName)
                .build();
    }

}
