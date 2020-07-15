package geno.oauth.server;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@PropertySource("classpath:application.properties")
public class OAuth2Test {

    @Autowired
    private Environment environment;

    @Test
    public void environmentTest(){
        Assert.assertNotNull(environment);
    }

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    public String googleClientId;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    public String googleSecretKey;

    @Value("${spring.security.oauth2.client.registration.facebook.client-id}")
    public String facebookClientId;
    @Value("${spring.security.oauth2.client.registration.facebook.client-secret}")
    public String facebookSecretKey;

    @Test
    public void clientTest(){
        Assert.assertNotNull(googleClientId);
        Assert.assertNotNull(googleSecretKey);
        Assert.assertNotNull(facebookClientId);
        Assert.assertNotNull(facebookSecretKey);

        Assert.assertNotEquals("", googleClientId);
        Assert.assertNotEquals("", googleSecretKey);
        Assert.assertNotEquals("", facebookClientId);
        Assert.assertNotEquals("", facebookSecretKey);
    }
}
