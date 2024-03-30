package io.imi.aot_test.auth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class CheckRolesLdapAuthenticationProvider implements AuthenticationProvider {

    //@Transactional
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        if (OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication)) {
            return true;
        }
        return false;
    }
}
