package associates.ai.cassandra.auth;

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;


public class ShiroPlainSaslNegotiator implements IAuthenticator.SaslNegotiator {

    private static Logger logger = LoggerFactory.getLogger(ShiroPlainSaslNegotiator.class);


    private boolean saslDone = false;
    private UsernamePasswordToken token;


    // ﻿https://tools.ietf.org/html/rfc4616
    public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
        byte[] authcid = null;
        byte[] passwd = null;

        int end = clientResponse.length;
        for (int i = clientResponse.length - 1; i >= 0; i--) {
            if (clientResponse[i] == 0) {
                if (passwd == null) passwd = Arrays.copyOfRange(clientResponse, i + 1, end);
                else if (authcid == null) authcid = Arrays.copyOfRange(clientResponse, i + 1, end);
                else logger.debug("skipping first {} bytes (authzid)", i);
                end = i;
            }
        }

        if (authcid == null) throw new AuthenticationException("Username was null");
        if (passwd == null) throw new AuthenticationException("Password was null");

        String user = new String(authcid, java.nio.charset.StandardCharsets.UTF_8);
        String pass = new String(passwd, java.nio.charset.StandardCharsets.UTF_8);

        logger.debug("SASL PLAIN user [{}]]", user);

        token = new UsernamePasswordToken(user, pass, false);
        saslDone = true;

        return null;
    }

    public boolean isComplete() {
        return saslDone;
    }

    public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
        if (saslDone) {
            Subject subject = SecurityUtils.getSubject();

            try {
                subject.login(token);
                return new AuthenticatedUser(token.getUsername());
            } catch (org.apache.shiro.authc.AuthenticationException ae) {
                logger.error("Shiro auth failed", ae);
                throw new AuthenticationException("Failed to login with LDAP");
            }
        }
        else throw new AuthenticationException("not finished authenticating with sasl");
    }
}