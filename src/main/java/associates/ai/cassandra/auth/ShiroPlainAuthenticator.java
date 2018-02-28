package associates.ai.cassandra.auth;

import com.google.common.collect.ImmutableSet;
import org.apache.cassandra.auth.*;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;

public class ShiroPlainAuthenticator implements IAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(ShiroPlainAuthenticator.class);

    public boolean requireAuthentication() {
        return true;
    }

    public Set<? extends IResource> protectedResources() {
        return ImmutableSet.of(DataResource.table(SchemaConstants.AUTH_KEYSPACE_NAME, AuthKeyspace.ROLES));
    }

    public void validateConfiguration() throws ConfigurationException {
        // this should be safe to call here, see org.apache.cassandra.auth.AuthConfig.applyAuth()

        IAuthorizer authorizer = DatabaseDescriptor.getAuthorizer();
        if (authorizer instanceof AllowAllAuthorizer) {
           throw new ConfigurationException("ShiroPlainAuthenticator cannot be used with AllowAllAuthorizer!");
        }
    }

    public void setup() {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
    }

    public SaslNegotiator newSaslNegotiator(InetAddress inetAddress) {
        return new ShiroPlainSaslNegotiator();
    }

    public AuthenticatedUser legacyAuthenticate(Map<String, String> map) throws AuthenticationException {
        throw new AuthenticationException("Legacy login is not supported.");
    }

}