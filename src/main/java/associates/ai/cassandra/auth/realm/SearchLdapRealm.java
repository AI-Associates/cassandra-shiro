package associates.ai.cassandra.auth.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.ldap.JndiLdapContextFactory;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

/**
 * Realm that searches users' DNs in LDAP based on given pattern and username,
 * then authenticates users by performing a bind with found DN and original password.
 */
public class SearchLdapRealm extends AuthenticatingRealm {
    private static final String UID_PLACEHOLDER = "{0}";

    private static final Logger logger = LoggerFactory.getLogger(SearchLdapRealm.class);

    private String searchFilterPattern;

    private String searchContext;

    private String searchScope;

    private LdapContextFactory contextFactory;

    /**
     * Default constructor.
     */
    public SearchLdapRealm() {
        super();
        setAuthenticationTokenClass(UsernamePasswordToken.class);
        this.contextFactory = new JndiLdapContextFactory();
    }

    public LdapContextFactory getContextFactory() {
        return contextFactory;
    }

    public void setContextFactory(LdapContextFactory contextFactory) {
        this.contextFactory = contextFactory;
    }

    /**
     * @return search filter pattern
     * @see #setSearchFilterPattern(String)
     */
    public String getSearchFilterPattern() {
        return searchFilterPattern;
    }

    /**
     * Sets the search filter pattern to use to search User DN in configured LDAP directory.
     * <p>
     * An example a pattern could look like this:
     * <p>
     * <pre>uid={0}</pre>
     *
     * @param searchFilterPattern filter pattern to use with placeholder {@code {0}} for supplied username
     */
    public void setSearchFilterPattern(String searchFilterPattern) {
        this.searchFilterPattern = searchFilterPattern;
    }

    /**
     * Gets the name of LDAP context to be searched.
     *
     * @return name of LDAP context to be searched.
     * @see #setSearchContext(String)
     */
    public String getSearchContext() {
        return searchContext;
    }

    /**
     * Sets the base LDAP context to be searched. For example, you could set this to your LDAP root object like this:
     * <pre>dn=my-company,dn=com</pre>
     *
     * or, use an organizational unit like:
     * <pre>ou=users,ou=people,dn=my-company,dn=com</pre>
     *
     * @param searchContext name of context to be searched
     */
    public void setSearchContext(String searchContext) {
        this.searchContext = searchContext;
    }


    /**
     * Searches for users' full DNs using system LDAP context.
     *
     * @param username name of the user to find a DN for
     * @return DN of user
     * @throws NamingException
     */
    private String searchUserDN(String username) throws NamingException {

        SearchControls sc = getSearchControls();
        String filter = searchFilterPattern.replace(UID_PLACEHOLDER, username);

        logger.debug("Searching for [{}] in [{}]", filter, searchContext);

        LdapContext systemCtx = null;
        try {
            systemCtx = contextFactory.getSystemLdapContext();

            NamingEnumeration<SearchResult> search = systemCtx.search(searchContext, filter, sc);
            String userDN = null;
            if (search.hasMore()) {
                SearchResult result = search.next();
                userDN = result.getNameInNamespace();

                logger.debug("Found result {}", userDN);
            } else {
                throw new AuthenticationException("Couldn't find any object matching filter [" + filter + "]");
            }

            if (search.hasMore()) {
                logger.error("Found more than one object matching filter [{}] in [{}] with search scope [{}]. " +
                        "Limit the search scope or use a more specific search context.", filter, searchContext, searchScope);
                throw new AuthenticationException("Couldn't find unique DN for username ["+ username +"]");
            }

            return userDN;
        } finally {
            LdapUtils.closeContext(systemCtx);
        }

    }

    private SearchControls getSearchControls() {
        SearchControls sc = new SearchControls();
        if (this.searchScope == null) throw new ConfigurationException("SearchLdapRealm.searchScope is not set!");
        SearchScope searchScope = SearchScope.valueOf(this.searchScope);
        sc.setSearchScope(searchScope.intValue);
        return sc;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        String foundPrincipal;

        LdapContext userCtx = null;
        try {
            foundPrincipal = searchUserDN(token.getPrincipal().toString());

            Object credentials = token.getCredentials();
            userCtx = contextFactory.getLdapContext(foundPrincipal, credentials);

            return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
        } catch (NamingException ne) {
            throw new AuthenticationException(ne);
        } finally {
            LdapUtils.closeContext(userCtx);
        }
    }

    /**
     * Gets the search scope.
     *
     * @see #setSearchScope(String)
     */
    public String getSearchScope() {
        return searchScope;
    }

    /**
     * Sets the search scope. Names correspond to JNDI search scopes.
     *
     * @param searchScope search scope name
     * @see SearchScope
     * @see SearchControls
     */
    public void setSearchScope(String searchScope) {
        this.searchScope = searchScope;
    }
}
