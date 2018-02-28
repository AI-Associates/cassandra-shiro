package associates.ai.cassandra.auth.realm;

import javax.naming.directory.SearchControls;

/**
 * Wraps JNDI SearchControls' scopes in a type safe enum.
 * @see SearchControls
 */
public enum SearchScope {
    /**
     * @see SearchControls#OBJECT_SCOPE
     */
    OBJECT_SCOPE(SearchControls.OBJECT_SCOPE),

    /**
     * @see SearchControls#ONELEVEL_SCOPE
     */
    ONELEVEL_SCOPE(SearchControls.ONELEVEL_SCOPE),

    /**
     * @see SearchControls#SUBTREE_SCOPE
     */
    SUBTREE_SCOPE(SearchControls.SUBTREE_SCOPE);

    public final int intValue;

    SearchScope(int intValue) {
        this.intValue = intValue;
    }
}
