package associates.ai.cassandra.auth.realm

import javax.naming.NamingEnumeration
import javax.naming.directory.{SearchControls, SearchResult}
import javax.naming.ldap.LdapContext

import org.apache.shiro.authc.{AuthenticationException, UsernamePasswordToken}
import org.apache.shiro.realm.ldap.LdapContextFactory
import org.scalamock.scalatest.MockFactory
import org.scalatest.{Matchers, WordSpec}

class SearchLdapRealmTest extends WordSpec with Matchers with MockFactory {
  "SearchLdapRealm" should {
    "search for objects in LDAP using given pattern and system account" in {

      val contextName = "dn=room,dn=the"
      val username = "mark"
      val password = "johnny_is_my_best_friend"
      val filterPattern = "uid={0}"
      val userDn = s"uid=mark,ou=people,$contextName"

      val token = new UsernamePasswordToken(username, password)

      val systemContext = mock[LdapContext]

      val enumeration = mock[NamingEnumeration[SearchResult]]
      val result = mock[SearchResult]
      inSequence {
        (enumeration.hasMore: () => Boolean).expects().returning(true)
        (enumeration.next: () => SearchResult).expects().returning(result)
        (result.getNameInNamespace: () => String).expects().returning(userDn)
        (enumeration.hasMore: () => Boolean).expects().returning(false)
      }


      val expectedFilter = filterPattern.replace("{0}", username)

      (systemContext.search(_: String, _: String, _: SearchControls))
        .expects(contextName, expectedFilter, *)
        .returning(enumeration)

      (systemContext.close: () => Unit).expects().once()


      val ctxFactory = mock[LdapContextFactory]

      (ctxFactory.getSystemLdapContext _).expects().returning(systemContext)

      val userCtx = mock[LdapContext]
      (ctxFactory.getLdapContext(_: Any, _: Any)).expects(userDn, token.getCredentials).returning(userCtx)
      (userCtx.close: () => Unit).expects()

      val realm = new SearchLdapRealm()

      realm.setContextFactory(ctxFactory)
      realm.setSearchContext(contextName)
      realm.setSearchScope(SearchScope.SUBTREE_SCOPE.name)
      realm.setSearchFilterPattern(filterPattern)

      realm.doGetAuthenticationInfo(token)
    }

    "fail" when {
      "there's no match in LDAP" in {
        val contextName = "ou=people,dn=room,dn=the"
        val username = "doggie"
        val password = "youre_my_fav_customer"
        val filterPattern = "uid={0}"
        val expectedFilter = filterPattern.replace("{0}", username)


        val token = new UsernamePasswordToken(username, password)

        val systemContext = mock[LdapContext]

        val enumeration = mock[NamingEnumeration[SearchResult]]
        val result = mock[SearchResult]

        (enumeration.hasMore: () => Boolean).expects().returning(false)


        (systemContext.search(_: String, _: String, _: SearchControls))
          .expects(contextName, expectedFilter, *)
          .returning(enumeration)

        (systemContext.close: () => Unit).expects().once()

        val ctxFactory = mock[LdapContextFactory]

        (ctxFactory.getSystemLdapContext _).expects().returning(systemContext)

        val realm = new SearchLdapRealm()

        realm.setContextFactory(ctxFactory)
        realm.setSearchContext(contextName)
        realm.setSearchScope(SearchScope.SUBTREE_SCOPE.name)
        realm.setSearchFilterPattern(filterPattern)

        intercept[AuthenticationException] { realm.doGetAuthenticationInfo(token) }
      }

      "there's more than one matching object" in {
        val contextName = "ou=people,dn=room,dn=the"
        val username = "lisa"
        val password = "icannottalkrightnow"
        val filterPattern = "uid={0}"
        val expectedFilter = filterPattern.replace("{0}", username)

        val userDn = s"$expectedFilter,$contextName"

        val token = new UsernamePasswordToken(username, password)

        val systemContext = mock[LdapContext]

        val enumeration = mock[NamingEnumeration[SearchResult]]
        val result = mock[SearchResult]

        (enumeration.hasMore: () => Boolean).expects().returning(true).atLeastTwice()
        (enumeration.next: () => SearchResult).expects().returning(result)

        (systemContext.search(_: String, _: String, _: SearchControls))
          .expects(contextName, expectedFilter, *)
          .returning(enumeration)

        (result.getNameInNamespace: () => String).expects().returning(userDn).atLeastOnce()

        (systemContext.close: () => Unit).expects().once()

        val ctxFactory = mock[LdapContextFactory]

        (ctxFactory.getSystemLdapContext _).expects().returning(systemContext)

        val realm = new SearchLdapRealm()

        realm.setContextFactory(ctxFactory)
        realm.setSearchContext(contextName)
        realm.setSearchScope(SearchScope.SUBTREE_SCOPE.name)
        realm.setSearchFilterPattern(filterPattern)

        intercept[AuthenticationException] { realm.doGetAuthenticationInfo(token) }
      }
    }
  }
}
