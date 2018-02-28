package associates.ai.cassandra.auth

import org.apache.cassandra.auth.CassandraAuthorizer
import org.apache.cassandra.config.DatabaseDescriptor
import org.apache.cassandra.exceptions.AuthenticationException
import org.apache.shiro.SecurityUtils
import org.apache.shiro.config.IniSecurityManagerFactory
import org.scalatest.{BeforeAndAfterAll, Matchers, WordSpec}

class ShiroPlainSaslNegotiatorSpec extends WordSpec with Matchers with BeforeAndAfterAll {

  "LDAP SASL Negotiator" when {
    "logging in with valid credentials" should {
      "return an AuthorizedUser with provided username" in {
        val negotiator = new ShiroPlainSaslNegotiator

        val user = "root"
        val password = "passw0rd"

        val saslAuth = saslAuthBytes(user, password)

        val response = negotiator.evaluateResponse(saslAuth)

        response shouldBe null

        negotiator shouldBe 'complete

        val authenticatedUser = negotiator.getAuthenticatedUser

        authenticatedUser.getName shouldEqual user
      }
    }
    "logging in with invalid credentials" should {
      "throw an exception" in {
        val negotiator = new ShiroPlainSaslNegotiator
        val user = "user"
        val password = "pass"

        val saslAuth = saslAuthBytes(user, password)

        val response = negotiator.evaluateResponse(saslAuth)

        negotiator shouldBe 'complete

        intercept[AuthenticationException](negotiator.getAuthenticatedUser)
      }
    }

    "unparseable data in SASL negotation is sent" should {
      "throw an exception" in {
        val negotiator = new ShiroPlainSaslNegotiator

        val garbage = Array[Byte](4,8,15,16,23,42)

        intercept[AuthenticationException](negotiator.evaluateResponse(garbage))
      }
    }
  }


  private def saslAuthBytes(user: String, password: String) = {
    // variable names wrapped with {} on purpose - scala will use those as part of identifier
    s"\u0000${user}\u0000${password}".getBytes("UTF-8")
  }

  override def beforeAll() = {
    // cassandra magic
    DatabaseDescriptor.clientInitialization()
    val authorizer = new CassandraAuthorizer()
    DatabaseDescriptor.setAuthorizer(authorizer)

    val factory = new IniSecurityManagerFactory("classpath:shiro.ini")
    val securityManager = factory.getInstance
    SecurityUtils.setSecurityManager(securityManager)
  }
}
