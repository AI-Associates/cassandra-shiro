package associates.ai.cassandra.auth

import org.apache.cassandra.auth.AllowAllAuthorizer
import org.apache.cassandra.auth.PasswordAuthenticator.{PASSWORD_KEY, USERNAME_KEY}
import org.apache.cassandra.config.DatabaseDescriptor
import org.apache.cassandra.exceptions.{AuthenticationException, ConfigurationException}
import org.apache.shiro.SecurityUtils
import org.apache.shiro.authc.UsernamePasswordToken
import org.scalatest.{Matchers, WordSpec}

class ShiroPlainAuthenticatorTest extends WordSpec with Matchers {
  "ShiroPlainAuthenticator" should {
    "set up shiro security manager with shiro.ini on the classpath" in {
      val auth = new ShiroPlainAuthenticator()
      auth.setup()

      val manager = SecurityUtils.getSecurityManager

      val subject = SecurityUtils.getSubject()
      val token = new UsernamePasswordToken("root", "passw0rd")
      subject.login(token)

      subject shouldBe 'authenticated
    }

    "fail to validate config if AllowAllAuthorizer is used" in {
      val authorizer = new AllowAllAuthorizer()
      DatabaseDescriptor.setAuthorizer(authorizer)

      val auth = new ShiroPlainAuthenticator()

      intercept[ConfigurationException](auth.validateConfiguration())
    }

    "not allow legacy logins" in {
      import scala.collection.JavaConverters._
      val auth = new ShiroPlainAuthenticator()
      auth.setup()

      val thriftCredentials = Map(USERNAME_KEY -> "root", PASSWORD_KEY -> "passw0rd")
      intercept[AuthenticationException] {
        auth.legacyAuthenticate(thriftCredentials.asJava)
      }
    }
  }
}
