
import java.security.PrivilegedAction
import java.util.Base64

import akka.http.scaladsl.model.headers._
import akka.http.scaladsl.server.AuthenticationFailedRejection
import akka.http.scaladsl.server._
import akka.http.scaladsl.server.AuthenticationFailedRejection.CredentialsMissing
import akka.http.scaladsl.server.directives.BasicDirectives.{extract, provide}
import akka.http.scaladsl.server.directives.RouteDirectives.reject
import javax.security.auth.Subject
import javax.security.auth.kerberos.KerberosPrincipal
import javax.security.auth.login.LoginContext
import org.ietf.jgss.{GSSContext, GSSCredential, GSSManager, GSSName}

import scala.collection.JavaConverters._
import scala.util.{Failure, Success, Try}

object AuthenticationDirective {
  sealed trait AuthAnswer

  case class Challenge(challenge: Option[String]) extends AuthAnswer
  case class Principal(name: GSSName) extends AuthAnswer

  def createLoginContext(principal: String): LoginContext = {
    val servicePrincipal = new KerberosPrincipal(principal)
    val subject = new Subject(false, Set(servicePrincipal).asJava, Set.empty.asJava, Set.empty.asJava)
    val loginContext = new LoginContext("name", subject)

    loginContext.login()
    loginContext
  }

  def kerberos(loginContext: LoginContext)(clientToken : Array[Byte]) = {

    def withContext[T](manager: GSSManager)(f: GSSContext => T): T = {
      val ctx = manager.createContext(Option.empty[GSSCredential].orNull)
      val result = try
        f(ctx)
      finally
        ctx.dispose()

      result
    }

    def principalOrChallenge(context: GSSContext, challenge: Array[Byte]) = {
      val principal = if (context.isEstablished) Some(context.getSrcName) else None
      val base64 = Option(challenge).map(Base64.getEncoder.encodeToString(_))
      principal.map(Principal).getOrElse(Challenge(base64))
    }

    def doAs[T](ctx: LoginContext)(f: => T) : T =
      Subject.doAs(ctx.getSubject, new PrivilegedAction[T] {
        override def run() = f
      })


    doAs(loginContext) {
      val gssManager = GSSManager.getInstance()
      withContext(gssManager) { ctx =>
        for {
          challenge <- Try(ctx.acceptSecContext(clientToken, 0, clientToken.length)) match {
            case Success(value) => Right(value).right
            case Failure(exception) => exception.printStackTrace()
              Left(s"${exception.toString} ${exception.getMessage}").right
          }
          answer <- Right(principalOrChallenge(ctx, challenge)).right
        } yield answer
      }
    }
  }

  def negotiationRejection(challenge: Challenge): AuthenticationFailedRejection = {
    challenge.challenge match {
      case Some(ch) => val header = RawHeader(
        "WWW-Authenticate",
        s"Negotiate $ch"
      )
        AuthenticationFailedRejection(CredentialsMissing, HttpChallenge(header.value, None))
      case None => AuthenticationFailedRejection(CredentialsMissing, HttpChallenge("Negotiate", None))
    }
  }

  def extractToken(s: String) = {
    if(s.startsWith("Negotiate"))
      Some(Base64.getDecoder.decode(s.substring("Negotiate ".length)))
    else None
  }

  def getAuthFromHeader(requestContext: RequestContext) = {
    requestContext.request.headers.find(header => header.name() == "Authorization")
      .flatMap(header => extractToken(header.value()))
      .map(token => {
        println("TOKEN: " + Base64.getEncoder.encodeToString(token))
        val r = kerberos(createLoginContext("HTTP/045fd803a9b2"))(token)
        println(r)
        r
      }
      )
      .getOrElse({println("init"); Right(Challenge(None))})
  }

  def spnego: Directive[Tuple1[GSSName]] = {
    extract(ctx => {
      print("HEADER: ")
      ctx.request.headers.foreach(println)
      getAuthFromHeader(ctx)
    }).flatMap{
      case Right(auth) => auth match {
        case c: Challenge =>
          println("challenge")
          reject(negotiationRejection(c))
        case Principal(p) =>
          println("provide")
          println(p.toString)
          provide(p)
      }
      case Left(msg) => reject
    }
  }
}