import AuthenticationDirective.Config
import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import akka.http.scaladsl.Http
import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives._

import scala.concurrent.duration.Duration
import scala.concurrent.{Await, Future}

object Server extends App {

  implicit val system = ActorSystem("my-system")
  implicit val materializer = ActorMaterializer()
  // needed for the future flatMap/onComplete in the end
  implicit val executionContext = system.dispatcher

  if (args.length < 1) {
    println ("error: no principal as cmd line argument")
    sys.exit(1)
  }

  val config = Config(principal = args.head, jaasName = "name")

  val route =
    path("hello") {
      get {
        AuthenticationDirective.spnego(config) { principal =>
          complete(
            HttpEntity(ContentTypes.`text/html(UTF-8)`,
                       s"Hello ${principal.toString}"))
        }

      }
    }

  val bindingFuture = Http()
    .bindAndHandle(route, "0.0.0.0", 8090)
    .map { binding =>
      println(s"REST interface bound to ${binding.localAddress}")
      binding
    }
    .flatMap(_ => Future.never)

  Await.result(bindingFuture, Duration.Inf)
}
