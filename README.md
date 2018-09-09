# Playground for akka http with kerberos auth

## Test environment:

After building a fat jar with `sbt assembly`, run

    cp ../target/scala-2.12/akka-kerberos-assembly-0.1.jar client/
    docker-compose build
    docker-compose up

in `kerberos-test`
