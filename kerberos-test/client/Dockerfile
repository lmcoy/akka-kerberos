FROM debian:stretch

EXPOSE 8090

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -qq update
RUN apt-get -qq install apt-transport-https locales krb5-user curl openjdk-8-jre python python-gssapi
RUN apt-get -qq clean

RUN locale-gen "en_US.UTF-8"
RUN echo "LC_ALL=\"en_US.UTF-8\"" >> /etc/default/locale

COPY krb5.conf /etc/

ENV REALM EXAMPLE.COM
ENV KADMIN_PRINCIPAL kadmin/admin
ENV KADMIN_PASSWORD Password123

COPY run.sh config.sh http_get.py  jaas.conf /tmp/
COPY akka-kerberos-assembly-0.1.jar /tmp/
CMD /tmp/run.sh