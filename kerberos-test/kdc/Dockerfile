FROM debian:stretch

EXPOSE 749 88

ENV DEBIAN_FRONTEND noninteractive
# The -qq implies --yes
RUN apt-get -qq update
RUN apt-get -qq install locales krb5-kdc krb5-admin-server
RUN apt-get -qq clean

RUN locale-gen "en_US.UTF-8"
RUN echo "LC_ALL=\"en_US.UTF-8\"" >> /etc/default/locale

ENV REALM EXAMPLE.COM
ENV KADMIN_PRINCIPAL kadmin/admin
ENV KADMIN_PASSWORD Password123

COPY init-script.sh /tmp/
CMD /tmp/init-script.sh
