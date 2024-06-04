# Dockerfile - kdc-server

FROM python:3.11-slim

# kerberos server configuration

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    KRB5_CONFIG=/etc/krb5.conf \
    KRB5_KDC_PROFILE=/var/kerberos/krb5kdc/kdc.conf \
    KRB5_TRACE=/dev/stdout

RUN set -eux; \
    apt-get update -y; \
    apt-get install supervisor krb5-kdc-ldap --no-install-recommends -y

RUN rm -r /var/lib/krb5kdc/;\
    rm -r /etc/krb5kdc/;\
    rm -rf /var/lib/krb5kdc/principal;\
    mkdir -pv /var/kerberos/krb5kdc/principal;\
    mkdir -pv /var/log/kerberos/ \
    mkdir /etc/krb5.d \
    mkdir /etc/krb5kdc/ \
    chmod u=rwx,g=,o= /etc/krb5.d \
    touch /var/log/kerberos/krb5.log;\
    touch /var/log/kerberos/kadmin.log;\
    touch /var/log/kerberos/krb5lib.log;\
    mkdir -pv /var/log/supervisord/

RUN pip install fastapi
COPY config_server.py /

# kdb5_ldap_util -D "cn=mdadmin,ou=users,dc=md,dc=multifactor,dc=dev" stashsrvpw -f /etc/krb5.d/stash.keyfile cn=krbadmin,ou=users,dc=md,dc=multifactor,dc=dev
# kdb5_ldap_util -D "cn=mdadmin,ou=users,dc=md,dc=multifactor,dc=dev" create -subtrees "cn=kerberos,ou=services,dc=md,dc=multifactor,dc=dev" -r MD.MULTIFACTOR.DEV -s
EXPOSE 8000
# COPY supervisord.conf /etc/supervisord.conf
# CMD ["/usr/sbin/krb5kdc", "-n", "-r", "MD.MULTIFACTOR.DEV", "-P", "superpassword"]
CMD ["supervisord", "-n", "-c", "/etc/supervisord.conf"]
