FROM python:3.11-slim

# kerberos server configuration

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    KRB5_CONFIG=/etc/krb5.conf \
    KRB5_KDC_PROFILE=/var/kerberos/krb5kdc/kdc.conf \
    KRB5_TRACE=/dev/stdout

RUN set -eux; \
    apt-get update -y; \
    apt-get install \
    supervisor \
    krb5-kdc-ldap \
    krb5-pkinit \
    krb5-admin-server \
    wamerican \
    libsasl2-modules-gssapi-mit \
    --no-install-recommends -y

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
    mkdir -pv /var/log/supervisord/;\
    mkdir /server;\
    mkdir /certs;

RUN pip install fastapi
COPY config_server.py /server/
# RUN openssl req -nodes -new -x509 -keyout /certs/krbkey.pem -out /certs/krbcert.pem -addext "subjectAltName=DNS:krb5" -subj '/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=Multifactor/CN=krb5'
EXPOSE 8000
COPY supervisord.conf /etc/supervisord.conf
CMD ["supervisord", "-n", "-c", "/etc/supervisord.conf"]
