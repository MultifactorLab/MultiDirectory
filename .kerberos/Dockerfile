# Dockerfile - kdc-server

FROM debian:buster-slim

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update -y; \
    apt-get install ntp krb5-admin-server krb5-kdc supervisor --no-install-recommends -y

# remove default configuration
RUN rm -r /var/lib/krb5kdc/
RUN rm -r /etc/krb5kdc/
RUN rm -rf /var/lib/krb5kdc/principal

# kerberos server configuration
ENV KRB5_CONFIG=/etc/krb5.conf \
    KRB5_KDC_PROFILE=/var/kerberos/krb5kdc/kdc.conf \
    KRB5_TRACE=/dev/stdout
RUN mkdir -pv /var/kerberos/krb5kdc

COPY kdc.conf /var/kerberos/krb5kdc/kdc.conf
# COPY kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
COPY krb5.conf /etc/krb5.conf

RUN mkdir -pv /var/log/kerberos/

RUN touch /var/log/kerberos/krb5.log;\
    touch /var/log/kerberos/kadmin.log;\
    touch /var/log/kerberos/krb5lib.log;\
    mkdir -pv /var/log/supervisord;\
    touch /var/log/supervisord/supervisord.log

RUN kdb5_util -r MD.MULTIFACTOR.DEV -P superpassword create -s
RUN echo "superadmin/admin@MD.MULTIFACTOR.DEV *\n" > /var/kerberos/krb5kdc/kadm5.acl
EXPOSE 8000

COPY supervisord.conf /etc/supervisord.conf

CMD ["supervisord", "-n", "-c", "/etc/supervisord.conf"]
