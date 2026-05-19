FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    squid-openssl \
    openssl \
    apache2-utils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/squid/ssl_cert \
             /etc/squid/auth \
             /var/cache/squid \
             /var/log/squid \
             /var/lib/squid && \
    chown proxy:proxy /etc/squid/ssl_cert \
                      /etc/squid/auth \
                      /var/cache/squid \
                      /var/log/squid \
                      /var/lib/squid

COPY squid.conf /etc/squid/squid.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3128

ENTRYPOINT ["/entrypoint.sh"]
