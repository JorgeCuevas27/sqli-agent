# NAXSI (WAF de nginx) como reverse-proxy a DVWA. Compila nginx + el modulo NAXSI desde el repo
# oficial (wargio/naxsi) — no hay imagen prebuilt. Basado en el Dockerfile oficial de NAXSI.
FROM alpine:latest AS build
ENV NGINX_VERSION=nginx-1.28.0
RUN apk add --no-cache openssl-dev pcre2-dev zlib-dev wget build-base git
RUN git clone --depth 1 --recurse-submodules https://github.com/wargio/naxsi.git /src/naxsi
RUN cd /tmp && wget -q http://nginx.org/download/${NGINX_VERSION}.tar.gz && tar -zxf ${NGINX_VERSION}.tar.gz \
 && cd ${NGINX_VERSION} \
 && sed -i 's#NGX_MAX_ERROR_STR   2048#NGX_MAX_ERROR_STR   8192#g' src/core/ngx_log.h \
 && ./configure --with-http_ssl_module --with-http_realip_module --with-http_v2_module \
      --add-dynamic-module=/src/naxsi/naxsi_src --prefix=/nginx \
      --http-log-path=/nginx/logs/access.log --error-log-path=/nginx/logs/error.log \
 && make -j"$(nproc)" && make install
RUN cp -r /src/naxsi/naxsi_rules /nginx/naxsi && mkdir -p /nginx/html

FROM alpine:latest
RUN apk add --no-cache openssl pcre2 zlib
COPY --from=build /nginx /nginx
COPY nginx.conf /nginx/conf/nginx.conf
COPY dvwa.conf /nginx/conf/sites-enabled/website.conf
RUN ln -sf /dev/stdout /nginx/logs/access.log && ln -sf /dev/stderr /nginx/logs/error.log
EXPOSE 8080
STOPSIGNAL SIGQUIT
CMD ["/nginx/sbin/nginx", "-g", "daemon off;"]
