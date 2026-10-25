FROM owasp/modsecurity-crs:apache
# Regla propia que se carga despues del CRS (nombre zzz-* => ultimo en /etc/modsecurity.d/*.conf)
COPY zzz-weak.conf /etc/modsecurity.d/zzz-weak.conf
