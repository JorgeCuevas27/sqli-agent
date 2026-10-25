FROM owasp/modsecurity-crs:apache
# modsecurity-override.conf es el archivo que la imagen carga DESPUES del CRS para reglas propias.
COPY zzz-weak.conf /etc/modsecurity.d/modsecurity-override.conf
