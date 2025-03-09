FROM perl:5.36.0
WORKDIR /app
COPY server.pl /app/server.pl
RUN cpanm Mojolicious Authen::WebAuthn
EXPOSE 3000
CMD ["morbo", "--listen=http://*:3000", "/app/server.pl"]
