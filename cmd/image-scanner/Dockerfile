FROM alpine:3.23
RUN apk --no-cache add ca-certificates git
COPY image-scanner /usr/local/bin/image-scanner
COPY contrib/*.tpl contrib/
ENTRYPOINT ["image-scanner"]
