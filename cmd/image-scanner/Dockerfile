FROM alpine:3.24.1
RUN apk --no-cache add ca-certificates git
COPY image-scanner /usr/local/bin/image-scanner
COPY contrib/*.tpl contrib/
ENTRYPOINT ["image-scanner"]
