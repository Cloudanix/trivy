FROM alpine:3.23
ARG TARGETARCH
RUN apk --no-cache add ca-certificates git
COPY image-scanner-${TARGETARCH} /usr/local/bin/image-scanner
COPY contrib/*.tpl contrib/
ENTRYPOINT ["image-scanner"]
