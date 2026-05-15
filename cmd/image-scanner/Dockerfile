FROM alpine:3.20.0

RUN apk --no-cache add ca-certificates git

WORKDIR /usr/local/bin

COPY image-scanner .
COPY contrib/*.tpl contrib/

RUN chmod +x image-scanner

# Command to run the application when the container starts
CMD ["./image-scanner"]
