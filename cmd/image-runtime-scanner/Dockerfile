FROM alpine:3.23
RUN apk --no-cache add ca-certificates git
COPY image-runtime-scanner /usr/local/bin/image-runtime-scanner
COPY contrib/*.tpl contrib/

# Expose the port on which the application will run
EXPOSE 8080

# Command to run the application when the container starts
CMD ["./image-runtime-scanner"]
