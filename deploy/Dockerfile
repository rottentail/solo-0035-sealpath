FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /sealpath ./cmd/sealpath
FROM alpine:3
RUN addgroup -S sealpath && adduser -S -G sealpath sealpath && mkdir /state && chown sealpath:sealpath /state
USER sealpath
COPY --from=build /sealpath /usr/local/bin/sealpath
EXPOSE 8435
ENTRYPOINT ["/usr/local/bin/sealpath", "-listen", "0.0.0.0:8435", "-state", "/state/sealpath.json"]
