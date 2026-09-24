FROM golang:1.22-alpine AS builder
WORKDIR /trojan-go
RUN apk add --no-cache git make
# download dependencies first so they are cached between source changes
COPY go.mod go.sum ./
RUN go mod download
# build from the local source tree, so local fixes are included in the image
COPY . .
ARG VERSION=custom
RUN mkdir -p build &&\
    CGO_ENABLED=0 go build -tags "full" -trimpath \
        -ldflags="-s -w -buildid= -X github.com/p4gefau1t/trojan-go/constant.Version=${VERSION}" \
        -o build/trojan-go . &&\
    wget https://github.com/v2fly/domain-list-community/raw/release/dlc.dat -O build/geosite.dat &&\
    wget https://github.com/v2fly/geoip/raw/release/geoip.dat -O build/geoip.dat &&\
    wget https://github.com/v2fly/geoip/raw/release/geoip-only-cn-private.dat -O build/geoip-only-cn-private.dat

FROM alpine
WORKDIR /
RUN apk add --no-cache tzdata ca-certificates
COPY --from=builder /trojan-go/build /usr/local/bin/
COPY --from=builder /trojan-go/example/server.json /etc/trojan-go/config.json

ENTRYPOINT ["/usr/local/bin/trojan-go", "-config"]
CMD ["/etc/trojan-go/config.json"]
