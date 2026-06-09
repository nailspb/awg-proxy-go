# Сборка статического бинаря под архитектуру роутера.
# Стадия build всегда нативная (BUILDPLATFORM) — Go кросс-компилирует сам, без эмуляции.
ARG GO_VERSION=1.25
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

# TARGETARCH/TARGETVARIANT автоматически проставляются buildx из --platform
# (linux/arm64, linux/arm/v7, linux/amd64, ...). При обычном docker build — из --build-arg.
ARG TARGETARCH=arm64
ARG TARGETVARIANT

# Версия и номер сборки (подставляются в футер веб-интерфейса):
#   docker build --build-arg VERSION=1.0.0 --build-arg BUILD=42 ...
ARG VERSION=alpha
ARG BUILD=0.0.1

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# GOARM берётся из варианта платформы (v7→7, v6→6); для не-arm игнорируется.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath \
    -ldflags="-s -w -X github.com/glebov/awg-proxy-go/internal/buildinfo.Version=${VERSION} -X github.com/glebov/awg-proxy-go/internal/buildinfo.Build=${BUILD}" \
    -o /awgproxy ./cmd/awgproxy

# Источник статического busybox целевой арки (берём только бинарь, не запускаем).
FROM busybox:1.37-musl AS bb

# Сборка корня будущего scratch-образа: app + busybox + симлинки на апплеты.
# Стадия нативная (BUILDPLATFORM): ln не исполняет busybox, поэтому эмуляция не нужна.
FROM --platform=$BUILDPLATFORM alpine:3.21 AS rootfs
COPY --from=bb /bin/busybox /rootfs/bin/busybox
# Симлинки апплетов (sh нужен для /container/shell; ping/wget/ip — для отладки сети).
RUN set -eux; mkdir -p /rootfs/app; cd /rootfs/bin; \
    for a in sh ash ls cat ip ping wget netstat nslookup vi grep ps; do ln -s busybox "$a"; done
COPY --from=build /awgproxy /rootfs/app/awgproxy
COPY config.example.json /rootfs/app/config.json

# Итог — плоский scratch (как рабочий вариант), но с шеллом busybox.
FROM scratch
COPY --from=rootfs /rootfs/ /
ENV PATH=/bin
ENTRYPOINT ["/app/awgproxy"]
