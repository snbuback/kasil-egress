# Build one binary per image; BINARY selects which.
FROM golang:1.26-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG BINARY=egressd
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=arm64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/${BINARY} ./cmd/${BINARY}

# distroless/static carries no shell and no libc: the binaries are pure Go, and
# a collector that can be exec'd into is a liability.
FROM gcr.io/distroless/static-debian12:nonroot

ARG BINARY=egressd
COPY --from=build /out/${BINARY} /usr/local/bin/app

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/app"]
