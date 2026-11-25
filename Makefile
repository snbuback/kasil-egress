BINARY_DIR := bin
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS    ?=
LDFLAGS    := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt fmt-check lint chart image clean

all: fmt-check vet test build

build:
	mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/egressd ./cmd/egressd
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/egressctl ./cmd/egressctl

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(gofmt -l .)

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# helm lint + render with the CRD groups the chart uses, so a template that
# only fails against a live CRD is caught here.
chart:
	helm lint deploy/helm/egress
	helm template egress deploy/helm/egress --namespace egress \
	  --api-versions monitoring.coreos.com/v1 \
	  --api-versions external-secrets.io/v1 \
	  --api-versions operator.victoriametrics.com/v1beta1 \
	  --values deploy/helm/egress/ci-values.yaml > /dev/null
	helm lint deploy/helm/egress --values deploy/helm/egress/ci-values.yaml

clean:
	rm -rf $(BINARY_DIR)
