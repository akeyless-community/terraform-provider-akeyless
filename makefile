TEST?=./...
HOSTNAME=akeyless.io
NAMESPACE=platform
NAME=akeyless
VERSION=0.9.0
BINARY=terraform-provider-${NAME}
OS_ARCH=darwin_amd64


vet:
	go vet ./...

fmt:
	@gofmt -s -w ./$(NAME)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

test:
    go test $(TEST) -timeout=30s

testacc: fmtcheck
	TF_ACC=1 go test $(TEST) -v -count 1 -timeout 120m

build-linux:
	GOOS=linux GOARCH=amd64 go build -o ${BINARY}

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -o ${BINARY}

install-linux: build-linux
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/linux_amd64
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/linux_amd64

install-darwin: build-darwin
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/darwin_amd64
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/darwin_amd64