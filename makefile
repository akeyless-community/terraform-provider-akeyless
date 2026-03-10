TEST?=./...
SOURCEHOST=registry.terraform.io
NAMESPACE=akeyless-community
NAME=akeyless
VERSION=1.0.0-dev
BINARY=terraform-provider-${NAME}

vet:
	go vet ./...

fmt:
	@gofmt -s -w ./$(NAME)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

test:
    go test $(TEST) -timeout=30s

testacc: fmtcheck
	TF_ACC=1 go test $(TEST) -v -count 1 -parallel 4 -timeout 120m
	
testgw-up:
	docker compose -f docker-compose.test.yml up -d --wait
	@echo "All services are healthy."

testgw-down:
	docker compose -f docker-compose.test.yml down -v

testgw: testgw-up
	AKEYLESS_GATEWAY=http://localhost:18081 TF_ACC=1 go test $(TEST) -v -count 1 -parallel 4 -timeout 120m; \
	ret=$$?; \
	$(MAKE) testgw-down; \
	exit $$ret

build-linux:
	GOOS=linux GOARCH=amd64 go build -o ${BINARY}

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -o ${BINARY}

build-darwin-m1:
	GOOS=darwin GOARCH=arm64 go build -o ${BINARY}

install-linux: build-linux
	mkdir -p ~/.terraform.d/plugins/${SOURCEHOST}/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/linux_amd64
	mv ${BINARY} ~/.terraform.d/plugins/${SOURCEHOST}/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/linux_amd64

install-darwin: build-darwin
	mkdir -p ~/.terraform.d/plugins/${SOURCEHOST}/${NAMESPACE}/${NAME}/${VERSION}/darwin_amd64
	mv ${BINARY} ~/.terraform.d/plugins/${SOURCEHOST}/${NAMESPACE}/${NAME}/${VERSION}/darwin_amd64

install-darwin-m1: build-darwin-m1
	mkdir -p ~/.terraform.d/plugins/${SOURCEHOST}/${NAMESPACE}/${NAME}/${VERSION}/darwin_arm64
	mv ${BINARY} ~/.terraform.d/plugins/${SOURCEHOST}/${NAMESPACE}/${NAME}/${VERSION}/darwin_arm64