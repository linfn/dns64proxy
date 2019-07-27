.PHONY: all
all:
	go build .

.PHONY: test
test:
	go test -race -coverprofile=coverage.txt

.PHONY: docker
docker:
	docker build --build-arg GOPROXY -t linfn/dns64proxy .

.PHONY: docker-push
docker-push:
	docker push linfn/dns64proxy
