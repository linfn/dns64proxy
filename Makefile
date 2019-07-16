.PHONY: all
all:
	go build .

.PHONY: test
test:
	go test ./...

.PHONY: docker
docker:
	docker build -t linfn/dns64proxy .

.PHONY: docker-push
docker-push:
	docker push linfn/dns64proxy
