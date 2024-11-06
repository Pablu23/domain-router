run: build
	sudo ./bin/domain-router

build: 
	go build -o bin/domain-router cmd/domain-router/main.go
