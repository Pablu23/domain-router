run: build
	sudo ./bin/domain-router --pretty --log-level debug

build: 
	go build -o bin/domain-router cmd/domain-router/main.go
