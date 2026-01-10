build:
	go generate ./cmd/build/gen.go && go build -o syscall_logger cmd/main.go  && mv syscall_logger cmd/build/
run:
	./cmd/build/syscall_logger

