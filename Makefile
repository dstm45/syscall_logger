build:
	go generate ./build/gen.go && go build -o syscall_logger cmd/main.go  && mv syscall_logger build/
run:
	./cmd/build/syscall_logger

