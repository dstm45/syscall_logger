build:
	go generate ./build/gen.go && go build -o syscall_logger cmd/main.go  && mv syscall_logger build/
run:
	./build/syscall_logger
clean:
	rm ./build/*.o ./build/main_bpfeb.go ./build/main_bpfel.go ./build/syscall_logger

