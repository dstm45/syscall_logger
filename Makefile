GENFILE=./build/gen.go
BINARY=syscall_logger
BUILD_DIRECTORY=./build
ENTRY_POINT=./cmd/main.go

build:
	go build -o syscall_logger $(ENTRY_POINT)
	mv $(BINARY) $(BUILD_DIRECTORY)
gen:
	go generate $(GENFILE)
run:
	$(BUILD_DIRECTORY)/$(BINARY)
clean:
	yes | rm $(BUILD_DIRECTORY)/*.o \
	$(BUILD_DIRECTORY)/main_bpfeb.go \
	$(BUILD_DIRECTORY)/main_bpfel.go \
	$(BUILD_DIRECTORY)/$(BINARY)
