.PHONY: build test run tidy clean

BINARY := actologger

build:
	go build -o $(BINARY) .

test:
	go test ./...

run:
	go run .

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
