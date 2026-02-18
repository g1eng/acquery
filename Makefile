NAME = acquery

all:
	cargo build --release

install: all
	install -m 755 target/release/$(NAME) $(PREFIX)/bin/$(NAME)
	
run-all: run-list run-search-prio run-search-op run-search-regex

run-list:
	cargo run -- -f ./fixtures/sample-policy.acl list
	
run-search-prio:
	cargo run -- -f ./fixtures/sample-policy.acl search 1001
	
run-search-op:
	cargo run -- -f ./fixtures/sample-policy.acl search unlink
	
run-search-regex:
	cargo run -- -f ./fixtures/sample-policy.acl search regex:path=
	
release:
	cargo build --release --target=x86_64-unknown-linux-musl
	
test:
	cargo test
	
cov:
	cargo tarpaulin -o Xml 
