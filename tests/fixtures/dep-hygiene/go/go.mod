module example.com/dep-hygiene

go 1.21

require (
	github.com/example/safe v1.2.3
	github.com/example/commit-pin v0.0.0-20230101000000-abcdef012345
	github.com/example/floating latest
	github.com/example/zero v0.0.0
)
