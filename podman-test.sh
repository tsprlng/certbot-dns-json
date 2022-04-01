#!/bin/zsh -e

exec sudo podman run  \
	-v $PWD:/wrk -w /wrk  \
	--entrypoint /wrk/podman-entrypoint.sh  \
	-it  \
	docker.io/certbot/certbot:latest "$@"
