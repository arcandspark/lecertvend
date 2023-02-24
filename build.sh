#!/bin/sh
CGO_ENABLED=0 go build cmd/lecertvend.go
chown $XUID ./lecertvend