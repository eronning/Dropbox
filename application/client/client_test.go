package main

import (
	"testing"
	"../lib/support/client"
	"../lib/support/rpc"
)


func TestBasic(t *testing.T) {
	// create a server remote to send calls to the server
	server := rpc.NewServerRemote("dropbox-eronning-wh7.foouniversity.com:8080")
	var token string
	server.Call("signup", &token, "testuser", "testpass")
	// if the token is actually a quit sign -- exit cleanly
	c := Client{server, "testuser", token}
	client.TestClient(t, &c) 
}