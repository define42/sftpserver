package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"log"

	"github.com/define42/sftpserver/internal/sftpserver"
	"golang.org/x/crypto/ssh"
)

func main() {
	hostKeyPath := flag.String("host-key", "", "path to a PEM-encoded private key file to use as the server host key (generated if not provided)")
	flag.Parse()

	// Example user DB (replace with your auth source).
	// WARNING: never hardcode credentials in production; use env vars or a secret store.
	users := map[string]sftpserver.UserInfo{
		"alice": {Password: "alicepw", Root: "/srv/sftp/alice", CanRead: true, CanWrite: true},
		"bob":   {Password: "bobpw", Root: "/srv/sftp/bob", CanRead: true, CanWrite: false},
	}

	var signer ssh.Signer
	if *hostKeyPath != "" {
		var err error
		signer, err = sftpserver.NewSignerFromFile(*hostKeyPath)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		signer = mustHostKey()
	}

	srv := sftpserver.NewServer(":2022", users, signer)

	go func() {
		for path := range srv.CompletedUploads {
			log.Printf("completed upload: %q", path)
		}
	}()

	log.Fatal(srv.ListenAndServe())
}

func mustHostKey() ssh.Signer {
	// For demo: generate a new key on each start.
	// In production: load from disk and keep stable.
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	return signer
}
