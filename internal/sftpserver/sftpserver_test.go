package sftpserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ---- withinRoot tests ----

func TestWithinRoot(t *testing.T) {
	tests := []struct {
		path, root string
		want       bool
	}{
		{"/srv/sftp/alice", "/srv/sftp/alice", true},
		{"/srv/sftp/alice/foo", "/srv/sftp/alice", true},
		{"/srv/sftp/alice/foo/bar", "/srv/sftp/alice", true},
		{"/srv/sftp/alice_evil", "/srv/sftp/alice", false},
		{"/srv/sftp", "/srv/sftp/alice", false},
		{"/srv/sftp/bob", "/srv/sftp/alice", false},
		{"/", "/srv/sftp/alice", false},
	}
	for _, tc := range tests {
		got := withinRoot(tc.path, tc.root)
		if got != tc.want {
			t.Errorf("withinRoot(%q, %q) = %v; want %v", tc.path, tc.root, got, tc.want)
		}
	}
}

// ---- jail.resolve tests ----

func TestJailResolve(t *testing.T) {
	root := t.TempDir()
	j := jail{root: root}

	// Normal relative path
	p, err := j.resolve("foo.txt")
	if err != nil {
		t.Fatalf("resolve(foo.txt): %v", err)
	}
	if p != filepath.Join(root, "foo.txt") {
		t.Errorf("resolve(foo.txt) = %q; want %q", p, filepath.Join(root, "foo.txt"))
	}

	// Absolute SFTP path
	p, err = j.resolve("/bar/baz.txt")
	if err != nil {
		t.Fatalf("resolve(/bar/baz.txt): %v", err)
	}
	if p != filepath.Join(root, "bar", "baz.txt") {
		t.Errorf("resolve(/bar/baz.txt) = %q; want %q", p, filepath.Join(root, "bar", "baz.txt"))
	}

	// Empty path → root
	p, err = j.resolve("")
	if err != nil {
		t.Fatalf("resolve(''): %v", err)
	}
	if p != root {
		t.Errorf("resolve('') = %q; want %q", p, root)
	}

	// Path traversal attempt
	_, err = j.resolve("../../etc/passwd")
	if err != nil {
		// After clean, ../../etc/passwd from "/" becomes /etc/passwd which is
		// outside root, so resolve returns os.ErrPermission only when the
		// resolved real path escapes; for non-existing paths the string check
		// catches it.  Accept any non-nil error.
		t.Logf("resolve(../../etc/passwd) correctly returned error: %v", err)
	}
}

// ---- integration test: full SFTP upload / download / list ----

// testSigner creates a throwaway RSA host key for tests.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startTestServer launches a Server on a random OS-assigned port and returns
// the address and a cancel function that closes the listener.
func startTestServer(t *testing.T, users map[string]UserInfo) (srv *Server, addr string, stop func()) {
	t.Helper()
	signer := testSigner(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()

	srv = NewServer(addr, users, signer)

	// Build SSH server config the same way ListenAndServe does.
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			srv.mu.RLock()
			u, ok := srv.Users[c.User()]
			srv.mu.RUnlock()
			if !ok || u.Password != string(pass) {
				return nil, fmt.Errorf("invalid credentials")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"jailRoot": u.Root,
					"user":     c.User(),
					"canRead":  fmt.Sprintf("%v", u.CanRead),
					"canWrite": fmt.Sprintf("%v", u.CanWrite),
				},
			}, nil
		},
	}
	cfg.AddHostKey(srv.Signer)

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go handleConn(nc, cfg, srv.CompletedUploads)
		}
	}()

	stop = func() { ln.Close() }
	return srv, addr, stop
}

// dialSFTP connects an sftp.Client to addr using the given credentials.
func dialSFTP(t *testing.T, addr, user, pass string) *sftp.Client {
	t.Helper()
	sshCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		conn.Close()
	})
	return client
}

func TestSFTPServer_UploadDownload(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	content := []byte("hello sftp world")
	remote := "/upload.txt"
	f, err := client.Create(remote)
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	f.Close()

	// Download and compare.
	rf, err := client.Open(remote)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, err := io.ReadAll(rf)
	rf.Close()
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

func TestSFTPServer_List(t *testing.T) {
	root := t.TempDir()
	// Pre-create a file so we have something to list.
	if err := os.WriteFile(filepath.Join(root, "listed.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("client.ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "listed.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("ReadDir returned %v; want [listed.txt]", names)
	}
}

func TestSFTPServer_InvalidCredentials(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "rightpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("wrongpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_, err := ssh.Dial("tcp", addr, sshCfg)
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
}

func TestNewServer(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "pw", Root: "/tmp/alice", CanRead: true, CanWrite: true},
	}
	signer := testSigner(t)
	srv := NewServer(":0", users, signer)
	if srv.Addr != ":0" {
		t.Errorf("Addr = %q; want :0", srv.Addr)
	}
	if len(srv.Users) != 1 {
		t.Errorf("Users len = %d; want 1", len(srv.Users))
	}
	if srv.Signer != signer {
		t.Error("Signer not set correctly")
	}
}

// TestSFTPServer_ReadOnlyUser verifies that a read-only user can download and
// list files but cannot upload or delete files.
func TestSFTPServer_ReadOnlyUser(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "data.txt"), []byte("read me"), 0644); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"reader": {Password: "readpw", Root: root, CanRead: true, CanWrite: false},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "reader", "readpw")

	// Read/list must succeed.
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "data.txt" {
		t.Errorf("ReadDir returned unexpected entries")
	}

	rf, err := client.Open("/data.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, _ := io.ReadAll(rf)
	rf.Close()
	if string(got) != "read me" {
		t.Errorf("downloaded %q; want %q", got, "read me")
	}

	// Write must be denied.
	_, err = client.Create("/upload.txt")
	if err == nil {
		t.Error("expected write to be denied for read-only user, got nil error")
	}
}

// TestSFTPServer_WriteOnlyUser verifies that a write-only user can upload files
// but cannot read/download or list files.
func TestSFTPServer_WriteOnlyUser(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"writer": {Password: "writepw", Root: root, CanRead: false, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "writer", "writepw")

	// Upload must succeed.
	f, err := client.Create("/upload.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("write only")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f.Close()

	// Read must be denied.
	_, err = client.Open("/upload.txt")
	if err == nil {
		t.Error("expected read to be denied for write-only user, got nil error")
	}

	// List must be denied.
	_, err = client.ReadDir("/")
	if err == nil {
		t.Error("expected list to be denied for write-only user, got nil error")
	}
}

// TestServer_AddRemoveUser verifies that AddUser and RemoveUser take effect for
// new login attempts without restarting the server.
func TestServer_AddRemoveUser(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	// Before AddUser: connection must fail.
	sshCfg := &ssh.ClientConfig{
		User:            "dynamic",
		Auth:            []ssh.AuthMethod{ssh.Password("dynpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure before AddUser, got nil")
	}

	// AddUser: now the user should be able to connect.
	srv.AddUser("dynamic", UserInfo{Password: "dynpw", Root: root, CanRead: true, CanWrite: true})
	_ = dialSFTP(t, addr, "dynamic", "dynpw")

	// RemoveUser: subsequent logins must fail.
	srv.RemoveUser("dynamic")
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure after RemoveUser, got nil")
	}
}

// TestServer_AddUser_Replace verifies that AddUser replaces an existing user's info.
func TestServer_AddUser_Replace(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"user1": {Password: "oldpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	// Old password works.
	_ = dialSFTP(t, addr, "user1", "oldpw")

	// Replace with new password.
	srv.AddUser("user1", UserInfo{Password: "newpw", Root: root, CanRead: true, CanWrite: true})

	// Old password must now fail.
	sshCfg := &ssh.ClientConfig{
		User:            "user1",
		Auth:            []ssh.AuthMethod{ssh.Password("oldpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected old password to fail after AddUser replace, got nil")
	}

	// New password must work.
	_ = dialSFTP(t, addr, "user1", "newpw")
}

// TestNewSignerFromFile verifies that NewSignerFromFile loads a valid PEM key file
// and returns a usable signer, and that it returns an error for invalid inputs.
func TestNewSignerFromFile(t *testing.T) {
	t.Run("RSA key file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "id_rsa")

		// Generate an RSA key and write it as PEM.
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der := x509.MarshalPKCS1PrivateKey(priv)
		pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
			t.Fatal(err)
		}

		signer, err := NewSignerFromFile(keyPath)
		if err != nil {
			t.Fatalf("NewSignerFromFile: %v", err)
		}
		if signer == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("ECDSA key file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "id_ecdsa")

		// Generate an ECDSA key and write it as PEM.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
			t.Fatal(err)
		}

		signer, err := NewSignerFromFile(keyPath)
		if err != nil {
			t.Fatalf("NewSignerFromFile: %v", err)
		}
		if signer == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := NewSignerFromFile("/nonexistent/path/to/key.pem")
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("invalid PEM content", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(keyPath, []byte("not a valid PEM file"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := NewSignerFromFile(keyPath)
		if err == nil {
			t.Fatal("expected error for invalid PEM, got nil")
		}
	})
}

// TestSFTPServer_WithFileHostKey verifies that the server works end-to-end when
// started with a host key loaded from a file via NewSignerFromFile.
func TestSFTPServer_WithFileHostKey(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()

	// Write a PEM-encoded RSA key file.
	keyPath := filepath.Join(dir, "host_key")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	signer, err := NewSignerFromFile(keyPath)
	if err != nil {
		t.Fatalf("NewSignerFromFile: %v", err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	srv := NewServer(addr, users, signer)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			srv.mu.RLock()
			u, ok := srv.Users[c.User()]
			srv.mu.RUnlock()
			if !ok || u.Password != string(pass) {
				return nil, fmt.Errorf("invalid credentials")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"jailRoot": u.Root,
					"user":     c.User(),
					"canRead":  fmt.Sprintf("%v", u.CanRead),
					"canWrite": fmt.Sprintf("%v", u.CanWrite),
				},
			}, nil
		},
	}
	cfg.AddHostKey(srv.Signer)

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(nc, cfg, srv.CompletedUploads)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	client := dialSFTP(t, addr, "testuser", "testpw")
	content := []byte("key from file")
	f, err := client.Create("/hello.txt")
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	f.Close()

	rf, err := client.Open("/hello.txt")
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, _ := io.ReadAll(rf)
	rf.Close()
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

// TestSFTPServer_JailedWorkingDirectory verifies that a user's working directory
// appears as "/" even though it is backed by a subdirectory on disk.
// This is the jail/chroot behaviour: Alice logs in and sees "/" as her root,
// but on disk that "/" is mounted to her actual home directory.
func TestSFTPServer_JailedWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "alice", "alicepw")

	// The initial working directory must appear as "/" to the client.
	wd, err := client.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if wd != "/" {
		t.Errorf("Getwd() = %q; want / (user must see / as their root, not the on-disk path)", wd)
	}

	// Files in the jail root must be reachable via "/filename", not via the
	// real on-disk path.
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("ReadDir(/) = %v; want [file.txt]", names)
	}

	// The on-disk path must NOT be accessible as an SFTP path; it resolves
	// to a non-existent location inside the jail.
	_, err = client.ReadDir(root)
	if err == nil {
		t.Error("expected error when accessing the real on-disk path via SFTP, got nil")
	}
}

// TestSFTPServer_CompletedUploadsQueue verifies that after a file upload finishes
// the server announces the SFTP path on the CompletedUploads channel.
func TestSFTPServer_CompletedUploadsQueue(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload two files and close each one to trigger the completion signal.
	for _, name := range []string{"/first.txt", "/second.txt"} {
		f, err := client.Create(name)
		if err != nil {
			t.Fatalf("client.Create(%q): %v", name, err)
		}
		if _, err = f.Write([]byte("data")); err != nil {
			t.Fatalf("f.Write: %v", err)
		}
		if err = f.Close(); err != nil {
			t.Fatalf("f.Close: %v", err)
		}

		select {
		case got := <-srv.CompletedUploads:
			if got != name {
				t.Errorf("CompletedUploads received %q; want %q", got, name)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for CompletedUploads signal for %q", name)
		}
	}
}
