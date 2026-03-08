package sftpserver

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// NewSignerFromFile reads a PEM-encoded private key from the given file path
// and returns an ssh.Signer suitable for use as a server host key.
// It supports any key type accepted by ssh.ParsePrivateKey (RSA, ECDSA, Ed25519).
func NewSignerFromFile(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host key %q: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse host key %q: %w", path, err)
	}
	return signer, nil
}

// UserInfo holds the credentials and jail root for a single SFTP user.
type UserInfo struct {
	Password string
	Root     string // jail root on disk, e.g. /srv/sftp/alice
	CanRead  bool   // allow read/download/list operations
	CanWrite bool   // allow write/upload/delete/rename operations
}

// Server is a self-contained SFTP server.
type Server struct {
	// Addr is the TCP address to listen on, e.g. ":2022".
	Addr string
	// Users maps usernames to their credentials and jail roots.
	Users map[string]UserInfo
	// mu protects Users for concurrent reads and writes.
	mu sync.RWMutex
	// Signer is the host key used for the SSH handshake.
	Signer ssh.Signer
	// CompletedUploads receives the SFTP path of each file whose write has
	// finished successfully (i.e. the client closed the file without error).
	// The channel is buffered; sends are non-blocking so a slow consumer
	// never stalls an upload.  Callers should drain the channel continuously.
	CompletedUploads chan string
}

// AddUser adds or replaces a user entry in the server's user map.
// It is safe to call concurrently with active connections.
func (s *Server) AddUser(username string, info UserInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Users == nil {
		s.Users = make(map[string]UserInfo)
	}
	s.Users[username] = info
}

// RemoveUser removes a user entry from the server's user map.
// Active connections for that user are not terminated.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Users, username)
}

// NewServer creates a new Server with the given address, user map, and host key.
func NewServer(addr string, users map[string]UserInfo, signer ssh.Signer) *Server {
	return &Server{
		Addr:             addr,
		Users:            users,
		Signer:           signer,
		CompletedUploads: make(chan string, 64),
	}
}

// ListenAndServe starts the SFTP server and blocks, accepting connections.
// It returns a non-nil error only if the listener cannot be created.
func (s *Server) ListenAndServe() error {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.mu.RLock()
			u, ok := s.Users[c.User()]
			s.mu.RUnlock()
			if !ok || subtle.ConstantTimeCompare([]byte(u.Password), pass) != 1 {
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
	cfg.AddHostKey(s.Signer)

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	log.Printf("SFTP listening on %s", s.Addr)

	for {
		nc, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConn(nc, cfg, s.CompletedUploads)
	}
}

func handleConn(nc net.Conn, cfg *ssh.ServerConfig, uploads chan<- string) {
	defer nc.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Println("ssh handshake:", err)
		return
	}
	defer sshConn.Close()

	jailRoot := sshConn.Permissions.Extensions["jailRoot"]
	user := sshConn.Permissions.Extensions["user"]
	canRead := sshConn.Permissions.Extensions["canRead"] == "true"
	canWrite := sshConn.Permissions.Extensions["canWrite"] == "true"
	log.Printf("login user=%s root=%s from=%s", user, jailRoot, sshConn.RemoteAddr())

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, inReqs, err := newCh.Accept()
		if err != nil {
			log.Println("accept channel:", err)
			continue
		}

		go handleSession(ch, inReqs, jailRoot, canRead, canWrite, uploads)
	}
}

func handleSession(ch ssh.Channel, inReqs <-chan *ssh.Request, jailRoot string, canRead, canWrite bool, uploads chan<- string) {
	defer ch.Close()

	for req := range inReqs {
		switch req.Type {
		case "subsystem":
			// Payload is: string "sftp"
			if len(req.Payload) < 4 || string(req.Payload[4:]) != "sftp" {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)

			handlers := jailedHandlers(jailRoot, canRead, canWrite, uploads)

			server := sftp.NewRequestServer(ch, handlers)
			if err := server.Serve(); err == io.EOF {
				_ = server.Close()
				return
			} else if err != nil {
				log.Println("sftp serve:", err)
				_ = server.Close()
				return
			}
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
}

type jail struct {
	root     string
	canRead  bool
	canWrite bool
	uploads  chan<- string
}

// resolve maps an SFTP path (possibly relative) into an absolute on-disk path
// under j.root, rejecting escapes and symlink escapes.
func (j jail) resolve(p string) (string, error) {
	if p == "" {
		p = "/"
	}

	// Force absolute + clean: "/../../etc" => "/etc"
	clean := filepath.Clean("/" + filepath.ToSlash(p))

	// Join to root. clean starts with "/", Join will drop earlier elems,
	// so we strip the leading "/" first.
	full := filepath.Join(j.root, strings.TrimPrefix(clean, "/"))

	// First prefix check (string check)
	if !withinRoot(full, j.root) {
		return "", os.ErrPermission
	}

	// Prevent symlink escapes:
	// EvalSymlinks fails if path doesn't exist; that's OK for create paths.
	// For create paths, check the parent directory's symlinks instead.
	target, err := filepath.EvalSymlinks(full)
	if err == nil {
		if !withinRoot(target, j.root) {
			return "", os.ErrPermission
		}
		return target, nil
	}

	// If full doesn't exist yet, validate parent
	parent := filepath.Dir(full)
	parentReal, perr := filepath.EvalSymlinks(parent)
	if perr == nil && !withinRoot(parentReal, j.root) {
		return "", os.ErrPermission
	}
	return full, nil
}

func withinRoot(path, root string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)

	if path == root {
		return true
	}
	if !strings.HasSuffix(root, string(os.PathSeparator)) {
		root += string(os.PathSeparator)
	}
	return strings.HasPrefix(path, root)
}

// jail implements the four sftp handler interfaces for a chrooted filesystem.
// Fileread implements sftp.FileReader.
func (j jail) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if !j.canRead {
		return nil, os.ErrPermission
	}
	p, err := j.resolve(r.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// writeLogger wraps an *os.File and logs the filename when the file is closed,
// signalling that the upload is complete. The sftp request server calls Close()
// on the returned io.WriterAt when it detects an io.Closer.
type writeLogger struct {
	*os.File
	filepath string
	uploads  chan<- string
}

func (w *writeLogger) Close() error {
	err := w.File.Close()
	if err == nil {
		log.Printf("upload complete: %q", w.filepath)
		// Announce the completed upload on the queue; non-blocking so a slow
		// consumer never stalls the upload handler.
		select {
		case w.uploads <- w.filepath:
		default:
			log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", w.filepath)
		}
	}
	return err
}

// Filewrite implements sftp.FileWriter.
func (j jail) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if !j.canWrite {
		return nil, os.ErrPermission
	}
	p, err := j.resolve(r.Filepath)
	if err != nil {
		return nil, err
	}
	log.Printf("upload: %q", r.Filepath)
	// Create/overwrite
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &writeLogger{File: f, filepath: r.Filepath, uploads: j.uploads}, nil
}

// Filecmd implements sftp.FileCmder.
func (j jail) Filecmd(r *sftp.Request) error {
	if !j.canWrite {
		return os.ErrPermission
	}
	switch r.Method {
	case "Setstat", "Fsetstat":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		// Minimal: allow chmod/chown/times only if you want; here we ignore.
		_ = p
		return nil

	case "Rename":
		oldP, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		newP, err := j.resolve(r.Target)
		if err != nil {
			return err
		}
		return os.Rename(oldP, newP)

	case "Rmdir":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		return os.Remove(p)

	case "Remove":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		return os.Remove(p)

	case "Mkdir":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		return os.Mkdir(p, 0750)

	case "Symlink":
		// Strongly consider disallowing symlinks entirely in a jailed server:
		return os.ErrPermission

	default:
		return fmt.Errorf("unsupported method: %s", r.Method)
	}
}

// Filelist implements sftp.FileLister.
func (j jail) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	if !j.canRead {
		return nil, os.ErrPermission
	}
	p, err := j.resolve(r.Filepath)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		return listerFromDirEntries(p, entries), nil
	case "Stat":
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		return listerFromFileInfo([]os.FileInfo{st}), nil
	case "Lstat":
		st, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		return listerFromFileInfo([]os.FileInfo{st}), nil
	default:
		return nil, fmt.Errorf("unsupported list method: %s", r.Method)
	}
}

func jailedHandlers(root string, canRead, canWrite bool, uploads chan<- string) sftp.Handlers {
	j := jail{root: filepath.Clean(root), canRead: canRead, canWrite: canWrite, uploads: uploads}
	return sftp.Handlers{
		FileGet:  j,
		FilePut:  j,
		FileCmd:  j,
		FileList: j,
	}
}

type fileInfoLister struct{ infos []os.FileInfo }

func (l fileInfoLister) ListAt(fis []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.infos)) {
		return 0, io.EOF
	}
	n := copy(fis, l.infos[offset:])
	if n < len(fis) {
		return n, io.EOF
	}
	return n, nil
}

func listerFromFileInfo(infos []os.FileInfo) sftp.ListerAt {
	return fileInfoLister{infos: infos}
}

func listerFromDirEntries(dir string, entries []os.DirEntry) sftp.ListerAt {
	infos := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		infos = append(infos, fi)
	}
	return fileInfoLister{infos: infos}
}
