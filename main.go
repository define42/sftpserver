package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type userInfo struct {
	Password string
	Root     string // jail root on disk, e.g. /srv/sftp/alice
}

func main() {
	// Example user DB (replace with your auth source)
	users := map[string]userInfo{
		"alice": {Password: "alicepw", Root: "/srv/sftp/alice"},
		"bob":   {Password: "bobpw", Root: "/srv/sftp/bob"},
	}

	hostSigner := mustHostKey()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			u, ok := users[c.User()]
			if !ok || u.Password != string(pass) {
				return nil, fmt.Errorf("invalid credentials")
			}
			// Put the jail root into Extensions so we can fetch it later per-conn.
			perms := &ssh.Permissions{
				Extensions: map[string]string{
					"jailRoot": u.Root,
					"user":     c.User(),
				},
			}
			return perms, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", ":2022")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("SFTP listening on :2022")

	for {
		nc, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConn(nc, cfg)
	}
}

func handleConn(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Println("ssh handshake:", err)
		return
	}
	defer sshConn.Close()

	jailRoot := sshConn.Permissions.Extensions["jailRoot"]
	user := sshConn.Permissions.Extensions["user"]
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

		go handleSession(ch, inReqs, jailRoot)
	}
}

func handleSession(ch ssh.Channel, inReqs <-chan *ssh.Request, jailRoot string) {
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

			handlers := jailedHandlers(jailRoot)

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
	root string
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

func jailedHandlers(root string) sftp.Handlers {
	j := jail{root: filepath.Clean(root)}

	// You can tighten this further (disallow symlinks entirely, restrict rename, etc.)
	return sftp.Handlers{
		FileGet: sftp.FileReaderFunc(func(r *sftp.Request) (io.ReaderAt, error) {
			p, err := j.resolve(r.Filepath)
			if err != nil {
				return nil, err
			}
			return os.Open(p)
		}),
		FilePut: sftp.FileWriterFunc(func(r *sftp.Request) (io.WriterAt, error) {
			p, err := j.resolve(r.Filepath)
			if err != nil {
				return nil, err
			}
			// Create/overwrite
			return os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
		}),
		FileCmd: sftp.FileCmderFunc(func(r *sftp.Request) error {
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
				return os.MkdirAll(p, 0750)

			case "Symlink":
				// Strongly consider disallowing symlinks entirely in a jailed server:
				return os.ErrPermission

			default:
				return fmt.Errorf("unsupported method: %s", r.Method)
			}
		}),
		FileList: sftp.FileListerFunc(func(r *sftp.Request) (sftp.ListerAt, error) {
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
		}),
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
		// Ensure Name() is correct; Info() already sets it
		_ = dir
		infos = append(infos, fi)
	}
	return fileInfoLister{infos: infos}
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
