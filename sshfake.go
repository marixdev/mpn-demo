package main

// The Files and Terminal tabs log in over SSH as the website's account. The demo has no such accounts: it answers
// those logins itself, over an in-process pipe, with an SFTP server whose files live in memory and a small pretend
// shell. Nothing reaches the machine's own files or programs.

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// fakeSSH implements web.Dialer.
type fakeSSH struct {
	cfg  *ssh.ServerConfig
	ckey ssh.Signer
	addr string

	mu    sync.Mutex
	files map[string]sftp.Handlers // one in-memory file tree per website account, reset with the rest of the demo
}

func newFakeSSH() *fakeSSH {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hk)
	_, ck, _ := ed25519.GenerateKey(rand.Reader)
	client, _ := ssh.NewSignerFromKey(ck)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(client.PublicKey().Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unknown key")
	}}
	cfg.AddHostKey(host)
	// A loopback port of its own: net.Pipe has no buffer, and both ends of an SSH handshake write before they read.
	// Only the client key made above, which never leaves this process, can log in.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	f := &fakeSSH{cfg: cfg, ckey: client, files: map[string]sftp.Handlers{}, addr: ln.Addr().String()}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(nc)
		}
	}()
	return f
}

func (f *fakeSSH) reset() {
	f.mu.Lock()
	f.files = map[string]sftp.Handlers{}
	f.mu.Unlock()
}

// tree is the account's file tree, filled with sample files the first time.
func (f *fakeSSH) tree(user string) sftp.Handlers {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := f.files[user]; ok {
		return h
	}
	h := sftp.InMemHandler()
	seedFiles(h, user)
	f.files[user] = h
	return h
}

func (f *fakeSSH) Dial(user string) (*ssh.Client, error) {
	if find(siteOfUser(user)) == nil {
		return nil, fmt.Errorf("no account %q", user)
	}
	cs, err := net.DialTimeout("tcp", f.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	cc, chans, reqs, err := ssh.NewClientConn(cs, f.addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(f.ckey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		cs.Close()
		return nil, err
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

func (f *fakeSSH) serve(nc net.Conn) {
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(nc, f.cfg)
	if err != nil {
		return
	}
	_ = nc.SetDeadline(time.Time{})
	user := sc.User()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, in, err := nch.Accept()
		if err != nil {
			continue
		}
		go f.session(ch, in, user)
	}
}

func (f *fakeSSH) session(ch ssh.Channel, in <-chan *ssh.Request, user string) {
	defer ch.Close()
	for req := range in {
		switch req.Type {
		case "subsystem":
			ok := len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
			_ = req.Reply(ok, nil)
			if !ok {
				return
			}
			srv := sftp.NewRequestServer(ch, f.tree(user), sftp.WithStartDirectory(homeOf(user)))
			_ = srv.Serve()
			_ = srv.Close()
			return
		case "pty-req", "window-change", "env":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			go func() {
				for r := range in {
					_ = r.Reply(r.Type == "window-change", nil)
				}
			}()
			shell(ch, user, f.tree(user))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func homeOf(user string) string { return "/home/" + user }

func siteOfUser(user string) string {
	mu.Lock()
	defer mu.Unlock()
	for _, s := range sites {
		if s["user"] == user {
			return s["name"].(string)
		}
	}
	return ""
}

// seedFiles writes the sample files of an account through the handler, the way an SFTP client would.
func seedFiles(h sftp.Handlers, user string) {
	home := homeOf(user)
	mk := func(p string) { _ = h.FileCmd.Filecmd(sftp.NewRequest("Mkdir", p)) }
	put := func(p, text string) {
		req := sftp.NewRequest("Put", p)
		req.Flags = 0x02 | 0x08 | 0x10 // SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC
		w, err := h.FilePut.Filewrite(req)
		if err == nil {
			_, _ = w.WriteAt([]byte(text), 0)
			if c, ok := w.(io.Closer); ok {
				c.Close()
			}
		}
	}
	for _, d := range []string{"/home", home, home + "/htdocs", home + "/logs", home + "/tmp", home + "/htdocs/assets"} {
		mk(d)
	}
	put(home+"/.profile", "# ~/.profile\nexport PATH=\"$HOME/bin:$PATH\"\n")
	put(home+"/htdocs/index.html", "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <title>Welcome</title>\n  <link rel=\"stylesheet\" href=\"assets/style.css\">\n</head>\n<body>\n  <h1>It works!</h1>\n  <p>This site is served by Mini Panel.</p>\n</body>\n</html>\n")
	put(home+"/htdocs/assets/style.css", "body {\n  font-family: system-ui, sans-serif;\n  margin: 4rem auto;\n  max-width: 40rem;\n  color: #1f2937;\n}\n")
	put(home+"/htdocs/robots.txt", "User-agent: *\nAllow: /\n")
	put(home+"/htdocs/info.php", "<?php\n// Shows the PHP settings of this site. Delete it once you are done.\nphpinfo();\n")
	put(home+"/README.txt", "This is the demo of Mini Panel.\nFiles you change here are kept in memory only and are reset every hour.\n")
}

// shell is a pretend terminal: it knows a few commands and works on the account's in-memory files.
func shell(ch ssh.Channel, user string, h sftp.Handlers) {
	home := homeOf(user)
	cwd := home
	out := func(s string) { _, _ = io.WriteString(ch, strings.ReplaceAll(s, "\n", "\r\n")) }
	prompt := func() {
		where := cwd
		if strings.HasPrefix(cwd, home) {
			where = "~" + strings.TrimPrefix(cwd, home)
		}
		out(fmt.Sprintf("\x1b[1;32m%s@demo\x1b[0m:\x1b[1;34m%s\x1b[0m$ ", user, where))
	}
	list := func(dir string) ([]os.FileInfo, error) {
		l, err := h.FileList.Filelist(sftp.NewRequest("List", dir))
		if err != nil {
			return nil, err
		}
		buf := make([]os.FileInfo, 200)
		n, _ := l.ListAt(buf, 0)
		fi := buf[:n]
		sort.Slice(fi, func(i, j int) bool { return fi[i].Name() < fi[j].Name() })
		return fi, nil
	}
	abs := func(p string) string {
		if p == "~" || p == "" {
			return home
		}
		if strings.HasPrefix(p, "~/") {
			p = home + p[1:]
		}
		if !strings.HasPrefix(p, "/") {
			p = cwd + "/" + p
		}
		return path.Clean(p)
	}
	out("Welcome to the Mini Panel demo terminal.\nThis is a pretend shell with a few commands (type help). Nothing here runs on a real server.\n\n")
	prompt()
	var line []rune
	buf := make([]byte, 1024)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		for _, r := range string(buf[:n]) {
			switch {
			case r == '\r' || r == '\n':
				out("\n")
				cmd := strings.Fields(string(line))
				line = line[:0]
				if len(cmd) > 0 {
					if cmd[0] == "exit" || cmd[0] == "logout" {
						out("logout\n")
						return
					}
					out(run(cmd, user, &cwd, abs, list, h))
				}
				prompt()
			case r == 127 || r == 8:
				if len(line) > 0 {
					line = line[:len(line)-1]
					out("\b \b")
				}
			case r == 3:
				line = line[:0]
				out("^C\n")
				prompt()
			case r == 4:
				if len(line) == 0 {
					out("logout\n")
					return
				}
			case r >= 32 && len(line) < 500:
				line = append(line, r)
				out(string(r))
			}
		}
	}
}

func run(cmd []string, user string, cwd *string, abs func(string) string, list func(string) ([]os.FileInfo, error), h sftp.Handlers) string {
	arg := func(i int) string {
		if len(cmd) > i {
			return cmd[i]
		}
		return ""
	}
	switch cmd[0] {
	case "help":
		return "Commands: ls, cd, pwd, cat, whoami, id, hostname, uname, date, uptime, df, free, php -v, node -v, echo, clear, exit\n"
	case "pwd":
		return *cwd + "\n"
	case "whoami":
		return user + "\n"
	case "id":
		return fmt.Sprintf("uid=1001(%s) gid=1001(%s) groups=1001(%s)\n", user, user, user)
	case "hostname":
		return "demo\n"
	case "uname":
		if arg(1) == "-a" {
			return "Linux demo 6.8.0-49-generic #49-Ubuntu SMP x86_64 GNU/Linux\n"
		}
		return "Linux\n"
	case "date":
		return time.Now().UTC().Format("Mon Jan _2 15:04:05 UTC 2006") + "\n"
	case "uptime":
		return " " + time.Now().UTC().Format("15:04:05") + " up 14 days,  3:12,  1 user,  load average: 0.21, 0.18, 0.15\n"
	case "df":
		return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        25G  7.9G   16G  34% /\n"
	case "free":
		return "               total        used        free      shared  buff/cache   available\nMem:           1.0Gi       430Mi       180Mi       2.0Mi       390Mi       560Mi\nSwap:          1.0Gi        24Mi       1.0Gi\n"
	case "php":
		return "PHP 8.4.14 (cli) (built: Nov  4 2026 10:12:31) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.4.14, Copyright (c) Zend Technologies\n"
	case "node":
		return "v22.21.0\n"
	case "echo":
		return strings.Join(cmd[1:], " ") + "\n"
	case "clear":
		return "\x1b[H\x1b[2J"
	case "cd":
		p := abs(arg(1))
		st, err := h.FileList.Filelist(sftp.NewRequest("Stat", p))
		if err != nil {
			return "cd: " + arg(1) + ": No such file or directory\n"
		}
		fi := make([]os.FileInfo, 1)
		if n, _ := st.ListAt(fi, 0); n == 0 || !fi[0].IsDir() {
			return "cd: " + arg(1) + ": Not a directory\n"
		}
		*cwd = p
		return ""
	case "ls", "ll":
		long := cmd[0] == "ll"
		target := *cwd
		for _, a := range cmd[1:] {
			if strings.HasPrefix(a, "-") {
				long = long || strings.Contains(a, "l")
			} else {
				target = abs(a)
			}
		}
		fi, err := list(target)
		if err != nil {
			return "ls: cannot access '" + target + "': No such file or directory\n"
		}
		var b strings.Builder
		for _, x := range fi {
			name := x.Name()
			if x.IsDir() {
				name = "\x1b[1;34m" + name + "\x1b[0m"
			}
			if long {
				mode := "-rw-r--r--"
				if x.IsDir() {
					mode = "drwxr-xr-x"
				}
				fmt.Fprintf(&b, "%s 1 %s %s %6d %s %s\n", mode, user, user, x.Size(), x.ModTime().Format("Jan _2 15:04"), name)
			} else {
				b.WriteString(name + "  ")
			}
		}
		if !long && len(fi) > 0 {
			b.WriteString("\n")
		}
		return b.String()
	case "cat":
		if arg(1) == "" {
			return ""
		}
		p := abs(arg(1))
		r, err := h.FileGet.Fileread(sftp.NewRequest("Get", p))
		if err != nil {
			return "cat: " + arg(1) + ": No such file or directory\n"
		}
		b := make([]byte, 64<<10)
		n, _ := r.ReadAt(b, 0)
		return string(b[:n])
	case "sudo", "su":
		return user + " is not in the sudoers file. This incident will be reported.\n"
	}
	return cmd[0] + ": command not found in this demo (type help)\n"
}
