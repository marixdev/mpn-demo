// Command mpn-demo runs the real Mini Panel web interface against a pretend server, so visitors can try every page.
//
// The panel's pages come unchanged from the mini-panel submodule. What a real panel asks its root helper is answered
// here from sample data; the Files and Terminal tabs log in to an in-memory SSH server (sshfake.go). Changes visitors
// make are kept in memory and everything is reset every hour. The program needs no root and touches no system file.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mpn/internal/ctl"
	"mpn/internal/mail"
	"mpn/internal/monitor"
	"mpn/internal/services"
	"mpn/internal/site"
	"mpn/internal/sitelog"
	"mpn/internal/web"
	"mpn/internal/webauth"
)

const (
	demoUser   = "demo"
	demoPass   = "demo-mini-panel"
	resetEvery = time.Hour
)

type m = map[string]any

var (
	mu       sync.Mutex
	sites    []m
	rules    []m
	nextRule int64 = 6
)

func stamp(daysAgo int) string {
	return time.Now().AddDate(0, 0, -daysAgo).Format("20060102") + "-033001"
}

// resetData puts the sample websites and firewall rules back.
func resetData() {
	mu.Lock()
	defer mu.Unlock()
	exp := time.Now().AddDate(0, 0, 62).Unix()
	sites = []m{
		{"name": "shop", "kind": "php", "user": "shop", "hostnames": []string{"shop.example.com", "www.shop.example.com"}, "detail": "php 8.4", "tls": true,
			"root": "/home/shop/htdocs", "www": "bare", "allow_http": false, "speed": true, "webmail": false, "app": "wordpress", "cert_expiry": exp, "custom_vhost": false},
		{"name": "api", "kind": "node", "user": "api", "hostnames": []string{"api.example.com"}, "detail": "node 22 on port 3001", "tls": true,
			"root": "/home/api/htdocs", "www": "", "allow_http": false, "speed": false, "webmail": false, "cert_expiry": exp, "custom_vhost": false},
		{"name": "blog", "kind": "static", "user": "blog", "hostnames": []string{"blog.example.org"}, "detail": "", "tls": false,
			"root": "/home/blog/htdocs", "www": "", "allow_http": true, "speed": false, "webmail": false, "custom_vhost": false},
	}
	rules = []m{
		{"id": 1, "action": "Allow", "proto": "tcp", "port": "80", "source": "", "comment": "HTTP"},
		{"id": 2, "action": "Allow", "proto": "tcp", "port": "443", "source": "", "comment": "HTTPS"},
		{"id": 3, "action": "Allow", "proto": "tcp", "port": "25", "source": "", "comment": "SMTP"},
		{"id": 4, "action": "Allow", "proto": "tcp", "port": "3306", "source": "203.0.113.10", "comment": "Office MySQL"},
		{"id": 5, "action": "Deny", "proto": "both", "port": "", "source": "198.51.100.77", "comment": "Scanner"},
	}
	nextRule = 6
}

// find needs mu held, or is called from a place that only reads.
func find(name string) m {
	for _, s := range sites {
		if s["name"] == name {
			return s
		}
	}
	return nil
}

func answer(v any) (ctl.Response, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return ctl.Response{}, err
	}
	return ctl.Response{OK: true, Output: string(b)}, nil
}

func refuse(text string) (ctl.Response, error) { return ctl.Response{Error: text}, nil }

func phpValues() (map[string]string, map[string]string) {
	vals := map[string]string{}
	for _, d := range site.PHPSettings("256M") {
		vals[d.Name] = d.Default
	}
	vals["memory_limit"], vals["upload_max_filesize"], vals["post_max_size"] = "512M", "128M", "128M"
	return vals, map[string]string{"memory_limit": "512M", "upload_max_filesize": "128M", "post_max_size": "128M"}
}

func serviceItems() []services.Item {
	act := []string{"start", "restart", "reload"}
	items := []services.Item{
		{Key: "nginx", Label: "nginx", Group: services.GroupService, Installed: true, Unit: "nginx.service", State: "active", Active: true, Actions: act},
		{Key: "database", Label: "MariaDB", Group: services.GroupDatabase, Installed: true, Unit: "mariadb.service", State: "active", Active: true, Actions: []string{"start", "stop", "restart"}},
		{Key: "fail2ban", Label: "fail2ban", Group: services.GroupService, Installed: true, Unit: "fail2ban.service", State: "active", Active: true, Actions: []string{"start", "stop", "restart", "reload"}, Link: "/security"},
		{Key: "postfix", Label: "Postfix", Group: services.GroupService, Installed: true, Unit: "postfix.service", State: "active", Active: true, Actions: []string{"start", "stop", "restart", "reload"}, Link: "/email"},
		{Key: "dovecot", Label: "Dovecot", Group: services.GroupService, Installed: true, Unit: "dovecot.service", State: "active", Active: true, Actions: []string{"start", "stop", "restart", "reload"}, Link: "/email"},
		{Key: "opendkim", Label: "OpenDKIM", Group: services.GroupService, Installed: true, Unit: "opendkim.service", State: "active", Active: true, Actions: []string{"start", "stop", "restart"}, Link: "/email"},
	}
	for i := len(site.PHPVersions) - 1; i >= 0; i-- {
		v := site.PHPVersions[i]
		it := services.Item{Key: services.PHPKey(v), Label: "PHP-FPM " + v, Group: services.GroupPHP}
		if v == "8.4" || v == "8.3" {
			it.Installed, it.Unit, it.State, it.Active, it.Actions = true, "php"+v+"-fpm.service", "active", true, []string{"start", "stop", "restart", "reload"}
		} else {
			it.Installable = true
		}
		items = append(items, it)
	}
	for i := len(site.NodeVersions) - 1; i >= 0; i-- {
		v := site.NodeVersions[i]
		items = append(items, services.Item{Key: services.NodeKey(v), Label: "Node.js " + v, Group: services.GroupNode, Installed: v == "22" || v == "20", Installable: !(v == "22" || v == "20")})
	}
	return items
}

// done is the answer to an operation that would change the server: the page shows it as a success.
func done(op string) (ctl.Response, error) {
	return ctl.Response{OK: true, Output: "(demo) " + op + ": done. In this demo nothing is changed on a real server."}, nil
}

func call(r ctl.Request) (ctl.Response, error) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	switch r.Op {
	case "site.list":
		return answer(sites)
	case "site.info":
		s := find(r.Site)
		if s == nil {
			return refuse("no such site")
		}
		vals, set := phpValues()
		info := m{"name": s["name"], "kind": s["kind"], "user": s["user"], "hostnames": s["hostnames"], "root": s["root"], "root_sub": "", "root_outside": false,
			"tls": s["tls"], "running": true, "run_detail": "php8.4-fpm", "disk_bytes": 184_320_000, "last_backup": stamp(0),
			"installed_php": []string{"8.3", "8.4"}, "installed_node": []string{"20", "22"}, "installed_python": []string{"3.11", "3.12"}, "nginx": "1.28.3"}
		if e, ok := s["cert_expiry"]; ok {
			info["cert_expiry"] = e
		}
		switch s["kind"] {
		case "php":
			info["php_version"], info["php_values"], info["php_set"], info["php_memory_default"] = "8.4", vals, set, 256
		case "node":
			info["node_version"], info["entry"], info["port"], info["mem_mb"], info["run_detail"] = "22", "server.js", 3001, 256, "mpn-node-api.service"
		case "static":
			info["run_detail"] = "nginx"
		}
		return answer(info)
	case "site.add":
		if find(r.Site) != nil {
			return refuse("a website named " + r.Site + " exists already")
		}
		if len(sites) >= 12 {
			return refuse("the demo holds at most 12 websites; remove one first, or wait for the hourly reset")
		}
		detail := ""
		switch r.Kind {
		case "php":
			detail = "php " + r.PHP
		case "node":
			detail = fmt.Sprintf("node %s on port %d", r.Node, r.Port)
		case "python":
			detail = "python " + r.Python
		case "proxy":
			detail = r.Upstream
		}
		sites = append(sites, m{"name": r.Site, "kind": r.Kind, "user": r.User, "hostnames": r.Hosts, "detail": detail, "tls": false,
			"root": "/home/" + r.User + "/htdocs", "www": "", "allow_http": true, "speed": false, "webmail": false, "custom_vhost": false})
		return ctl.Response{OK: true, Output: "(demo) [1/3] account and files\n  run   useradd -m " + r.User + "\n[2/3] nginx vhost\n  write /etc/nginx/sites-enabled/" + r.Site + ".conf\n[3/3] reload nginx\ndone"}, nil
	case "site.remove":
		for i, s := range sites {
			if s["name"] == r.Site {
				sites = append(sites[:i], sites[i+1:]...)
				return done(r.Op)
			}
		}
		return refuse("no such site")
	case "services.status":
		return answer(serviceItems())
	case "firewall.status":
		return answer(m{"on": true, "active": true, "conflict": "", "has_nft": true, "locked": m{"ssh": []int{22}, "panel": []int{2610, 2611, 2612}}, "rules": rules})
	case "firewall.add":
		if len(rules) >= 30 {
			return refuse("the demo holds at most 30 rules")
		}
		rules = append(rules, m{"id": nextRule, "action": r.FwAction, "proto": r.FwProto, "port": r.FwPort, "source": r.FwSource, "comment": r.FwComment})
		nextRule++
		return done(r.Op)
	case "firewall.del":
		for i, x := range rules {
			if id, _ := x["id"].(int64); id == r.RuleID {
				rules = append(rules[:i], rules[i+1:]...)
				break
			}
			if id, _ := x["id"].(int); int64(id) == r.RuleID {
				rules = append(rules[:i], rules[i+1:]...)
				break
			}
		}
		return done(r.Op)
	case "security.status":
		return answer(m{"waf_mode": "detect", "waf_installed": true, "crs_version": "4.10.0", "f2b_on": true, "f2b_installed": true, "f2b_active": true,
			"ignore": []string{"127.0.0.1/8", "203.0.113.10"},
			"jails": []m{
				{"name": "sshd", "failed": 2, "total_failed": 148, "banned": 1, "total_banned": 9, "ips": []string{"198.51.100.23"}},
				{"name": "mpn-panel", "failed": 0, "total_failed": 12, "banned": 0, "total_banned": 1, "ips": []string{}},
				{"name": "mpn-modsec", "failed": 1, "total_failed": 36, "banned": 2, "total_banned": 5, "ips": []string{"192.0.2.44", "192.0.2.45"}},
			}})
	case "panel.sslinfo":
		return answer(m{"mode": "letsencrypt", "domain": "panel.example.com", "issuer": "Let's Encrypt (E7)", "names": []string{"panel.example.com"},
			"not_before": now.AddDate(0, 0, -20).Unix(), "not_after": now.AddDate(0, 0, 70).Unix(), "covers": true, "trusted": true,
			"panel_port": 2610, "pma_port": 2611, "plain": false, "pma_path": false})
	case "panel.updatecheck":
		return ctl.Response{OK: true, Output: "this is " + web.Version + ", the latest release"}, nil
	case "panel.update":
		return refuse("updating is switched off in the demo")
	case "mail.status":
		recs := mail.Records("example.com", "mail.example.com", "mail", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy3demoKEYdemoKEYdemoKEYdemoKEYdemoKEY")
		return answer(m{"on": true, "host": "mail.example.com", "installed": true, "services": m{"postfix": true, "dovecot": true, "opendkim": true},
			"ports": []int{25, 465, 587, 993}, "cert": m{"mode": "letsencrypt", "days": 74, "issuer": "Let's Encrypt (E7)", "covers": true},
			"webmail":   m{"on": true, "installed": true, "active": true, "port": 2612, "url": ""},
			"domains":   []m{{"name": "example.com", "has_key": true, "mailboxes": 2, "aliases": 1, "records": recs}},
			"mailboxes": []m{{"address": "info@example.com", "quota_mb": 1024}, {"address": "sales@example.com", "quota_mb": 0}},
			"aliases":   []m{{"address": "hello@example.com", "targets": []string{"info@example.com"}}}})
	case "mail.cfdetect":
		return answer(m{"cloudflare": true})
	case "cloud.status":
		return answer(m{"connected": true, "kind": "s3", "where": "S3 Cloudflare R2: backups/mpn-backups", "shown": m{"provider": "Cloudflare"}, "folder": "backups",
			"pending": nil, "enabled": true,
			"state": m{"at": now.Add(-5 * time.Hour).Unix(), "ok": true, "message": "", "uploaded": 1, "present": 7}, "fetch": nil})
	case "cloud.list":
		return answer([]m{{"stamp": stamp(0), "size_mb": 182.4, "local": true}, {"stamp": stamp(1), "size_mb": 181.9, "local": true}, {"stamp": stamp(9), "size_mb": 170.2, "local": false}})
	case "db.list":
		b := strings.ReplaceAll(r.Site, "-", "_")
		return answer([]m{{"name": b, "site": r.Site}, {"name": b + "_staging", "site": r.Site}})
	case "backup.list":
		rows := []m{}
		for i := 0; i < 5; i++ {
			rows = append(rows, m{"site": r.Site, "backup": stamp(i), "state": "ok", "files": true, "databases": []string{strings.ReplaceAll(r.Site, "-", "_")}, "size_mb": 180.5 - float64(i)})
		}
		return answer(rows)
	case "backup.keepinfo":
		return answer(m{"keep": 7})
	case "site.sslinfo":
		s := find(r.Site)
		if s == nil || s["tls"] != true {
			return answer(m{"mode": "none"})
		}
		return answer(m{"mode": "letsencrypt", "issuer": "Let's Encrypt (E7)", "names": s["hostnames"],
			"not_before": now.AddDate(0, 0, -28).Unix(), "not_after": now.AddDate(0, 0, 62).Unix(), "covers": true, "pending_csr": "", "trusted": true})
	case "site.vhost":
		return answer(m{"custom": false, "tls": true, "text": "server {\n    listen 443 ssl;\n    http2 on;\n    server_name shop.example.com www.shop.example.com;\n    root /home/shop/htdocs;\n    index index.php index.html;\n\n    ssl_certificate     /etc/mpn/certs/shop/fullchain.pem;\n    ssl_certificate_key /etc/mpn/certs/shop/privkey.pem;\n\n    location / {\n        try_files $uri $uri/ /index.php?$args;\n    }\n\n    location ~ \\.php$ {\n        fastcgi_pass unix:/run/php/shop.sock;\n        include fastcgi_params;\n        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n    }\n}\n"})
	case "site.cronlist":
		return answer([]m{
			{"id": 1, "schedule": "*/5 * * * *", "command": "php /home/shop/htdocs/wp-cron.php", "enabled": true},
			{"id": 2, "schedule": "0 3 * * *", "command": "php /home/shop/htdocs/artisan schedule:run", "enabled": true},
			{"id": 3, "schedule": "@weekly", "command": "/home/shop/bin/cleanup.sh", "enabled": false},
		})
	case "site.log":
		day := now.Format("02/Jan/2006")
		lines := []string{
			`203.0.113.5 - - [` + day + `:09:14:02 +0000] "GET / HTTP/2.0" 200 18432 "-" "Mozilla/5.0"`,
			`203.0.113.5 - - [` + day + `:09:14:03 +0000] "GET /wp-content/themes/twentytwentyfive/style.css HTTP/2.0" 200 5210 "https://shop.example.com/" "Mozilla/5.0"`,
			`198.51.100.9 - - [` + day + `:09:15:40 +0000] "GET /wp-login.php HTTP/2.0" 200 4412 "-" "curl/8.5.0"`,
			`198.51.100.9 - - [` + day + `:09:15:41 +0000] "POST /wp-login.php HTTP/2.0" 302 0 "-" "curl/8.5.0"`,
			`66.249.66.1 - - [` + day + `:09:20:11 +0000] "GET /robots.txt HTTP/2.0" 200 67 "-" "Googlebot/2.1"`,
		}
		kind := r.LogKind
		if kind == sitelog.Error {
			lines = []string{now.Format("2006/01/02") + ` 09:16:22 [error] 1021#1021: *4412 open() "/home/shop/htdocs/favicon.ico" failed (2: No such file or directory), client: 203.0.113.5, server: shop.example.com`}
		}
		if kind == sitelog.App {
			lines = []string{"Server listening on port 3001", "GET /health 200 2ms"}
		}
		return answer(sitelog.Result{Kind: kind, Path: "/var/log/mpn/sites/" + r.Site + "/" + kind + ".log", Exists: true, Size: 482_113, Lines: lines, Matched: len(lines)})
	case "wp.status":
		return answer(m{"version": "6.8.1", "url": "https://shop.example.com", "core_update": "6.8.2",
			"plugins": []m{
				{"name": "akismet", "title": "Akismet Anti-spam", "status": "active", "version": "5.4", "update": "available", "update_version": "5.5"},
				{"name": "wordpress-seo", "title": "Yoast SEO", "status": "active", "version": "25.1", "update": "none", "update_version": ""},
				{"name": "hello", "title": "Hello Dolly", "status": "inactive", "version": "1.7.2", "update": "none", "update_version": ""},
			},
			"themes": []m{
				{"name": "twentytwentyfive", "title": "Twenty Twenty-Five", "status": "active", "version": "1.2", "update": "none", "update_version": ""},
				{"name": "twentytwentyfour", "title": "Twenty Twenty-Four", "status": "inactive", "version": "1.3", "update": "none", "update_version": ""},
			}})
	case "wp.search":
		return answer([]m{{"name": "Yoast SEO", "slug": "wordpress-seo", "rating": 96, "version": "25.1", "short_description": "Improve your WordPress SEO."},
			{"name": "Rank Math SEO", "slug": "seo-by-rank-math", "rating": 98, "version": "1.0.246", "short_description": "SEO made easy."}})
	case "site.access":
		if r.Enable {
			return ctl.Response{OK: true, Output: fmt.Sprintf("(demo) user %q can now log in over SSH/SFTP", r.User)}, nil
		}
		return done(r.Op)
	case "db.pma", "db.pmadrop":
		return refuse("phpMyAdmin is not part of the demo")
	}
	return done(r.Op)
}

// samples fills the monitoring charts with a day of believable numbers, then keeps adding one every 30 seconds.
func samples(mon *monitor.Collector) {
	at := func(t time.Time) monitor.Sample {
		x := float64(t.Unix()) / 3600
		return monitor.Sample{T: t.Unix(),
			CPU:   math.Max(1, 14+10*math.Sin(x/2)+6*math.Sin(x*3)),
			Load:  math.Max(0.05, 0.25+0.2*math.Sin(x/2)+0.1*math.Sin(x*3)),
			MemMB: 410 + 60*math.Sin(x/3) + 12*math.Sin(x*5), SwapMB: 24,
			Rx: math.Max(800, 42000+30000*math.Sin(x/1.5)+9000*math.Sin(x*4)), Tx: math.Max(500, 91000+60000*math.Sin(x/1.5)+15000*math.Sin(x*4))}
	}
	now := time.Now()
	for t := now.Add(-24 * time.Hour); t.Before(now); t = t.Add(30 * time.Second) {
		mon.Add(at(t))
	}
	for t := range time.Tick(30 * time.Second) {
		mon.Add(at(t))
	}
}

// loginNote puts the demo's sign-in details above the sign-in form.
type loginNote struct {
	http.ResponseWriter
	buf  bytes.Buffer
	code int
}

func (l *loginNote) WriteHeader(code int)        { l.code = code }
func (l *loginNote) Write(b []byte) (int, error) { return l.buf.Write(b) }

var notes = map[string]string{
	"en": "This is a demo. Sign in with user <b>%s</b> and password <b>%s</b>. Changes are not real and everything resets every hour.",
	"vi": "Đây là bản demo. Đăng nhập với tài khoản <b>%s</b> và mật khẩu <b>%s</b>. Mọi thay đổi chỉ là giả lập và được đặt lại mỗi giờ.",
	"zh": "这是演示版。请使用用户名 <b>%s</b> 和密码 <b>%s</b> 登录。所有更改均为模拟，每小时重置一次。",
}

func withLoginNote(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			next.ServeHTTP(w, r)
			return
		}
		l := &loginNote{ResponseWriter: w, code: 200}
		next.ServeHTTP(l, r)
		page := l.buf.String()
		lang := "en"
		for _, x := range []string{"vi", "zh"} {
			if strings.Contains(page, `<html lang="`+x) {
				lang = x
			}
		}
		note := `<div class="alert-warn mb-4" role="note"><span>` + fmt.Sprintf(notes[lang], demoUser, demoPass) + `</span></div>`
		page = strings.Replace(page, `<div class="card p-6">`, note+`<div class="card p-6">`, 1)
		w.Header().Del("Content-Length")
		w.WriteHeader(l.code)
		_, _ = w.Write([]byte(page))
	})
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8790", "address to listen on (a loopback address behind nginx)")
	host := flag.String("host", "demo.mpanel.biz", "public name of the demo")
	secure := flag.Bool("secure", true, "the demo is reached over HTTPS")
	flag.Parse()

	dir, err := os.MkdirTemp("", "mpn-demo-")
	if err != nil {
		log.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	accountFile := filepath.Join(dir, "account.json")
	hash, err := webauth.Hash(demoPass)
	if err != nil {
		log.Fatal(err)
	}
	if err := webauth.SaveAccount(accountFile, webauth.Account{User: demoUser, Hash: hash}, -1, -1); err != nil {
		log.Fatal(err)
	}
	writePasswd := func() {
		var b strings.Builder
		mu.Lock()
		for i, s := range sites {
			fmt.Fprintf(&b, "%s:x:%d:%d::/home/%s:/bin/bash\n", s["user"], 1001+i, 1001+i, s["user"])
		}
		mu.Unlock()
		_ = os.WriteFile(passwd, []byte(b.String()), 0o644)
	}
	resetData()
	writePasswd()

	mon := monitor.New(func(name string) ([]byte, error) {
		if name == "uptime" {
			return []byte("1209600.55 2000000.00"), nil
		}
		return nil, os.ErrNotExist
	}, "")
	mon.SetMachine(monitor.Machine{Cores: 1, MemTotalMB: 1024, SwapTotalMB: 1024})
	go samples(mon)

	ssh := newFakeSSH()
	sessions := webauth.NewSessions(30*time.Minute, 2*time.Hour, 500)
	go func() {
		for range time.Tick(resetEvery) {
			resetData()
			writePasswd()
			ssh.reset()
			log.Print("demo data reset")
		}
	}()
	go func() { // a website added in the demo gets an account, so its SSH card and terminal work
		for range time.Tick(5 * time.Second) {
			writePasswd()
		}
	}()

	web.Version = "1.2.1"
	srv := &web.Server{
		HostOS:  "Ubuntu 24.04.3 LTS",
		Mon:     mon,
		Account: func() (webauth.Account, error) { return webauth.LoadAccount(accountFile) },
		// Changing the password or turning on the two-step sign-in would lock other visitors out, so they are refused.
		SaveAccount: func(webauth.Account) error { return fmt.Errorf("the demo account cannot be changed") },
		Sessions:    sessions,
		Throttle:    webauth.NewThrottle(),
		Hosts:       []string{*host},
		Secure:      *secure,
		// nginx on the same machine sets X-Real-IP. Without it every visitor would share 127.0.0.1, and one person typing
		// wrong passwords would lock everybody out of the sign-in.
		TrustProxy:   true,
		InstalledPHP: func() []string { return []string{"8.3", "8.4"} },
		NodeRoot:     filepath.Join(dir, "node"),
		PasswdFile:   passwd,
		UserExists:   func(string) bool { return false },
		LoginCheck:   func(string) error { return nil },
		Dialer:       ssh,
		MaxUpload:    2 << 20,
		MaxTerminals: 20,
		TermIdle:     10 * time.Minute,
		TermMax:      30 * time.Minute,
		UnitState: func(unit string) (string, string) {
			switch unit {
			case "nginx.service", "mariadb.service", "cron.service", "ssh.service", "mpn-root.service", "mpn-web.service", "mpn-firewall.service", "php8.3-fpm.service", "php8.4-fpm.service":
				return unit, "active"
			}
			return "", ""
		},
		Call: call,
	}
	for _, v := range []string{"20", "22"} {
		_ = os.MkdirAll(filepath.Join(dir, "node", v, "bin"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "node", v, "bin", "node"), []byte("x"), 0o755)
	}
	hs := &http.Server{Addr: *listen, Handler: withLoginNote(srv.Handler()), MaxHeaderBytes: 16 << 10,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second}
	log.Printf("demo panel on http://%s for %s (user %s, password %s)", *listen, *host, demoUser, demoPass)
	log.Fatal(hs.ListenAndServe())
}
