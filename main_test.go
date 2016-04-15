package main

import (
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	syslog "github.com/RackSec/srslog"
)

var PapertrailUrl = "tcp+tls://logs3.papertrailapp.com:32912"

// RFC5424Formatter provides an RFC 5424 compliant message.
func RFC5424Formatter(p syslog.Priority, hostname, tag, content string) string {
	timestamp := time.Now().Format(time.RFC3339)
	// pid := os.Getpid()
	// appName := os.Args[0]
	msg := fmt.Sprintf("<%d>%d %s %s %s %s - - %s",
		22, 1, timestamp, "httpd", "web:RXZMCQEPDKO", "1d11a78279e0", content)
	return msg
}

// Reformatter takes a syslog-ish line, parses it,
// then returns a function that will re-format it as proper syslog
func Reformatter(line string) syslog.Formatter {
	timestamp := time.Now().Format(time.RFC3339)
	hostname := "convox"
	tag := "unknown"
	content := line

	if m := Re.FindStringSubmatch(line); m != nil {
		hostname = m[3]
		tag = fmt.Sprintf("%s.%s", m[4], m[5])
		content = m[6]
	}

	return func(p syslog.Priority, h, t, c string) string {
		msg := fmt.Sprintf("<%d> %s %s %s[%d]: %s",
			p, timestamp, hostname, tag, os.Getpid(), content+c)
		return msg
	}
}

func Info(w *syslog.Writer, line string) error {
	w.SetFormatter(Reformatter(line))
	return w.Info("")
}

func Formatter(p syslog.Priority, hostname, tag, content string) string {
	timestamp := time.Now().Format(time.RFC3339)
	// pid := os.Getpid()
	// appName := os.Args[0]
	msg := fmt.Sprintf("<%d>%d %s %s %s %s - - %s",
		22, 1, timestamp, "httpd", "web:RXZMCQEPDKO", "1d11a78279e0", content)
	return msg
}

func TestPapertrail(t *testing.T) {
	os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "test-syslog")
	u, _ := url.Parse(PapertrailUrl)
	w, _ := syslog.Dial(u.Scheme, u.Host, syslog.LOG_INFO, "tag")
	w.SetFormatter(contentFormatter)
	w.Info(`1460682044602 httpd web:RGBCKLEZHCX/ec329dcefd61 10.0.3.37 - - [15/Apr/2016:01:00:44 +0000] "GET / HTTP/1.1" 304 -`)

	// Info(w, "2016-04-12 22:54:54 i-553ffcd2 convox/agent:0.66 : Starting web process 7c490475314f")
	// Info(w, "2016-04-12 22:54:55 i-553ffcd2 convox-httpd/web:RXZMCQEPDKO : AH00558: httpd: Could not reliably determine the server's fully qualified domain name, using 172.17.0.5. Set the 'ServerName' directive globally to suppress this message")
}
