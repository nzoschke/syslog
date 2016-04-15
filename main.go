package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	syslog "github.com/RackSec/srslog"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/jasonmoo/lambda_proc"
	"github.com/mweagle/Sparta/aws/cloudwatchlogs"
)

func main() {
	lambda_proc.Run(func(context *lambda_proc.Context, eventJSON json.RawMessage) (interface{}, error) {
		syslogUrl, err := readOrDescribeURL(context.FunctionName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "readOrDescribeURL err=%s\n", err)
			return nil, err
		}

		u, err := url.Parse(syslogUrl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "url.Parse url=%s err=%s\n", syslogUrl, err)
			return nil, err
		}

		fmt.Fprintf(os.Stderr, "event=%q url=%s\n", eventJSON, u.String())

		var event cloudwatchlogs.Event
		err = json.Unmarshal([]byte(eventJSON), &event)
		if err != nil {
			fmt.Fprintf(os.Stderr, "json.Unmarshal err=%s\n", err)
			return nil, err
		}

		d, err := event.AWSLogs.DecodedData()
		if err != nil {
			fmt.Fprintf(os.Stderr, "AWSLogs.DecodedData err=%s\n", err)
			return nil, err
		}

		fmt.Fprintf(os.Stderr, "DecodedData=%+v\n", d)

		w, err := syslog.Dial(u.Scheme, u.Host, syslog.LOG_INFO, "convox/syslog")
		if err != nil {
			fmt.Fprintf(os.Stderr, "syslog.Dial scheme=%s host=%s err=%s\n", u.Scheme, u.Host, err)
			return nil, err
		}
		defer w.Close()

		w.SetFormatter(contentFormatter)

		logs, errs := 0, 0
		for _, e := range d.LogEvents {
			err := w.Info(fmt.Sprintf("%d %s", e.Timestamp, e.Message))
			if err != nil {
				errs += 1
			} else {
				logs += 1
			}
		}

		return fmt.Sprintf("LogGroup=%s LogStream=%s MessageType=%s NumLogEvents=%d logs=%d errs=%d", d.LogGroup, d.LogStream, d.MessageType, len(d.LogEvents), logs, errs), nil
	})
}

var Re = regexp.MustCompile(`([\d]+) ([^ ]+) ([^:]+):([^/]+)/([^ ]+) (.*)`)

// contentFormatter parses the content string to populate the entire syslog RFC5424 message.
// No os information is referenced.
// 1460682044602 httpd web:RGBCKLEZHCX/ec329dcefd61 10.0.3.37 - - [15/Apr/2016:01:00:44 +0000] "GET / HTTP/1.1" 304 -
func contentFormatter(p syslog.Priority, hostname, tag, content string) string {
	hostname = os.Getenv("AWS_LAMBDA_FUNCTION_NAME")
	timestamp := time.Now()
	program := ""
	tag = "-"

	if m := Re.FindStringSubmatch(content); m != nil {
		fmt.Printf("M: %+v\n", m)
		i, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stcvonv.ParseInt s=%s err=%s\n", m[1], err)
		} else {
			sec := i / 1000
			nsec := i - (sec * 1000)
			timestamp = time.Unix(sec, nsec)
		}

		program = fmt.Sprintf("%s:%s", m[3], m[4])
		tag = m[5]
		content = m[6]
	} else {
		fmt.Fprintf(os.Stderr, "Re.FindStringSubmatch miss\n")
	}

	msg := fmt.Sprintf("<%d>%d %s %s %s %s - - %s",
		22, 1, timestamp.Format(time.RFC3339), hostname, program, tag, content)

	fmt.Fprintln(os.Stderr, msg)

	return msg
}

func readOrDescribeURL(name string) (string, error) {
	data, err := ioutil.ReadFile("/tmp/url")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ioutil.ReadFile err=%s\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "ioutil.ReadFile url=%s\n", string(data))
		return string(data), nil
	}

	cf := cloudformation.New(session.New(&aws.Config{}))

	resp, err := cf.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(name),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cf.DescribeStacks err=%s\n", err)
		return "", err
	}

	fmt.Fprintf(os.Stderr, "cf.DescribeStacks resp=%+v\n", resp)

	if len(resp.Stacks) == 1 {
		for _, p := range resp.Stacks[0].Parameters {
			if *p.ParameterKey == "Url" {
				url := *p.ParameterValue

				err := ioutil.WriteFile("/tmp/url", []byte(url), 0644)
				if err != nil {
					fmt.Fprintf(os.Stderr, "ioutil.WriteFile url=%s err=%s\n", url, err)
				} else {
					fmt.Fprintf(os.Stderr, "ioutil.WriteFile url=%s\n", url)
				}

				return url, nil
			}
		}
	}

	return "", fmt.Errorf("Could not find stack %s Url Parameter", name)
}
