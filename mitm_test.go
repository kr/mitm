package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"path"
	"errors"
)

var hostname, _ = os.Hostname()

var (
	nettest  = flag.Bool("nettest", false, "run tests over network")
	dir      = path.Join(os.Getenv("HOME"), ".rometer")
	keyFile  = path.Join(dir, "ca-key.pem")
	certFile = path.Join(dir, "ca-cert.pem")
)

func init() {
	flag.Parse()
}

func testProxy(t *testing.T, ca *tls.Certificate, setupReq func(req *http.Request), analyze func(RequestRecord), downstream http.HandlerFunc, checkResp func(*http.Response)) {
	ds := httptest.NewTLSServer(downstream)
	defer ds.Close()

	p := &Proxy{
		CA: ca,
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			//CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		Analyze: analyze,
	}

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal("Listen:", err)
	}
	defer l.Close()

	go func() {
		if err := http.Serve(l, p); err != nil {
			if !strings.Contains(err.Error(), "use of closed network") {
				t.Fatal("Serve:", err)
			}
		}
	}()

	t.Logf("requesting %q", ds.URL)
	req, err := http.NewRequest("GET", ds.URL, nil)
	if err != nil {
		t.Fatal("NewRequest:", err)
	}
	setupReq(req)

	u, err := url.Parse("http://" + l.Addr().String())

	c := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	t.Log(l.Addr().String())

	resp, err := c.Do(req)

	if resp == nil {
		t.Log("Null response:")
	}
	if err != nil {
		t.Fatal("Do:", err)
	}
	checkResp(resp)
}

func loadCA() (cert tls.Certificate, err error) {
	// TODO(kr): check file permissions
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if os.IsNotExist(err) {
		err = errors.New("CA Certificate not found on path: " + dir)
	}
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	return
}


func TestAnalyzeMethodCalled(t *testing.T) {
	//TODO Run test also on https when http.client bug fixed https://github.com/golang/go/issues/28012
	ca, err := loadCA()
	if err != nil {
		t.Fatal(err)
	}

	var analyzed bool
	testProxy(t, &ca, func(req *http.Request) {
		nreq, _ := http.NewRequest("GET", "http://www.google.com/", nil)
		*req = *nreq
	}, func(rr RequestRecord) {
		analyzed = true
	}, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("this shouldn't be hit")
	}, func(resp *http.Response) {
		if !analyzed {
			t.Errorf("expected analysis")
		}
		got, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("ReadAll:", err)
		}
		if code := resp.StatusCode; code != 200 {
			t.Errorf("want code 200, got %d", code)
		}
		if g := string(got); !strings.Contains(g, "doctype") {
			t.Errorf("want Google, got %q", g)
		}
	})
}
