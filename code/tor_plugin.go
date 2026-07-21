package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var UNIX_PLUGIN_LISTENER = TEST_PREFIX + "/run/spr-krun-plugin/spr-tor.sock"

var TorBinary = "/usr/bin/tor"

// the name of the interface from the docker network (see docker-compose.yml)
// which is visible outside of the container.
var gSPRTorInterface = "spr-tor"

var gControl = &ControlClient{
	SocketPath: TorControlSocket,
	CookiePath: TorCookieFile,
}

// ---- tor daemon supervision ----

var (
	torProcMtx sync.Mutex
	torProc    *os.Process
)

func superviseTor() {
	for {
		cmd := exec.Command(TorBinary, "-f", TorrcPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Println("[-] failed to start tor:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		torProcMtx.Lock()
		torProc = cmd.Process
		torProcMtx.Unlock()
		log.Println("[+] tor started, pid", cmd.Process.Pid)

		err := cmd.Wait()
		torProcMtx.Lock()
		torProc = nil
		torProcMtx.Unlock()
		log.Println("[-] tor exited:", err)
		time.Sleep(5 * time.Second)
	}
}

// reloadTor asks the running daemon to re-read torrc: first over the control
// socket, falling back to SIGHUP if the control channel is not up yet.
func reloadTor() error {
	if err := gControl.Signal("RELOAD"); err == nil {
		return nil
	}
	torProcMtx.Lock()
	defer torProcMtx.Unlock()
	if torProc == nil {
		// supervisor will start tor with the new torrc
		return nil
	}
	return torProc.Signal(syscall.SIGHUP)
}

func getContainerIP() string {
	if ip := os.Getenv("CONTAINER_IP"); ip != "" {
		return ip
	}
	iface, err := net.InterfaceByName("eth0")
	if err == nil {
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	log.Println("[-] could not determine container IP, falling back to 127.0.0.1")
	return "127.0.0.1"
}

// ---- HTTP handlers ----

func httpJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Println("[-] encoding response failed:", err)
	}
}

type TorStatus struct {
	Running            bool
	Version            string
	BootstrapProgress  int
	BootstrapSummary   string
	CircuitEstablished bool
	BytesRead          int64
	BytesWritten       int64
	ContainerIP        string
	SocksPort          string
	TransPort          string
	DNSPort            string
}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	Configmtx.RLock()
	cfg := gConfig
	Configmtx.RUnlock()

	ip := getContainerIP()
	status := TorStatus{
		ContainerIP: ip,
		SocksPort:   fmt.Sprintf("%s:%d", ip, TorSocksPortNum),
	}
	if cfg.TransPortEnabled {
		status.TransPort = fmt.Sprintf("%s:%d", ip, TorTransPortNum)
	}
	if cfg.DNSPortEnabled {
		status.DNSPort = fmt.Sprintf("%s:%d", ip, TorDNSPortNum)
	}

	info, err := gControl.GetInfo("version", "status/bootstrap-phase",
		"status/circuit-established", "traffic/read", "traffic/written")
	if err != nil {
		// tor still bootstrapping the control socket or restarting;
		// report a well-formed "not running (yet)" status
		httpJSON(w, status)
		return
	}

	status.Running = true
	status.Version = info["version"]
	status.BootstrapProgress, status.BootstrapSummary =
		parseBootstrapPhase(info["status/bootstrap-phase"])
	status.CircuitEstablished = info["status/circuit-established"] == "1"
	status.BytesRead, _ = strconv.ParseInt(info["traffic/read"], 10, 64)
	status.BytesWritten, _ = strconv.ParseInt(info["traffic/written"], 10, 64)

	httpJSON(w, status)
}

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	Configmtx.RLock()
	defer Configmtx.RUnlock()
	httpJSON(w, gConfig)
}

func handlePutConfig(w http.ResponseWriter, r *http.Request) {
	cfg := Config{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := validateConfig(&cfg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	Configmtx.Lock()
	gConfig = cfg
	err := writeConfigLocked()
	Configmtx.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ip := getContainerIP()
	if err := writeTorrc(&cfg, ip); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := reloadTor(); err != nil {
		log.Println("[-] tor reload failed:", err)
	}
	syncTransProxy(&cfg, ip)

	httpJSON(w, cfg)
}

func handleNewNym(w http.ResponseWriter, r *http.Request) {
	if err := gControl.Signal("NEWNYM"); err != nil {
		http.Error(w, "tor is not running: "+err.Error(), 503)
		return
	}
	httpJSON(w, map[string]bool{"success": true})
}

func handleGetCircuits(w http.ResponseWriter, r *http.Request) {
	info, err := gControl.GetInfo("circuit-status")
	if err != nil {
		http.Error(w, "tor is not running: "+err.Error(), 503)
		return
	}
	httpJSON(w, parseCircuitStatus(info["circuit-status"]))
}

// ---- static UI ----

type spaHandler struct {
	staticPath string
	indexPath  string
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path, err := filepath.Abs(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	path = filepath.Join(h.staticPath, path)
	if !strings.HasPrefix(path, filepath.Clean(h.staticPath)) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.FileServer(http.Dir(h.staticPath)).ServeHTTP(w, r)
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func main() {
	log.SetOutput(os.Stdout)

	if err := loadConfig(); err != nil {
		log.Println("[-] loadConfig:", err)
	}

	Configmtx.RLock()
	cfg := gConfig
	Configmtx.RUnlock()
	if err := writeTorrc(&cfg, getContainerIP()); err != nil {
		log.Println("[-] writing torrc failed:", err)
	} else {
		go superviseTor()
	}
	syncTransProxy(&cfg, getContainerIP())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", handleGetStatus)
	mux.HandleFunc("GET /config", handleGetConfig)
	mux.HandleFunc("PUT /config", handlePutConfig)
	mux.HandleFunc("POST /newnym", handleNewNym)
	mux.HandleFunc("GET /circuits", handleGetCircuits)
	mux.HandleFunc("GET /topology", handleGetTopology)
	mux.Handle("/", spaHandler{staticPath: "/ui", indexPath: "index.html"})

	os.Remove(UNIX_PLUGIN_LISTENER)
	os.MkdirAll(filepath.Dir(UNIX_PLUGIN_LISTENER), 0755)
	listener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}
	if err := os.Chmod(UNIX_PLUGIN_LISTENER, 0770); err != nil {
		log.Println("[-] chmod socket:", err)
	}

	server := http.Server{Handler: logRequest(mux)}
	log.Println("[+] spr-tor plugin listening on", UNIX_PLUGIN_LISTENER)
	if err := server.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
