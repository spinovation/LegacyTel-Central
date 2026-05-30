package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HardwareInfo represents collected system hardware stats
type HardwareInfo struct {
	CPUModel    string  `json:"cpu_model"`
	CPUCores    int     `json:"cpu_cores"`
	TotalRAMGB  float64 `json:"total_ram_gb"`
	TotalDiskGB float64 `json:"total_disk_gb"`
	SysModel    string  `json:"sys_model"`
}

// AgentNode represents a registered LegacyTel agent in the fleet database
type AgentNode struct {
	ID                 string                 `json:"id"`
	Hostname           string                 `json:"hostname"`
	IP                 string                 `json:"ip"`
	OS                 string                 `json:"os"`
	Version            string                 `json:"version"`
	HypervisorType     string                 `json:"hypervisor_type"`
	HypervisorName     string                 `json:"hypervisor_name"`
	AppInventory       []string               `json:"app_inventory"`
	Hardware           HardwareInfo           `json:"hardware"`
	CPUUsage           float64                `json:"cpu_usage"`
	MemoryUsage        float64                `json:"memory_usage"`
	Throughput         float64                `json:"throughput"`
	LastHeartbeat      time.Time              `json:"last_heartbeat"`
	Status             string                 `json:"status"` // "ACTIVE", "INACTIVE", "UPGRADING", "ROLLBACK"
	TargetPolicyVersion int                    `json:"target_policy_version"`
	CurrentPolicyVersion int                   `json:"current_policy_version"`
	PendingUpgrade     string                 `json:"pending_upgrade"` // Target version if upgrading
}

// AuditLogRecord represents a standardized enterprise security audit log
type AuditLogRecord struct {
	Timestamp   string `json:"timestamp"`
	Host        string `json:"host"`
	EventCode   string `json:"event_code"`
	Description string `json:"description"`
	SourceIP    string `json:"source_ip"`
	DestIP      string `json:"dest_ip"`
	User        string `json:"user"`
	Email       string `json:"email"`
	Domain      string `json:"domain"`
	RawLog      string `json:"raw_log"`
}

// AgentBinary represents a stored package in the Central Repository
type AgentBinary struct {
	Version    string    `json:"version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	Channel    string    `json:"channel"` // "stable" (N), "previous" (N-1), "beta" (Beta)
	UploadTime time.Time `json:"upload_time"`
	Checksum   string    `json:"checksum"`
}

// FleetDatabase holds the in-memory state of the registered nodes
type FleetDatabase struct {
	mu           sync.RWMutex
	Nodes        map[string]*AgentNode
	Binaries     map[string][]*AgentBinary // Key: "os/arch" -> List of versions
	ClientChans  map[chan string]bool
	PolicyConfig string
	PolicyVer    int
	AuditLogs    []*AuditLogRecord // Caches the last 100 security logs
}

var db = &FleetDatabase{
	Nodes:       make(map[string]*AgentNode),
	Binaries:    make(map[string][]*AgentBinary),
	ClientChans: make(map[chan string]bool),
	PolicyVer:   1,
	PolicyConfig: `receivers:
  syslog:
    port: 514
  otlp:
    port: 4317
exporters:
  splunk_hec:
    enabled: true
    index: "security_fleet"`,
	AuditLogs: make([]*AuditLogRecord, 0),
}

func main() {
	// Initialize default binary repository packages (N, N-1, Beta) for verification
	initDefaultBinaryRepository()

	// Initialize default security audit logs to pre-populate log stream
	initDefaultSecurityLogs()

	// Root route serving the fleet management dashboard
	http.HandleFunc("/", handleDashboard)
	
	// API Endpoints for Fleet Nodes (mTLS / HTTP secure streams)
	http.HandleFunc("/api/v1/register", handleRegister)
	http.HandleFunc("/api/v1/heartbeat", handleHeartbeat)
	http.HandleFunc("/api/v1/policy", handlePolicy)
	
	// API Endpoints for UI / Admin Console control
	http.HandleFunc("/api/v1/admin/upgrade", handleAdminUpgrade)
	http.HandleFunc("/api/v1/admin/upgrade-all", handleAdminUpgradeAll)
	http.HandleFunc("/api/v1/admin/policy/update", handleAdminPolicyUpdate)
	http.HandleFunc("/api/v1/admin/binaries", handleAdminBinaries)
	http.HandleFunc("/api/v1/stream", handleSSEStream)

	// Mock database generator for direct evaluation/demo purposes
	go runMockHeartbeatSimulator()

	serverAddr := ":9090"
	log.Printf("[CONTROL PLANE] LegacyTel Central Fleet Manager starting on %s", serverAddr)
	log.Printf("[CONTROL PLANE] Access the central dashboard: http://localhost:9090")
	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		log.Fatalf("Control Plane server failed: %v", err)
	}
}

func initDefaultBinaryRepository() {
	db.mu.Lock()
	defer db.mu.Unlock()

	platforms := []string{"linux", "windows", "darwin"}
	for _, osName := range platforms {
		key := osName + "/amd64"
		db.Binaries[key] = []*AgentBinary{
			{Version: "v2.0.0", OS: osName, Arch: "amd64", Channel: "stable", UploadTime: time.Now().Add(-48 * time.Hour), Checksum: "sha256-a1b2c3d4"},
			{Version: "v1.9.8", OS: osName, Arch: "amd64", Channel: "previous", UploadTime: time.Now().Add(-240 * time.Hour), Checksum: "sha256-e5f6g7h8"},
			{Version: "v2.1.0-beta", OS: osName, Arch: "amd64", Channel: "beta", UploadTime: time.Now().Add(-2 * time.Hour), Checksum: "sha256-i9j0k1l2"},
		}
	}
}

func initDefaultSecurityLogs() {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Pre-populate with 20 diverse historical security events
	now := time.Now()
	nodeKeys := []string{"node-linux-web", "node-win-ad", "node-mac-dev", "node-legacy-solaris", "node-legacy-aix", "node-legacy-tandem"}
	
	for i := 0; i < 20; i++ {
		// Calculate a past timestamp (5 minutes apart)
		eventTime := now.Add(time.Duration(-5 * (20 - i)) * time.Minute)
		
		// Determine target node
		nodeKey := nodeKeys[i%len(nodeKeys)]
		targetNode, exists := db.Nodes[nodeKey]
		if !exists {
			continue
		}
		
		// Select event template sequentially so we get a good representative mix
		tmpl := eventTemplates[i%len(eventTemplates)]
		u := mockUsers[i%len(mockUsers)]
		srcIP := mockIPs[i%len(mockIPs)]
		pid := 2000 + i*15 + 7
		
		var raw string
		switch tmpl.Code {
		case "LL01", "LL03":
			raw = fmt.Sprintf(tmpl.Raw, pid, u.User, srcIP, 50000+pid%1000)
		case "LL02":
			raw = fmt.Sprintf(tmpl.Raw, pid, u.User)
		case "LL04", "LL05", "SA02", "SA03", "SA08", "SA09":
			raw = fmt.Sprintf(tmpl.Raw, pid, u.User)
		case "CC01":
			raw = fmt.Sprintf(tmpl.Raw, pid, db.PolicyVer)
		case "PA01":
			raw = fmt.Sprintf(tmpl.Raw, pid, u.User, u.User)
		case "PA02":
			raw = fmt.Sprintf(tmpl.Raw, pid, u.User, 1000+pid%100, u.User)
		case "SA01":
			raw = fmt.Sprintf(tmpl.Raw, pid, u.User, 1000+pid%100, 1000+pid%100)
		case "SA04":
			raw = fmt.Sprintf(tmpl.Raw, pid, "db-users", 500+pid%100)
		case "SA05", "SA06":
			raw = fmt.Sprintf(tmpl.Raw, pid, "db-users")
		case "SA07":
			raw = fmt.Sprintf(tmpl.Raw, pid, u.Email)
		case "SS03", "SS04":
			raw = fmt.Sprintf(tmpl.Raw, pid, "users_inventory")
		case "CM02":
			raw = fmt.Sprintf(tmpl.Raw, pid, 85+pid%15)
		case "CM04":
			raw = fmt.Sprintf(tmpl.Raw, pid, 256+pid%256)
		default:
			raw = fmt.Sprintf(tmpl.Raw, pid)
		}

		// Determine user context based on event type
		var logUser, logEmail, logDomain string
		if strings.HasPrefix(tmpl.Code, "LL") || strings.HasPrefix(tmpl.Code, "PA") || strings.HasPrefix(tmpl.Code, "SA") {
			logUser = u.User
			logEmail = u.Email
			logDomain = u.Domain
		} else {
			logUser = "system"
			logEmail = "service@spinovation.com"
			logDomain = "spinovation.local"
		}

		rawLog := fmt.Sprintf("%s %s LegacyTel[%d]: [%s] %s [src_ip=%s dest_ip=%s user=%s email=%s domain=%s]", 
			eventTime.Format("Jan _2 15:04:05"), 
			targetNode.Hostname, 
			pid, 
			tmpl.Code, 
			raw, 
			srcIP, 
			targetNode.IP, 
			logUser, 
			logEmail, 
			logDomain)

		record := &AuditLogRecord{
			Timestamp:   eventTime.Format(time.RFC3339),
			Host:        targetNode.Hostname,
			EventCode:   tmpl.Code,
			Description: tmpl.Desc,
			SourceIP:    srcIP,
			DestIP:      targetNode.IP,
			User:        logUser,
			Email:       logEmail,
			Domain:      logDomain,
			RawLog:      rawLog,
		}
		db.AuditLogs = append(db.AuditLogs, record)
	}
}

// handleRegister registers a new node in the control plane database
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var node AgentNode
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.mu.Lock()
	node.LastHeartbeat = time.Now()
	node.Status = "ACTIVE"
	node.TargetPolicyVersion = db.PolicyVer
	node.CurrentPolicyVersion = 0
	db.Nodes[node.ID] = &node
	db.mu.Unlock()

	log.Printf("[REGISTER] Node '%s' (%s - %s) successfully registered.", node.Hostname, node.OS, node.ID)
	broadcastUpdate(fmt.Sprintf("Registered node %s", node.Hostname))

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "SUCCESS",
		"node_id":        node.ID,
		"policy_version": db.PolicyVer,
	})
}

// handleHeartbeat processes live health updates and returns pending actions
func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var update AgentNode
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.mu.Lock()
	node, exists := db.Nodes[update.ID]
	if exists {
		node.CPUUsage = update.CPUUsage
		node.MemoryUsage = update.MemoryUsage
		node.Throughput = update.Throughput
		node.Version = update.Version
		node.LastHeartbeat = time.Now()
		node.Status = "ACTIVE"
		if update.HypervisorType != "" {
			node.HypervisorType = update.HypervisorType
			node.HypervisorName = update.HypervisorName
		}
		if len(update.AppInventory) > 0 {
			node.AppInventory = update.AppInventory
		}
		if update.Hardware.CPUModel != "" {
			node.Hardware = update.Hardware
		}
		node.CurrentPolicyVersion = update.CurrentPolicyVersion
	} else {
		update.LastHeartbeat = time.Now()
		update.Status = "ACTIVE"
		update.TargetPolicyVersion = db.PolicyVer
		db.Nodes[update.ID] = &update
		node = &update
	}
	db.mu.Unlock()

	db.mu.RLock()
	resp := map[string]interface{}{
		"status":            "OK",
		"policy_version":    db.PolicyVer,
		"policy_config":     db.PolicyConfig,
		"target_version":    node.PendingUpgrade,
		"upgrade_scheduled": node.PendingUpgrade != "",
	}
	db.mu.RUnlock()

	broadcastUpdate(fmt.Sprintf("Heartbeat from %s (CPU: %.1f%%, RAM: %.1f%%)", node.Hostname, node.CPUUsage, node.MemoryUsage))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handlePolicy returns the latest policy config
func handlePolicy(w http.ResponseWriter, r *http.Request) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version": db.PolicyVer,
		"config":  db.PolicyConfig,
	})
}

// handleAdminUpgrade triggers a scheduled upgrade command for a selective host
func handleAdminUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID        string `json:"node_id"`
		TargetVersion string `json:"target_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.mu.Lock()
	node, exists := db.Nodes[req.NodeID]
	if exists {
		node.PendingUpgrade = req.TargetVersion
		node.Status = "UPGRADING"
	}
	db.mu.Unlock()

	if !exists {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	log.Printf("[ADMIN] Scheduled upgrade of Node '%s' to version '%s'", node.Hostname, req.TargetVersion)
	broadcastUpdate(fmt.Sprintf("Scheduled upgrade for %s to %s", node.Hostname, req.TargetVersion))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "UPGRADE_SCHEDULED"})
}

// handleAdminUpgradeAll triggers an upgrade for all hosts in the fleet
func handleAdminUpgradeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetVersion string `json:"target_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.mu.Lock()
	count := 0
	for _, node := range db.Nodes {
		node.PendingUpgrade = req.TargetVersion
		node.Status = "UPGRADING"
		count++
	}
	db.mu.Unlock()

	log.Printf("[ADMIN] Orchestrated bulk upgrade for %d nodes to version '%s'", count, req.TargetVersion)
	broadcastUpdate(fmt.Sprintf("Scheduled bulk upgrade of all %d nodes to %s", count, req.TargetVersion))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "BULK_UPGRADE_SCHEDULED",
		"count":  count,
	})
}

// handleAdminBinaries handles package uploads, duplicate checking, and listing versions
func handleAdminBinaries(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		db.mu.RLock()
		defer db.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(db.Binaries)
		return
	}

	if r.Method == http.MethodPost {
		var req AgentBinary
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		key := req.OS + "/" + req.Arch
		db.mu.Lock()
		list, exists := db.Binaries[key]
		if !exists {
			list = []*AgentBinary{}
		}

		// Duplicate check
		duplicate := false
		for _, b := range list {
			if b.Version == req.Version {
				duplicate = true
				break
			}
		}

		if duplicate {
			db.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"status": "DUPLICATE_VERSION", "message": "Binary version already exists."})
			return
		}

		// Save uploaded version (limit and shift channel pointers if necessary to keep 3 versions)
		req.UploadTime = time.Now()
		req.Checksum = fmt.Sprintf("sha256-u%dp%d", time.Now().Second(), time.Now().Nanosecond()%1000)
		db.Binaries[key] = append(db.Binaries[key], &req)
		db.mu.Unlock()

		log.Printf("[REPOSITORY] Uploaded new package version '%s' for platform '%s/%s'", req.Version, req.OS, req.Arch)
		broadcastUpdate(fmt.Sprintf("New agent binary %s uploaded for %s/%s in Channel: %s", req.Version, req.OS, req.Arch, req.Channel))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "UPLOAD_SUCCESS"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleAdminPolicyUpdate updates the global policy config
func handleAdminPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.mu.Lock()
	db.PolicyVer++
	db.PolicyConfig = req.Config
	db.mu.Unlock()

	log.Printf("[ADMIN] Dynamic Policy updated to Version %d", db.PolicyVer)
	broadcastUpdate(fmt.Sprintf("Global Policy updated to Version %d", db.PolicyVer))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "SUCCESS",
		"version": db.PolicyVer,
	})
}

// handleSSEStream streams events to the control plane dashboard
func handleSSEStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan string, 10)
	db.mu.Lock()
	db.ClientChans[ch] = true
	db.mu.Unlock()

	defer func() {
		db.mu.Lock()
		delete(db.ClientChans, ch)
		db.mu.Unlock()
		close(ch)
	}()

	// Send initial database dump to UI
	db.mu.RLock()
	nodesJSON, _ := json.Marshal(db.Nodes)
	binariesJSON, _ := json.Marshal(db.Binaries)
	logsJSON, _ := json.Marshal(db.AuditLogs)
	fmt.Fprintf(w, "event: init\ndata: {\"nodes\":%s, \"binaries\":%s, \"audit_logs\":%s}\n\n", string(nodesJSON), string(binariesJSON), string(logsJSON))
	flusher.Flush()
	db.mu.RUnlock()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			db.mu.RLock()
			nodesJSON, _ := json.Marshal(db.Nodes)
			binariesJSON, _ := json.Marshal(db.Binaries)
			logsJSON, _ := json.Marshal(db.AuditLogs)
			db.mu.RUnlock()
			fmt.Fprintf(w, "event: update\ndata: {\"log\":\"%s\", \"nodes\":%s, \"binaries\":%s, \"audit_logs\":%s}\n\n", msg, string(nodesJSON), string(binariesJSON), string(logsJSON))
			flusher.Flush()
		}
	}
}

func broadcastUpdate(msg string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	formatted := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	for ch := range db.ClientChans {
		select {
		case ch <- formatted:
		default:
		}
	}
}

// handleDashboard renders the single page fleet manager UI
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, nil)
}

// runMockHeartbeatSimulator populates the UI with simulated nodes for direct evaluation
func runMockHeartbeatSimulator() {
	db.mu.Lock()
	db.Nodes["node-linux-web"] = &AgentNode{
		ID:                  "node-linux-web",
		Hostname:            "prod-linux-nginx-01",
		IP:                  "10.0.10.15",
		OS:                  "linux",
		Version:             "v1.9.8",
		HypervisorType:      "type-1",
		HypervisorName:      "VMware ESXi",
		AppInventory:        []string{"nginx", "postgresql", "docker", "redis"},
		Hardware: HardwareInfo{
			CPUModel:    "Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz",
			CPUCores:    16,
			TotalRAMGB:  64.0,
			TotalDiskGB: 512.0,
			SysModel:    "ProLiant DL360 Gen10",
		},
		CPUUsage:            12.4,
		MemoryUsage:         45.8,
		Throughput:          245.2,
		LastHeartbeat:       time.Now(),
		Status:              "ACTIVE",
		TargetPolicyVersion: 1,
		CurrentPolicyVersion: 1,
	}

	db.Nodes["node-win-ad"] = &AgentNode{
		ID:                  "node-win-ad",
		Hostname:            "corp-win-ad-02",
		IP:                  "10.0.20.44",
		OS:                  "windows",
		Version:             "v1.9.8",
		HypervisorType:      "type-1",
		HypervisorName:      "Microsoft Hyper-V",
		AppInventory:        []string{"ActiveDirectory", "IIS", "DHCP_Server"},
		Hardware: HardwareInfo{
			CPUModel:    "Intel(R) Xeon(R) Platinum 8280 CPU @ 2.70GHz",
			CPUCores:    8,
			TotalRAMGB:  32.0,
			TotalDiskGB: 256.0,
			SysModel:    "PowerEdge R740",
		},
		CPUUsage:            8.7,
		MemoryUsage:         64.2,
		Throughput:          98.5,
		LastHeartbeat:       time.Now(),
		Status:              "ACTIVE",
		TargetPolicyVersion: 1,
		CurrentPolicyVersion: 1,
	}

	db.Nodes["node-mac-dev"] = &AgentNode{
		ID:                  "node-mac-dev",
		Hostname:            "dev-macbook-gs",
		IP:                  "192.168.1.108",
		OS:                  "darwin",
		Version:             "v2.0.0",
		HypervisorType:      "type-2",
		HypervisorName:      "VirtualBox",
		AppInventory:        []string{"vscode", "docker", "go", "node"},
		Hardware: HardwareInfo{
			CPUModel:    "Apple M2 Pro",
			CPUCores:    10,
			TotalRAMGB:  16.0,
			TotalDiskGB: 512.0,
			SysModel:    "Mac14,5",
		},
		CPUUsage:            24.1,
		MemoryUsage:         82.1,
		Throughput:          14.2,
		LastHeartbeat:       time.Now(),
		Status:              "ACTIVE",
		TargetPolicyVersion: 1,
		CurrentPolicyVersion: 1,
	}

	db.Nodes["node-legacy-solaris"] = &AgentNode{
		ID:                  "node-legacy-solaris",
		Hostname:            "legacy-solaris-db",
		IP:                  "192.168.50.12",
		OS:                  "solaris",
		Version:             "v1.0.4-legacy",
		HypervisorType:      "type-1",
		HypervisorName:      "Bare-Metal",
		AppInventory:        []string{"oracle-db-11g", "syslog-daemon", "weblogic"},
		Hardware: HardwareInfo{
			CPUModel:    "SPARC T8-1 @ 5.0GHz",
			CPUCores:    32,
			TotalRAMGB:  128.0,
			TotalDiskGB: 2048.0,
			SysModel:    "SPARC Enterprise",
		},
		CPUUsage:            41.2,
		MemoryUsage:         73.5,
		Throughput:          1205.0,
		LastHeartbeat:       time.Now(),
		Status:              "ACTIVE",
		TargetPolicyVersion: 1,
		CurrentPolicyVersion: 1,
	}

	db.Nodes["node-legacy-aix"] = &AgentNode{
		ID:                  "node-legacy-aix",
		Hostname:            "mainframe-ibm-aix",
		IP:                  "192.168.50.15",
		OS:                  "aix",
		Version:             "v1.1.0-legacy",
		HypervisorType:      "type-1",
		HypervisorName:      "IBM PowerVM",
		AppInventory:        []string{"cobol-billing-app", "db2", "websphere"},
		Hardware: HardwareInfo{
			CPUModel:    "IBM POWER9 @ 3.8GHz",
			CPUCores:    24,
			TotalRAMGB:  256.0,
			TotalDiskGB: 4096.0,
			SysModel:    "Power Systems E950",
		},
		CPUUsage:            68.4,
		MemoryUsage:         89.2,
		Throughput:          432.0,
		LastHeartbeat:       time.Now(),
		Status:              "ACTIVE",
		TargetPolicyVersion: 1,
		CurrentPolicyVersion: 1,
	}

	db.Nodes["node-legacy-tandem"] = &AgentNode{
		ID:                  "node-legacy-tandem",
		Hostname:            "hpe-nonstop-tns",
		IP:                  "192.168.60.40",
		OS:                  "nonstop",
		Version:             "v1.2.0-legacy",
		HypervisorType:      "type-1",
		HypervisorName:      "Bare-Metal",
		AppInventory:        []string{"$ZEMS (EMS)", "TACL Shell", "TMF Coordinator", "Pathway"},
		Hardware: HardwareInfo{
			CPUModel:    "Intel(R) Itanium(R) 9700 @ 2.66GHz",
			CPUCores:    8,
			TotalRAMGB:  64.0,
			TotalDiskGB: 1024.0,
			SysModel:    "HPE NonStop BladeSystem",
		},
		CPUUsage:            28.5,
		MemoryUsage:         52.4,
		Throughput:          150.0,
		LastHeartbeat:       time.Now(),
		Status:              "ACTIVE",
		TargetPolicyVersion: 1,
		CurrentPolicyVersion: 1,
	}
	db.mu.Unlock()

	ticker := time.NewTicker(3 * time.Second)
	for range ticker.C {
		db.mu.Lock()
		for _, node := range db.Nodes {
			// Simulating fluctuating metrics
			node.CPUUsage += float64((time.Now().UnixNano() % 5) - 2)
			if node.CPUUsage < 2 {
				node.CPUUsage = 5.2
			} else if node.CPUUsage > 95 {
				node.CPUUsage = 88.4
			}

			node.MemoryUsage += float64((time.Now().UnixNano() % 3) - 1)
			if node.MemoryUsage < 10 {
				node.MemoryUsage = 24.1
			} else if node.MemoryUsage > 98 {
				node.MemoryUsage = 92.5
			}

			node.Throughput += float64((time.Now().UnixNano() % 11) - 5)
			if node.Throughput < 0 {
				node.Throughput = 15.4
			}

			node.LastHeartbeat = time.Now()
			
			// Resolve upgrade simulation if scheduled
			if node.Status == "UPGRADING" && node.PendingUpgrade != "" {
				node.Version = node.PendingUpgrade
				node.PendingUpgrade = ""
				node.Status = "ACTIVE"
				broadcastUpdate(fmt.Sprintf("[FLEET] Node %s upgrade completed successfully. Status set to ACTIVE.", node.Hostname))
			}
		}
		db.mu.Unlock()

		// Periodic security event simulator (35% chance per tick)
		if time.Now().UnixNano()%100 < 35 {
			db.mu.Lock()
			nodeList := make([]*AgentNode, 0)
			for _, n := range db.Nodes {
				nodeList = append(nodeList, n)
			}
			db.mu.Unlock()

			if len(nodeList) > 0 {
				db.mu.Lock()
				targetNode := nodeList[int(time.Now().UnixNano())%len(nodeList)]
				tmpl := eventTemplates[int(time.Now().UnixNano())%len(eventTemplates)]
				u := mockUsers[int(time.Now().UnixNano())%len(mockUsers)]
				srcIP := mockIPs[int(time.Now().UnixNano())%len(mockIPs)]
				pid := 2000 + int(time.Now().UnixNano())%10000
				
				var raw string
				switch tmpl.Code {
				case "LL01", "LL03":
					raw = fmt.Sprintf(tmpl.Raw, pid, u.User, srcIP, 50000+pid%1000)
				case "LL02":
					raw = fmt.Sprintf(tmpl.Raw, pid, u.User)
				case "LL04", "LL05", "SA02", "SA03", "SA08", "SA09":
					raw = fmt.Sprintf(tmpl.Raw, pid, u.User)
				case "CC01":
					raw = fmt.Sprintf(tmpl.Raw, pid, db.PolicyVer)
				case "PA01":
					raw = fmt.Sprintf(tmpl.Raw, pid, u.User, u.User)
				case "PA02":
					raw = fmt.Sprintf(tmpl.Raw, pid, u.User, 1000+pid%100, u.User)
				case "SA01":
					raw = fmt.Sprintf(tmpl.Raw, pid, u.User, 1000+pid%100, 1000+pid%100)
				case "SA04":
					raw = fmt.Sprintf(tmpl.Raw, pid, "db-users", 500+pid%100)
				case "SA05", "SA06":
					raw = fmt.Sprintf(tmpl.Raw, pid, "db-users")
				case "SA07":
					raw = fmt.Sprintf(tmpl.Raw, pid, u.Email)
				case "SS03", "SS04":
					raw = fmt.Sprintf(tmpl.Raw, pid, "users_inventory")
				case "CM02":
					raw = fmt.Sprintf(tmpl.Raw, pid, 85+pid%15)
				case "CM04":
					raw = fmt.Sprintf(tmpl.Raw, pid, 256+pid%256)
				default:
					raw = fmt.Sprintf(tmpl.Raw, pid)
				}

				// Record security event
				var logUser, logEmail, logDomain string
				if strings.HasPrefix(tmpl.Code, "LL") || strings.HasPrefix(tmpl.Code, "PA") || strings.HasPrefix(tmpl.Code, "SA") {
					logUser = u.User
					logEmail = u.Email
					logDomain = u.Domain
				} else {
					logUser = "system"
					logEmail = "service@spinovation.com"
					logDomain = "spinovation.local"
				}

				rawLog := fmt.Sprintf("%s %s LegacyTel[%d]: [%s] %s [src_ip=%s dest_ip=%s user=%s email=%s domain=%s]", 
					time.Now().Format("Jan _2 15:04:05"), 
					targetNode.Hostname, 
					pid, 
					tmpl.Code, 
					raw, 
					srcIP, 
					targetNode.IP, 
					logUser, 
					logEmail, 
					logDomain)

				record := &AuditLogRecord{
					Timestamp:   time.Now().Format(time.RFC3339),
					Host:        targetNode.Hostname,
					EventCode:   tmpl.Code,
					Description: tmpl.Desc,
					SourceIP:    srcIP,
					DestIP:      targetNode.IP,
					User:        logUser,
					Email:       logEmail,
					Domain:      logDomain,
					RawLog:      rawLog,
				}

				db.AuditLogs = append(db.AuditLogs, record)
				if len(db.AuditLogs) > 100 {
					db.AuditLogs = db.AuditLogs[1:]
				}
				db.mu.Unlock()

				broadcastUpdate(fmt.Sprintf("AUDIT_LOG|%s", record.RawLog))
			}
		}

		broadcastUpdate("Fleet metrics updated successfully.")
	}
}

var mockUsers = []struct {
	User   string
	Email  string
	Domain string
}{
	{"sridhargs", "sridhar@spinovation.com", "spinovation.local"},
	{"admin", "admin@spinovation.com", "spinovation.local"},
	{"ops_lead", "ops@spinovation.com", "spinovation.local"},
	{"db_admin", "db_admin@spinovation.local", "spinovation.local"},
	{"guest_user", "guest@spinovation.com", "spinovation.local"},
}

var mockIPs = []string{
	"192.168.1.50", "192.168.1.108", "10.0.10.15", "10.0.20.44", "192.168.5.12", "192.168.5.15",
}

var eventTemplates = []struct {
	Code string
	Desc string
	Raw  string
}{
	{"LL01", "Successful login", "sshd[%d]: Accepted password for %s from %s port %d ssh2"},
	{"LL02", "Successful logoff", "sshd[%d]: Pam_unix(sshd:session): session closed for user %s"},
	{"LL03", "User login failure", "sshd[%d]: Failed password for invalid user %s from %s port %d ssh2"},
	{"LL04", "Password change success", "passwd[%d]: Pam_unix(passwd:chauthtok): password changed for %s"},
	{"LL05", "Password change failure", "passwd[%d]: Pam_unix(passwd:chauthtok): password change failed for %s"},
	{"CC01", "Application configuration change", "legacytel-worker[%d]: Policy hot-reload initiated. Applied config revision %d"},
	{"CC02", "Security configuration change", "sshd[%d]: Reloading sshd configuration: changes applied dynamically"},
	{"PA01", "Successful privilege operation access", "sudo[%d]: %s : TTY=pts/1 ; PWD=/home/%s ; USER=root ; COMMAND=/usr/bin/systemctl restart legacytel-supervisor"},
	{"PA02", "Failed privileged operation access", "sudo[%d]: %s : pam_unix(sudo:auth): auth failure; logname= uid=%d euid=0 tty=pts/1 ruser= rhost=  user=%s"},
	{"SA01", "User creation", "useradd[%d]: New user created: name=%s, uid=%d, gid=%d"},
	{"SA02", "User change", "usermod[%d]: User parameters modified: name=%s"},
	{"SA03", "User deletion", "userdel[%d]: User account removed: name=%s"},
	{"SA04", "User profile/role creation", "groupadd[%d]: New security group added: name=%s, gid=%d"},
	{"SA05", "User profile/role change", "groupmod[%d]: Security group modified: name=%s"},
	{"SA06", "User profile/role deletion", "groupdel[%d]: Security group deleted: name=%s"},
	{"SA07", "User password reset", "admin-tools[%d]: Administrative password reset executed for %s by admin@spinovation.com"},
	{"SA08", "User account locked", "pam_tally2[%d]: User %s locked due to excessive authentication failures"},
	{"SA09", "User account unlocked", "pam_tally2[%d]: User %s manually unlocked by system administrator"},
	{"SS01", "Application started", "systemd[%d]: Started LegacyTel Active OTel Log Collector Worker."},
	{"SS02", "Application stopped", "systemd[%d]: Stopped LegacyTel Active OTel Log Collector Worker."},
	{"SS03", "Application data dump", "postgres[%d]: Database backup dump successfully completed for table %s"},
	{"SS04", "Application data restore", "postgres[%d]: Database restore successfully completed for table %s"},
	{"SS05", "Application logging change", "legacytel-worker[%d]: Logging level dynamically set to DEBUG by supervisor policy"},
	{"CM01", "Sequencing failure", "legacytel-worker[%d]: Event sequence mismatch detected in stream ingestion pipeline"},
	{"CM02", "Utilization threshold reached", "legacytel-worker[%d]: CPU utilization alert: active threadpool core usage at %d%%"},
	{"CM03", "Application code change", "supervisor[%d]: Swapping worker active process with compiled code release"},
	{"CM04", "Application memory change", "legacytel-worker[%d]: Dynamic memory allocation bounds modified to %d MB"},
}

// Stunning Single-Page Glassmorphic HTML Template for Central Control Plane Console
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LegacyTel Central Control Plane</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0c10;
            --card-bg: rgba(22, 26, 44, 0.55);
            --border-glow: rgba(0, 242, 254, 0.2);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-teal: #00f2fe;
            --accent-gold: #ffb703;
            --accent-orange: #ff5e62;
            --accent-green: #4ade80;
            --accent-bronze: #e28743;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            background-image: 
                radial-gradient(at 10% 20%, rgba(123, 44, 191, 0.15) 0px, transparent 50%),
                radial-gradient(at 90% 80%, rgba(0, 242, 254, 0.1) 0px, transparent 50%),
                radial-gradient(at 50% 50%, rgba(226, 135, 67, 0.05) 0px, transparent 50%);
            background-attachment: fixed;
            min-height: 100vh;
            padding: 30px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            background: rgba(20, 24, 46, 0.65);
            border: 1px solid var(--border-glow);
            padding: 20px 30px;
            border-radius: 20px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        h1 {
            font-weight: 700;
            font-size: 26px;
            background: linear-gradient(to right, #00f2fe, #4facfe, #ffb703);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .subtitle {
            font-size: 14px;
            color: var(--text-muted);
            margin-top: 4px;
        }

        .stats-strip {
            display: flex;
            gap: 15px;
        }

        .stat-badge {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 8px 16px;
            border-radius: 12px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .stat-badge span {
            font-weight: 700;
            color: var(--accent-teal);
        }

        main {
            display: grid;
            grid-template-columns: 2fr 1.2fr;
            gap: 30px;
        }

        .panel {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border-glow);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            margin-bottom: 30px;
        }

        .panel-title {
            font-weight: 600;
            font-size: 18px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 12px;
        }

        /* SVG Map Pulsing Neon glows on searched nodes */
        @keyframes neon-pulse-teal {
            0% { filter: drop-shadow(0 0 2px var(--accent-teal)); stroke-width: 2px; }
            50% { filter: drop-shadow(0 0 12px var(--accent-teal)); stroke-width: 4px; }
            100% { filter: drop-shadow(0 0 2px var(--accent-teal)); stroke-width: 2px; }
        }

        @keyframes neon-pulse-bronze {
            0% { filter: drop-shadow(0 0 2px var(--accent-bronze)); stroke-width: 2px; }
            50% { filter: drop-shadow(0 0 12px var(--accent-bronze)); stroke-width: 4px; }
            100% { filter: drop-shadow(0 0 2px var(--accent-bronze)); stroke-width: 2px; }
        }

        .topology-container {
            width: 100%;
            height: 380px;
            background: rgba(0, 0, 0, 0.4);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.04);
            position: relative;
            overflow: hidden;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .topology-svg {
            width: 100%;
            height: 100%;
        }

        /* Custom OS Grid tabs */
        .tabs-nav {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding-bottom: 10px;
        }

        .tab-btn {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: var(--text-muted);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .tab-btn:hover {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-main);
        }

        .tab-btn.active {
            background: linear-gradient(135deg, rgba(0, 242, 254, 0.15) 0%, rgba(79, 172, 254, 0.15) 100%);
            border-color: var(--accent-teal);
            color: var(--accent-teal);
            box-shadow: 0 0 10px rgba(0, 242, 254, 0.15);
        }

        .node-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
        }

        .node-card {
            background: rgba(255, 255, 255, 0.01);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 16px;
            padding: 20px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .node-card:hover {
            transform: translateY(-2px);
            border-color: var(--accent-teal);
            box-shadow: 0 8px 24px rgba(0, 242, 254, 0.08);
        }

        .node-card.legacy-card {
            border-color: rgba(226, 135, 67, 0.18);
            background: rgba(30, 24, 20, 0.15);
        }

        .node-card.legacy-card:hover {
            border-color: var(--accent-bronze);
            box-shadow: 0 8px 24px rgba(226, 135, 67, 0.12);
        }

        .node-card.upgrading {
            border-color: var(--accent-gold);
            animation: pulse-border 1.5s infinite;
        }

        @keyframes pulse-border {
            0% { border-color: rgba(255, 183, 3, 0.3); }
            50% { border-color: rgba(255, 183, 3, 1); }
            100% { border-color: rgba(255, 183, 3, 0.3); }
        }

        .node-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .node-meta {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .node-title {
            font-weight: 700;
            font-size: 17px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .node-os {
            text-transform: uppercase;
            font-size: 11px;
            background: rgba(255, 255, 255, 0.08);
            padding: 2px 8px;
            border-radius: 6px;
            font-weight: 600;
            color: var(--text-muted);
        }

        .node-ver {
            font-size: 12px;
            color: var(--accent-teal);
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0, 242, 254, 0.08);
            padding: 2px 8px;
            border-radius: 6px;
        }

        .node-ver.legacy-ver {
            color: var(--accent-bronze);
            background: rgba(226, 135, 67, 0.08);
        }

        .node-metrics {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 15px;
        }

        .metric-item {
            background: rgba(0, 0, 0, 0.2);
            padding: 10px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }

        .metric-lbl {
            font-size: 11px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }

        .metric-val {
            font-size: 16px;
            font-weight: 700;
            color: var(--text-main);
        }

        .node-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-top: 1px solid rgba(255, 255, 255, 0.04);
            padding-top: 12px;
        }

        .hypervisor-tag {
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--accent-gold);
            font-weight: 600;
        }

        .hypervisor-tag.type-2 {
            color: var(--accent-teal);
        }

        .hypervisor-tag.legacy-tag {
            color: var(--accent-bronze);
        }

        .card-actions {
            display: flex;
            gap: 8px;
        }

        button {
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            border: none;
            color: #0d0e15;
            padding: 6px 14px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }

        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 242, 254, 0.3);
        }

        button.btn-sec {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-main);
        }

        button.btn-sec:hover {
            background: rgba(255, 255, 255, 0.15);
            box-shadow: none;
        }

        .console-log {
            background: #05060b;
            border: 1px solid rgba(0, 242, 254, 0.15);
            border-radius: 12px;
            padding: 15px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            height: 200px;
            overflow-y: auto;
            color: var(--accent-teal);
        }

        .log-entry {
            margin-bottom: 6px;
            line-height: 1.4;
            border-left: 2px solid var(--accent-teal);
            padding-left: 8px;
        }

        .inventory-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 10px;
        }

        .inventory-tag {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.08);
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 6px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }

        .repo-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            padding: 15px;
        }

        #repo-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }

        .repo-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
            margin-bottom: 8px;
            padding-bottom: 6px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }

        .repo-row span.channel {
            text-transform: uppercase;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 700;
        }

        .channel.stable { background: rgba(74, 222, 128, 0.15); color: var(--accent-green); }
        .channel.previous { background: rgba(148, 163, 184, 0.15); color: var(--text-muted); }
        .channel.beta { background: rgba(255, 183, 3, 0.15); color: var(--accent-gold); }

        /* Fullscreen Inventory Table Modal */
        .fullscreen-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(8, 9, 15, 0.94);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            z-index: 2000;
            justify-content: center;
            align-items: center;
            padding: 40px;
        }

        .fullscreen-content {
            background: #111425;
            border: 1px solid rgba(0, 242, 254, 0.35);
            border-radius: 24px;
            width: 100%;
            max-width: 1200px;
            height: 90%;
            display: flex;
            flex-direction: column;
            padding: 30px;
            box-shadow: 0 15px 45px rgba(0, 0, 0, 0.6);
        }

        .fullscreen-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 15px;
        }

        .table-wrapper {
            flex: 1;
            overflow-y: auto;
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            background: rgba(0, 0, 0, 0.2);
        }

        .inventory-table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }

        .inventory-table th {
            background: rgba(22, 26, 44, 0.95);
            color: var(--accent-teal);
            font-weight: 700;
            padding: 14px 16px;
            border-bottom: 2px solid rgba(0, 242, 254, 0.2);
            position: sticky;
            top: 0;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }

        .inventory-table th:hover {
            background: rgba(30, 35, 58, 0.9);
        }

        .inventory-table th .sort-icon {
            margin-left: 6px;
            font-size: 11px;
        }

        .inventory-table td {
            padding: 12px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            color: var(--text-main);
        }

        .inventory-table tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }

        /* Modal styling */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .modal-content {
            background: #14182e;
            border: 1px solid var(--accent-teal);
            border-radius: 20px;
            padding: 30px;
            width: 500px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
        }

        .modal-header {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            padding-bottom: 10px;
        }

        textarea {
            width: 100%;
            height: 180px;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            color: #fff;
            font-family: 'JetBrains Mono', monospace;
            padding: 10px;
            margin-bottom: 20px;
            resize: none;
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }

        .input-group {
            margin-bottom: 15px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .input-group label {
            font-size: 13px;
            color: var(--text-muted);
        }

        .input-group input, .input-group select {
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 10px;
            border-radius: 8px;
            color: #fff;
            font-family: inherit;
        }

        .flex-row {
            display: flex;
            gap: 15px;
        }

        /* Beautiful progress meter blocks */
        .progress-container {
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            height: 8px;
            overflow: hidden;
            margin-top: 6px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .progress-bar {
            height: 100%;
            border-radius: 8px;
            transition: width 0.4s ease;
        }
        .progress-bar.teal { background: linear-gradient(90deg, #00f2fe, #4facfe); }
        .progress-bar.gold { background: linear-gradient(90deg, #ffb703, #fb8500); }
        .progress-bar.orange { background: linear-gradient(90deg, #ff5e62, #ff9966); }
        .progress-bar.bronze { background: linear-gradient(90deg, #e28743, #c86b29); }

        .inspector-metric-card {
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 12px;
            padding: 12px 15px;
            margin-bottom: 12px;
        }

        .aggregate-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-top: 15px;
        }

        .aggregate-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 10px;
            text-align: center;
        }
        
        .aggregate-val {
            font-size: 18px;
            font-weight: 700;
            color: var(--accent-teal);
            margin-top: 4px;
        }
    </style>
</head>
<body>

    <header>
        <div>
            <h1>🛰️ LegacyTel Central</h1>
            <div class="subtitle">Unified Observability Control Plane & Dynamic Fleet Database</div>
        </div>
        <div class="stats-strip">
            <div class="stat-badge">Active Nodes: <span id="stat-active">0</span></div>
            <div class="stat-badge">Upgrading: <span id="stat-upgrading">0</span></div>
            <div class="stat-badge">Global Policy Version: <span id="stat-policy">1</span></div>
        </div>
    </header>

    <!-- Global OS Platforms Selection Tabs Panel -->
    <div class="panel" style="margin-bottom: 25px; padding: 15px 25px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px;">
            <div style="font-weight: 700; font-size: 15px; color: var(--accent-teal); display: flex; align-items: center; gap: 8px;">
                🖥️ Active Fleet OS Filter Group
            </div>
            <div class="tabs-nav" id="fleet-tabs" style="border-bottom: none; padding-bottom: 0; margin-bottom: 0; display: flex; gap: 10px;">
                <button class="tab-btn active" onclick="setPlatformFilter('all')">🌐 All Systems</button>
                <button class="tab-btn" onclick="setPlatformFilter('legacy')">🏛️ Legacy (v1)</button>
                <button class="tab-btn" onclick="setPlatformFilter('linux')">🐧 Linux (v2)</button>
                <button class="tab-btn" onclick="setPlatformFilter('windows')">🪟 Windows (v2)</button>
                <button class="tab-btn" onclick="setPlatformFilter('darwin')">🍎 macOS (v2)</button>
            </div>
        </div>
    </div>

    <main>
        <!-- Hub & Spoke Topology Visualizer - Full-Width Landscape -->
        <div class="panel" style="grid-column: span 2;">
            <div class="panel-title" style="flex-wrap: wrap; gap: 15px;">
                <span>🕸️ Fleet Network Topology Map (Landscape)</span>
                <div style="display: flex; gap: 8px; align-items: center; margin-left: auto;">
                    <input type="text" id="node-search" placeholder="🔍 Search Hostname, IP, Software..." onkeydown="if(event.key==='Enter') executeSearch()" style="background: rgba(0,0,0,0.3); color:#fff; border:1px solid var(--accent-teal); padding: 6px 12px; border-radius: 8px; font-size:13px; width:220px; outline:none; transition: all 0.2s;" />
                    <button onclick="executeSearch()">Search</button>
                    <button class="btn-sec" onclick="resetSearch()">Reset</button>
                    <button class="btn-sec" onclick="triggerBulkUpgrade()" style="margin-left: 5px;">🚀 Bulk Upgrade v2 Fleet</button>
                </div>
            </div>
            <div class="topology-container" style="height: 320px;">
                <svg class="topology-svg" id="topology-map">
                    <!-- Dynamic Hub & Spokes rendered inside script -->
                </svg>
            </div>
        </div>

        <!-- Left Column: Agent Grid -->
        <div>
            <div class="panel">
                <div class="panel-title" style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 12px; margin-bottom: 20px;">
                    <span>🖥️ Registered Agent Fleet</span>
                    <div style="display: flex; gap: 8px; margin-left: auto;">
                        <button class="btn-sec" onclick="openHardwareTableModal()">📋 Fleet Asset Database</button>
                        <button onclick="openPolicyModal()">⚙️ Global Policy Manager</button>
                    </div>
                </div>
                <div class="node-grid" id="node-container">
                    <!-- Nodes dynamically injected here -->
                </div>
            </div>
        </div>

        <!-- Right Column: Inspector & Event Logs -->
        <div style="display: flex; flex-direction: column; gap: 30px;">
            <!-- Real-time Terminal Log -->
            <div class="panel">
                <div class="panel-title">📡 Real-Time Central Event Stream</div>
                <div class="console-log" id="console-stream">
                    <!-- Event logs dynamically injected -->
                </div>
            </div>

            <!-- Drill-down Inspector Drawer with tabs -->
            <div class="panel" id="inspector-panel">
                <div class="panel-title" style="flex-direction: column; align-items: flex-start; gap: 15px; border-bottom: none; padding-bottom: 0;">
                    <span>🔍 Central Asset & Inventory Inspector</span>
                    <div class="tabs-nav" style="width: 100%; margin-bottom: 0; padding-bottom: 5px;">
                        <button class="tab-btn active" id="inspector-tab-software" onclick="setInspectorTab('software')">📂 Software</button>
                        <button class="tab-btn" id="inspector-tab-hardware" onclick="setInspectorTab('hardware')">💻 Specs</button>
                        <button class="tab-btn" id="inspector-tab-aggregates" onclick="setInspectorTab('aggregates')">📊 Fleet Summary</button>
                    </div>
                </div>
                <div id="central-inventory" style="color: var(--text-muted); font-size: 14px; margin-top: 15px;">
                    Select a node card or map spoke to load real-time database details.
                </div>
            </div>
        </div>

        <!-- Full-Width Bottom Section: Central Binary Repository -->
        <div class="panel" style="grid-column: span 2; margin-top: 10px;">
            <div class="panel-title" style="flex-wrap: wrap; gap: 15px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 12px; margin-bottom: 20px;">
                <span>📦 Central Binary Repository</span>
                <button onclick="openUploadModal()" style="margin-left: auto;">➕ Upload New Package</button>
            </div>
            <div id="repo-container">
                <!-- Binaries (N, n-1, Beta) rendered here side-by-side -->
            </div>
        </div>

    <!-- Live Enterprise Security Log Auditor Panel -->
    <div class="panel" style="grid-column: span 2; margin-top: 10px;">
        <div class="panel-title" style="flex-wrap: wrap; gap: 15px;">
            <span style="color: var(--accent-orange); display: flex; align-items: center; gap: 8px;">🛡️ Live Enterprise Security Log Auditor</span>
            <div style="display: flex; gap: 8px; align-items: center; margin-left: auto;">
                <input type="text" id="log-auditor-search" placeholder="🔍 Filter Code, User, IP, Domain..." oninput="applyLogSearchFilter()" style="background: rgba(0,0,0,0.3); color:#fff; border:1px solid var(--accent-orange); padding: 6px 12px; border-radius: 8px; font-size:13px; width:280px; outline:none; transition: all 0.2s;" />
                <button class="btn-sec" onclick="clearLogAuditorFilter()">Reset Filters</button>
                <button onclick="exportSecurityCSVData()" style="background: linear-gradient(135deg, #ff5e62 0%, #ff9966 100%); color: #0d0e15;">📤 Export Security CSV</button>
            </div>
        </div>
        <div class="table-wrapper" style="max-height: 300px; overflow-y: auto;">
            <table class="inventory-table" style="font-size: 12px;">
                <thead>
                    <tr>
                        <th style="width: 140px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Timestamp</th>
                        <th style="width: 120px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Host</th>
                        <th style="width: 80px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Code</th>
                        <th style="width: 180px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Event Description</th>
                        <th style="width: 100px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Source IP</th>
                        <th style="width: 100px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Dest IP</th>
                        <th style="width: 200px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">User / Email</th>
                        <th style="width: 120px; border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Domain</th>
                        <th style="border-bottom-color: var(--accent-orange); color: var(--accent-orange);">Raw Syslog Message</th>
                    </tr>
                </thead>
                <tbody id="log-auditor-body">
                    <!-- Dynamic log entries injected here -->
                </tbody>
            </table>
        </div>
    </div>

    <!-- Fullscreen Inventory Table Modal -->
    <div class="fullscreen-modal" id="hardware-table-modal">
        <div class="fullscreen-content">
            <div class="fullscreen-header">
                <div>
                    <h2 style="font-weight: 700; color: var(--accent-teal); display: flex; align-items: center; gap: 8px;">📋 LegacyTel Central Fleet Inventory Database</h2>
                    <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Comprehensive tabular hardware spreadsheet and package index</div>
                </div>
                <div style="display: flex; gap: 12px; align-items: center;">
                    <input type="text" id="modal-table-search" placeholder="🔍 Filter hosts, CPU, model..." oninput="filterModalTable()" style="background: rgba(0,0,0,0.3); color:#fff; border:1px solid var(--accent-teal); padding: 8px 14px; border-radius: 8px; font-size:13px; width:260px; outline:none; transition: all 0.2s;" />
                    <button onclick="exportCSVData()">📤 Export CSV Report</button>
                    <button class="btn-sec" onclick="closeHardwareTableModal()">Close Window</button>
                </div>
            </div>
            <div class="table-wrapper">
                <table class="inventory-table">
                    <thead>
                        <tr>
                            <th onclick="sortModalTable(0)">Hostname <span id="sort-icon-0" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(1)">IP Address <span id="sort-icon-1" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(2)">Agent Protocol <span id="sort-icon-2" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(3)">Operating System <span id="sort-icon-3" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(4)">System Model <span id="sort-icon-4" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(5)">CPU Brand Model <span id="sort-icon-5" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(6)">Cores <span id="sort-icon-6" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(7)">Memory <span id="sort-icon-7" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(8)">Storage <span id="sort-icon-8" class="sort-icon">⇅</span></th>
                            <th onclick="sortModalTable(9)">Hypervisor / Host <span id="sort-icon-9" class="sort-icon">⇅</span></th>
                        </tr>
                    </thead>
                    <tbody id="modal-table-body">
                        <!-- Spreadsheet rows injected here -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Global Policy Modal -->
    <div class="modal" id="policy-modal">
        <div class="modal-content">
            <div class="modal-header">Global Policy Configuration</div>
            <textarea id="policy-text">receivers:
  syslog:
    port: 514
  otlp:
    port: 4317
exporters:
  splunk_hec:
    enabled: true
    index: "security_fleet"</textarea>
            <div class="modal-footer">
                <button class="btn-sec" onclick="closePolicyModal()">Cancel</button>
                <button onclick="savePolicyConfig()">Save & Deploy Policy</button>
            </div>
        </div>
    </div>

    <!-- Binary Package Upload Modal -->
    <div class="modal" id="upload-modal">
        <div class="modal-content">
            <div class="modal-header">Upload Latest Agent Binary Package</div>
            <div class="flex-row">
                <div class="input-group" style="flex: 1;">
                    <label>Target OS</label>
                    <select id="upload-os">
                        <option value="linux">Linux</option>
                        <option value="windows">Windows</option>
                        <option value="darwin">macOS (Darwin)</option>
                    </select>
                </div>
                <div class="input-group" style="flex: 1;">
                    <label>Architecture</label>
                    <select id="upload-arch">
                        <option value="amd64">x86_64 (amd64)</option>
                        <option value="arm64">Apple Silicon / ARM (arm64)</option>
                    </select>
                </div>
            </div>
            <div class="flex-row">
                <div class="input-group" style="flex: 1;">
                    <label>Package Version</label>
                    <input type="text" id="upload-version" placeholder="e.g. v2.0.2">
                </div>
                <div class="input-group" style="flex: 1;">
                    <label>Upgrade Channel</label>
                    <select id="upload-channel">
                        <option value="stable">N (Latest Stable)</option>
                        <option value="previous">N-1 (Previous Stable)</option>
                        <option value="beta">Beta (Testing Branch)</option>
                    </select>
                </div>
            </div>
            <div style="color: var(--accent-orange); font-size: 12px; margin-bottom: 15px;" id="upload-error"></div>
            <div class="modal-footer">
                <button class="btn-sec" onclick="closeUploadModal()">Cancel</button>
                <button onclick="submitPackageUpload()">Verify & Upload Binary</button>
            </div>
        </div>
    </div>

    <script>
        let nodesData = {};
        let repoData = {};
        let auditLogsData = [];
        let currentPlatformFilter = 'all';
        let currentInspectorTab = 'software';
        let selectedNodeId = null;
        let highlightedNodeId = null;

        // Modal database sort states
        let sortedColumn = -1;
        let sortAscending = true;

        // Establish real-time SSE link with Control Plane
        const source = new EventSource('/api/v1/stream');

        source.addEventListener('init', function(e) {
            const data = JSON.parse(e.data);
            nodesData = data.nodes;
            repoData = data.binaries;
            if (data.audit_logs) {
                auditLogsData = data.audit_logs;
            }
            renderNodes();
            renderRepository();
            renderTopologyMap();
            updateInspector();
            renderSecurityLogs();
        });

        source.addEventListener('update', function(e) {
            const payload = JSON.parse(e.data);
            nodesData = payload.nodes;
            repoData = payload.binaries;
            if (payload.audit_logs) {
                auditLogsData = payload.audit_logs;
            }
            
            // Ingest log stream
            const stream = document.getElementById('console-stream');
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            
            if (payload.log.startsWith("AUDIT_LOG|")) {
                entry.style.color = "var(--accent-gold)";
                entry.style.borderLeftColor = "var(--accent-gold)";
                entry.textContent = payload.log.substring(10);
            } else {
                entry.textContent = payload.log;
            }
            
            stream.appendChild(entry);
            stream.scrollTop = stream.scrollHeight;

            renderNodes();
            renderRepository();
            renderTopologyMap();
            updateInspector();
            renderSecurityLogs();
        });

        // Helper to identify legacy v1 agents
        function isLegacyNode(node) {
            return node.version.includes('legacy') || node.os === 'solaris' || node.os === 'aix';
        }

        // Live dynamic Security Logs table generator
        function renderSecurityLogs() {
            const body = document.getElementById('log-auditor-body');
            if (!body) return;
            body.innerHTML = '';

            const query = document.getElementById('log-auditor-search') ? document.getElementById('log-auditor-search').value.toLowerCase().trim() : '';

            // Render in reverse chronological order (newest first)
            const reversedLogs = [...auditLogsData].reverse();

            reversedLogs.forEach(log => {
                const matchesSearch = !query || 
                                     log.event_code.toLowerCase().includes(query) ||
                                     log.description.toLowerCase().includes(query) ||
                                     log.host.toLowerCase().includes(query) ||
                                     log.source_ip.includes(query) ||
                                     log.dest_ip.includes(query) ||
                                     log.user.toLowerCase().includes(query) ||
                                     log.email.toLowerCase().includes(query) ||
                                     log.domain.toLowerCase().includes(query) ||
                                     log.raw_log.toLowerCase().includes(query);

                if (!matchesSearch) return;

                const tr = document.createElement('tr');
                
                // Color codes dynamically
                let codeColor = 'var(--text-main)';
                let bgStyle = '';
                if (log.event_code.startsWith('LL')) {
                    if (log.event_code === 'LL03' || log.event_code === 'LL05') {
                        codeColor = 'var(--accent-orange)';
                        bgStyle = 'background: rgba(255, 94, 98, 0.04);';
                    } else {
                        codeColor = 'var(--accent-green)';
                    }
                } else if (log.event_code.startsWith('PA')) {
                    codeColor = log.event_code === 'PA01' ? 'var(--accent-green)' : 'var(--accent-orange)';
                    if (log.event_code === 'PA02') bgStyle = 'background: rgba(255, 94, 98, 0.04);';
                } else if (log.event_code.startsWith('SA')) {
                    codeColor = 'var(--accent-gold)';
                } else if (log.event_code.startsWith('CM')) {
                    codeColor = 'var(--accent-bronze)';
                } else if (log.event_code.startsWith('SS')) {
                    codeColor = 'var(--accent-teal)';
                }

                // Format timestamp nicely
                const ts = log.timestamp.substring(11, 19);

                tr.innerHTML = 
                    '<td style="font-family: \'JetBrains Mono\', monospace; ' + bgStyle + '">' + log.timestamp.substring(0, 10) + ' ' + ts + '</td>' +
                    '<td style="' + bgStyle + '"><strong>' + log.host + '</strong></td>' +
                    '<td style="font-family: \'JetBrains Mono\', monospace; font-weight:700; color:' + codeColor + '; ' + bgStyle + '">' + log.event_code + '</td>' +
                    '<td style="' + bgStyle + '">' + log.description + '</td>' +
                    '<td style="font-family: \'JetBrains Mono\', monospace; ' + bgStyle + '">' + log.source_ip + '</td>' +
                    '<td style="font-family: \'JetBrains Mono\', monospace; ' + bgStyle + '">' + log.dest_ip + '</td>' +
                    '<td style="' + bgStyle + '">' + log.user + ' <span style="font-size:10px; color:var(--text-muted);">(' + log.email + ')</span></td>' +
                    '<td style="color:var(--text-muted); ' + bgStyle + '">' + log.domain + '</td>' +
                    '<td style="font-family: \'JetBrains Mono\', monospace; font-size:11px; color:var(--text-muted); max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; ' + bgStyle + '" title="' + log.raw_log + '">' + log.raw_log + '</td>';

                body.appendChild(tr);
            });
        }

        function applyLogSearchFilter() {
            renderSecurityLogs();
        }

        function clearLogAuditorFilter() {
            document.getElementById('log-auditor-search').value = '';
            renderSecurityLogs();
        }

        // Segment selector tabs controller
        function setPlatformFilter(filter) {
            currentPlatformFilter = filter;
            
            // Update active states
            const buttons = document.querySelectorAll('#fleet-tabs .tab-btn');
            buttons.forEach(btn => {
                btn.classList.remove('active');
                if (filter === 'all' && btn.textContent.includes('All')) btn.classList.add('active');
                if (filter === 'legacy' && btn.textContent.includes('Legacy')) btn.classList.add('active');
                if (filter === 'linux' && btn.textContent.includes('Linux')) btn.classList.add('active');
                if (filter === 'windows' && btn.textContent.includes('Windows')) btn.classList.add('active');
                if (filter === 'darwin' && btn.textContent.includes('macOS')) btn.classList.add('active');
            });

            renderNodes();
            renderTopologyMap();
        }

        function renderNodes() {
            const container = document.getElementById('node-container');
            container.innerHTML = '';

            let activeCount = 0;
            let upgradingCount = 0;

            const searchQuery = document.getElementById('node-search') ? document.getElementById('node-search').value.toLowerCase().trim() : '';

            Object.values(nodesData).forEach(node => {
                const isLegacy = isLegacyNode(node);
                
                // 1. Grid category filters
                if (currentPlatformFilter !== 'all') {
                    if (currentPlatformFilter === 'legacy' && !isLegacy) return;
                    if (currentPlatformFilter === 'linux' && (node.os !== 'linux' || isLegacy)) return;
                    if (currentPlatformFilter === 'windows' && (node.os !== 'windows' || isLegacy)) return;
                    if (currentPlatformFilter === 'darwin' && (node.os !== 'darwin' || isLegacy)) return;
                }

                // 2. Search query matches
                if (searchQuery) {
                    const matchesBasic = node.hostname.toLowerCase().includes(searchQuery) || 
                                         node.IP.includes(searchQuery) || 
                                         node.os.toLowerCase().includes(searchQuery);
                    const matchesApps = node.app_inventory.some(app => app.toLowerCase().includes(searchQuery));
                    const matchesHw = (node.hardware && node.hardware.cpu_model.toLowerCase().includes(searchQuery)) || 
                                       (node.hardware && node.hardware.sys_model.toLowerCase().includes(searchQuery));
                    if (!matchesBasic && !matchesApps && !matchesHw) {
                        return;
                    }
                }

                if (node.status === 'ACTIVE') activeCount++;
                if (node.status === 'UPGRADING') upgradingCount++;

                const card = document.createElement('div');
                card.id = 'card-' + node.id;
                
                let cardClasses = 'node-card ';
                if (node.status === 'UPGRADING') cardClasses += 'upgrading';
                else if (isLegacy) cardClasses += 'legacy-card';
                
                card.className = cardClasses;
                
                const isType1 = node.hypervisor_type === 'type-1';
                const hvClass = isLegacy ? 'legacy-tag' : (isType1 ? 'type-1' : 'type-2');
                const hvLabel = isLegacy ? 'Bare-Metal Mainframe' : (isType1 ? 'Type 1 (Bare-Metal)' : 'Type 2 (Hosted)');

                // Render dynamic actions
                let actionHTML = '';
                if (isLegacy) {
                    actionHTML = '<span style="font-size: 11px; font-weight:700; color: var(--accent-bronze); background: rgba(226, 135, 67, 0.12); padding: 4px 10px; border-radius: 6px; border: 1px solid rgba(226, 135, 67, 0.25);">🏛️ Monolithic Agent (v1)</span>';
                } else {
                    const osKey = node.os + '/amd64';
                    let selectOptions = '';
                    if (repoData[osKey]) {
                        repoData[osKey].forEach(binary => {
                            const channelLabel = binary.channel === 'stable' ? 'N' : (binary.channel === 'previous' ? 'N-1' : 'Beta');
                            selectOptions += '<option value="' + binary.version + '">' + binary.version + ' (' + channelLabel + ')</option>';
                        });
                    }
                    actionHTML = 
                        '<select id="select-' + node.id + '" style="background: rgba(0,0,0,0.3); color:#fff; border:1px solid rgba(255,255,255,0.15); padding: 4px; border-radius: 6px; font-size:11px; outline:none; cursor:pointer;">' +
                            selectOptions +
                        '</select>' +
                        '<button onclick="triggerUpgrade(\'' + node.id + '\')">Upgrade</button>';
                }

                const verClass = 'node-ver ' + (isLegacy ? 'legacy-ver' : '');
                const agentLabel = isLegacy ? 'LegacyTel v1 (Monolithic)' : 'LegacyTel v2 (OTel)';

                card.innerHTML = 
                    '<div class="node-header" style="cursor: pointer;" onclick="inspectInventory(\'' + node.id + '\')">' +
                        '<div class="node-meta">' +
                            '<div class="node-title">' +
                                '<span>' + node.hostname + '</span>' +
                                '<span class="node-os">' + node.os + '</span>' +
                            '</div>' +
                            '<div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">IP Address: <strong>' + node.IP + '</strong></div>' +
                        '</div>' +
                        '<div style="display:flex; flex-direction:column; align-items:flex-end; gap:4px;">' +
                            '<span class="' + verClass + '">' + node.version + '</span>' +
                            '<span style="font-size:9px; color:var(--text-muted);">' + agentLabel + '</span>' +
                        '</div>' +
                    '</div>' +

                    '<div class="node-metrics" style="cursor: pointer;" onclick="inspectInventory(\'' + node.id + '\')">' +
                        '<div class="metric-item">' +
                            '<div class="metric-lbl">CPU Usage</div>' +
                            '<div class="metric-val">' + node.cpu_usage.toFixed(1) + '%</div>' +
                        '</div>' +
                        '<div class="metric-item">' +
                            '<div class="metric-lbl">RAM Usage</div>' +
                            '<div class="metric-val">' + node.memory_usage.toFixed(1) + '%</div>' +
                        '</div>' +
                        '<div class="metric-item">' +
                            '<div class="metric-lbl">Throughput</div>' +
                            '<div class="metric-val">' + node.throughput.toFixed(1) + ' EPS</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="node-footer">' +
                        '<span class="hypervisor-tag ' + hvClass + '">' +
                            '🛡️ ' + node.hypervisor_name + ' [' + hvLabel + ']' +
                        '</span>' +
                        '<div class="card-actions" style="align-items: center; gap: 8px;">' +
                            actionHTML +
                        '</div>' +
                    '</div>';
                container.appendChild(card);
            });

            document.getElementById('stat-active').textContent = activeCount;
            document.getElementById('stat-upgrading').textContent = upgradingCount;
        }

        function renderRepository() {
            const container = document.getElementById('repo-container');
            container.innerHTML = '';

            Object.keys(repoData).forEach(platformKey => {
                const card = document.createElement('div');
                card.className = 'repo-card';
                card.innerHTML = '<div style="font-weight: 700; font-size:14px; margin-bottom:10px; color:var(--accent-teal);">🖥️ ' + platformKey.toUpperCase() + '</div>';

                repoData[platformKey].forEach(binary => {
                    const chClass = binary.channel === 'stable' ? 'stable' : (binary.channel === 'previous' ? 'previous' : 'beta');
                    const chLabel = binary.channel === 'stable' ? 'N (Latest)' : (binary.channel === 'previous' ? 'N-1 (Stable)' : 'Beta (Testing)');

                    card.innerHTML += 
                        '<div class="repo-row">' +
                            '<span><strong>' + binary.version + '</strong></span>' +
                            '<span class="channel ' + chClass + '">' + chLabel + '</span>' +
                        '</div>';
                });
                container.appendChild(card);
            });
        }

        function renderTopologyMap() {
            const svg = document.getElementById('topology-map');
            svg.innerHTML = ''; // Reset

            // Dynamically calculate the center of the landscape SVG topology map
            const width = svg.clientWidth || svg.parentNode.clientWidth || 1000;
            const height = svg.clientHeight || svg.parentNode.clientHeight || 320;
            const cx = width / 2;
            const cy = height / 2;
            const nodes = Object.values(nodesData);
            const radius = Math.min(width, height) * 0.38;

            const searchQuery = document.getElementById('node-search') ? document.getElementById('node-search').value.toLowerCase().trim() : '';

            // 1. Draw central Hub node (Control Plane)
            const hubGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            hubGroup.innerHTML = 
                '<circle cx="' + cx + '" cy="' + cy + '" r="35" fill="rgba(0, 242, 254, 0.15)" stroke="var(--accent-teal)" stroke-width="2" style="filter: drop-shadow(0 0 10px rgba(0, 242, 254, 0.4));" />' +
                '<text x="' + cx + '" y="' + (cy + 4) + '" fill="#fff" font-size="12" font-weight="700" text-anchor="middle">CENTRAL</text>';
            
            // 2. Draw Spokes and Node connections dynamically
            nodes.forEach((node, idx) => {
                const isLegacy = isLegacyNode(node);
                const angle = (idx * 2 * Math.PI) / nodes.length;
                const nx = cx + radius * Math.cos(angle);
                const ny = cy + radius * Math.sin(angle);

                // 2.1 Tab validation
                let tabActive = true;
                if (currentPlatformFilter !== 'all') {
                    if (currentPlatformFilter === 'legacy' && !isLegacy) tabActive = false;
                    if (currentPlatformFilter === 'linux' && (node.os !== 'linux' || isLegacy)) tabActive = false;
                    if (currentPlatformFilter === 'windows' && (node.os !== 'windows' || isLegacy)) tabActive = false;
                    if (currentPlatformFilter === 'darwin' && (node.os !== 'darwin' || isLegacy)) tabActive = false;
                }

                // 2.2 Search validation
                let searchActive = true;
                if (searchQuery) {
                    const matchesBasic = node.hostname.toLowerCase().includes(searchQuery) || 
                                         node.IP.includes(searchQuery) || 
                                         node.os.toLowerCase().includes(searchQuery);
                    const matchesApps = node.app_inventory.some(app => app.toLowerCase().includes(searchQuery));
                    const matchesHw = (node.hardware && node.hardware.cpu_model.toLowerCase().includes(searchQuery)) || 
                                       (node.hardware && node.hardware.sys_model.toLowerCase().includes(searchQuery));
                    if (!matchesBasic && !matchesApps && !matchesHw) {
                        searchActive = false;
                    }
                }

                const opacity = (tabActive && searchActive) ? '1.0' : '0.12';

                // Spoke line color
                let lineColor = 'rgba(255,255,255,0.15)';
                if (node.status === 'UPGRADING') {
                    lineColor = 'var(--accent-gold)';
                } else if (node.id === highlightedNodeId) {
                    lineColor = isLegacy ? 'var(--accent-bronze)' : 'var(--accent-teal)';
                }

                // Draw connecting spoke line
                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', cx);
                line.setAttribute('y1', cy);
                line.setAttribute('x2', nx);
                line.setAttribute('y2', ny);
                line.setAttribute('stroke', lineColor);
                line.setAttribute('stroke-width', (node.id === highlightedNodeId) ? '3' : '2');
                line.setAttribute('opacity', opacity);
                if (node.status === 'UPGRADING' && tabActive && searchActive) {
                    line.setAttribute('stroke-dasharray', '5,5');
                    line.innerHTML = '<animate attributeName="stroke-dashoffset" values="50;0" dur="2s" repeatCount="indefinite" />';
                }
                svg.appendChild(line);

                // Glow animation for search results focus
                if (node.id === highlightedNodeId && tabActive && searchActive) {
                    const halo = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                    halo.setAttribute('cx', nx);
                    halo.setAttribute('cy', ny);
                    halo.setAttribute('r', '32');
                    halo.setAttribute('fill', 'none');
                    halo.setAttribute('stroke', isLegacy ? 'var(--accent-bronze)' : 'var(--accent-teal)');
                    halo.setAttribute('stroke-width', '2');
                    halo.setAttribute('style', 'animation: ' + (isLegacy ? 'neon-pulse-bronze' : 'neon-pulse-teal') + ' 1.5s infinite;');
                    halo.setAttribute('opacity', opacity);
                    svg.appendChild(halo);
                }

                // Draw Spoke server node
                const nodeG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                nodeG.setAttribute('style', 'cursor: pointer;');
                nodeG.setAttribute('onclick', 'inspectInventory("' + node.id + '")');
                nodeG.setAttribute('opacity', opacity);

                const circleColor = isLegacy ? 'var(--accent-bronze)' : (node.os === 'linux' ? 'var(--accent-teal)' : (node.os === 'windows' ? 'var(--accent-gold)' : 'var(--accent-orange)'));
                const statusPulse = node.status === 'UPGRADING' ? 'rgba(255, 183, 3, 0.3)' : 'rgba(255,255,255,0.05)';

                nodeG.innerHTML = 
                    '<circle cx="' + nx + '" cy="' + ny + '" r="22" fill="' + statusPulse + '" stroke="' + circleColor + '" stroke-width="2" />' +
                    '<text x="' + nx + '" y="' + (ny - 27) + '" fill="#fff" font-size="11" font-weight="600" text-anchor="middle">' + node.hostname + '</text>' +
                    '<text x="' + nx + '" y="' + (ny + 4) + '" fill="var(--text-muted)" font-size="9" font-weight="700" text-anchor="middle">' + (isLegacy ? 'LEGACY' : node.os.toUpperCase()) + '</text>' +
                    '<text x="' + nx + '" y="' + (ny + 27) + '" fill="' + (isLegacy ? 'var(--accent-bronze)' : 'var(--accent-teal)') + '" font-size="9" text-anchor="middle">' + node.IP + '</text>';

                svg.appendChild(nodeG);
            });

            svg.appendChild(hubGroup);
        }

        // Deep Search Orchestrator (Searches Hostname, IP, OS, Software)
        function executeSearch() {
            const query = document.getElementById('node-search').value.toLowerCase().trim();
            if (!query) {
                resetSearch();
                return;
            }

            const matches = Object.values(nodesData).filter(n => {
                const matchesBasic = n.hostname.toLowerCase().includes(query) || 
                                     n.IP.includes(query) || 
                                     n.os.toLowerCase().includes(query);
                const matchesApps = n.app_inventory.some(app => app.toLowerCase().includes(query));
                const matchesHw = (n.hardware && n.hardware.cpu_model.toLowerCase().includes(query)) || 
                                   (n.hardware && n.hardware.sys_model.toLowerCase().includes(query));
                return matchesBasic || matchesApps || matchesHw;
            });

            if (matches.length === 0) {
                // Shake search field and outline orange
                const input = document.getElementById('node-search');
                input.style.borderColor = 'var(--accent-orange)';
                input.style.boxShadow = '0 0 10px rgba(255, 94, 98, 0.4)';
                setTimeout(() => {
                    input.style.borderColor = 'var(--accent-teal)';
                    input.style.boxShadow = 'none';
                }, 1500);
                return;
            }

            // Target first matched server
            const matchedNode = matches[0];
            highlightedNodeId = matchedNode.id;

            // Automatically open its matching tab selector
            const isLegacy = isLegacyNode(matchedNode);
            if (isLegacy) {
                setPlatformFilter('legacy');
            } else if (matchedNode.os === 'linux') {
                setPlatformFilter('linux');
            } else if (matchedNode.os === 'windows') {
                setPlatformFilter('windows');
            } else if (matchedNode.os === 'darwin') {
                setPlatformFilter('darwin');
            }

            inspectInventory(matchedNode.id);
            renderTopologyMap();
            renderNodes();

            // Perform visually stunning card focus transition
            setTimeout(() => {
                const card = document.getElementById('card-' + matchedNode.id);
                if (card) {
                    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    card.style.borderColor = isLegacy ? 'var(--accent-bronze)' : 'var(--accent-teal)';
                    card.style.boxShadow = isLegacy ? '0 0 20px rgba(226, 135, 67, 0.3)' : '0 0 20px rgba(0, 242, 254, 0.3)';
                    setTimeout(() => {
                        card.style.borderColor = matchedNode.status === 'UPGRADING' ? 'var(--accent-gold)' : (isLegacy ? 'rgba(226, 135, 67, 0.18)' : 'rgba(255,255,255,0.06)');
                        card.style.boxShadow = 'none';
                    }, 2500);
                }
            }, 100);
        }

        function resetSearch() {
            document.getElementById('node-search').value = '';
            highlightedNodeId = null;
            renderNodes();
            renderTopologyMap();
        }

        // Tabbed inspector controls
        function setInspectorTab(tab) {
            currentInspectorTab = tab;
            
            // Set buttons active state
            document.getElementById('inspector-tab-software').classList.remove('active');
            document.getElementById('inspector-tab-hardware').classList.remove('active');
            document.getElementById('inspector-tab-aggregates').classList.remove('active');
            
            if (tab === 'software') document.getElementById('inspector-tab-software').classList.add('active');
            if (tab === 'hardware') document.getElementById('inspector-tab-hardware').classList.add('active');
            if (tab === 'aggregates') document.getElementById('inspector-tab-aggregates').classList.add('active');

            updateInspector();
        }

        function inspectInventory(nodeId) {
            selectedNodeId = nodeId;
            updateInspector();
        }

        function updateInspector() {
            const div = document.getElementById('central-inventory');
            
            // If the Aggregates tab is clicked, always display calculations
            if (currentInspectorTab === 'aggregates') {
                renderFleetAggregates(div);
                return;
            }

            if (!selectedNodeId || !nodesData[selectedNodeId]) {
                div.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px 0;">Select a host spoke node or card to inspect attributes.</div>';
                return;
            }

            const node = nodesData[selectedNodeId];
            const isLegacy = isLegacyNode(node);

            if (currentInspectorTab === 'software') {
                let tagsHTML = '';
                node.app_inventory.forEach(app => {
                    tagsHTML += '<span class="inventory-tag">' + app + '</span>';
                });

                const protocolLabel = isLegacy ? 'LegacyTel v1 (Monolithic Service)' : 'LegacyTel v2 (OTel Active Worker)';
                const hyperLabel = isLegacy ? 'Bare-Metal Mainframe' : node.hypervisor_name;
                const statusTheme = isLegacy ? 'var(--accent-bronze)' : 'var(--accent-teal)';

                div.innerHTML = 
                    '<div style="font-weight: 700; color: #fff; margin-bottom: 12px; font-size: 15px; border-left: 3px solid ' + statusTheme + '; padding-left: 8px;">' + node.hostname + ' (' + node.IP + ')</div>' +
                    '<div style="margin-bottom: 8px; font-size: 13px;">Agent Protocol: <strong style="color: ' + statusTheme + ';">' + protocolLabel + '</strong></div>' +
                    '<div style="margin-bottom: 8px; font-size: 13px;">Classified Host Environment: <strong style="color: var(--accent-gold);">' + hyperLabel + '</strong></div>' +
                    '<div style="margin-bottom: 18px; font-size: 13px;">Agent Active Version: <strong style="color: var(--accent-teal);">' + node.version + '</strong></div>' +
                    '<div style="font-weight: 600; color: #fff; margin-bottom: 6px; font-size: 13px;">Scanned Application Inventory:</div>' +
                    '<div class="inventory-list">' + tagsHTML + '</div>';

            } else if (currentInspectorTab === 'hardware') {
                let hw = node.hardware;
                let hardwareHTML = '';
                const progressTheme = isLegacy ? 'bronze' : (node.os === 'linux' ? 'teal' : (node.os === 'windows' ? 'gold' : 'orange'));
                
                if (hw && hw.cpu_model) {
                    hardwareHTML = 
                        '<div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 12px; margin-bottom: 15px; font-size: 12px; line-height:1.6;">' +
                            '<div style="font-weight:700; color:var(--accent-teal); margin-bottom: 8px; font-size:13px;">💻 SYSTEM HARDWARE PARAMETERS</div>' +
                            '<div><strong>Hardware Model:</strong> ' + hw.sys_model + '</div>' +
                            '<div><strong>CPU Model:</strong> ' + hw.cpu_model + '</div>' +
                            '<div><strong>Active CPU Cores:</strong> ' + hw.cpu_cores + ' Cores</div>' +
                            '<div><strong>Memory Size:</strong> ' + hw.total_ram_gb.toFixed(1) + ' GB RAM</div>' +
                            '<div><strong>Disk Storage capacity:</strong> ' + hw.total_disk_gb.toFixed(1) + ' GB SSD</div>' +
                        '</div>';
                }

                div.innerHTML = 
                    '<div style="font-weight: 700; color: #fff; margin-bottom: 12px; font-size: 15px;">Host: ' + node.hostname + '</div>' +
                    hardwareHTML +
                    '<div class="inspector-metric-card">' +
                        '<div style="display:flex; justify-content:space-between; font-size:12px;">' +
                            '<span>Live CPU Utilization</span>' +
                            '<strong>' + node.cpu_usage.toFixed(1) + '%</strong>' +
                        '</div>' +
                        '<div class="progress-container">' +
                            '<div class="progress-bar ' + progressTheme + '" style="width: ' + node.cpu_usage + '%;"></div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="inspector-metric-card">' +
                        '<div style="display:flex; justify-content:space-between; font-size:12px;">' +
                            '<span>Live RAM Allocation</span>' +
                            '<strong>' + node.memory_usage.toFixed(1) + '%</strong>' +
                        '</div>' +
                        '<div class="progress-container">' +
                            '<div class="progress-bar ' + progressTheme + '" style="width: ' + node.memory_usage + '%;"></div>' +
                        '</div>' +
                    '</div>';
            }
        }

        // Live Dynamic Fleet Aggregator tab generator
        function renderFleetAggregates(div) {
            const nodes = Object.values(nodesData);
            let totalMemory = 0;
            let totalStorage = 0;
            let totalCores = 0;
            let totalThroughput = 0;
            
            let legacyCount = 0;
            let linuxCount = 0;
            let winCount = 0;
            let macCount = 0;

            nodes.forEach(n => {
                const isLegacy = isLegacyNode(n);
                if (isLegacy) legacyCount++;
                else if (n.os === 'linux') linuxCount++;
                else if (n.os === 'windows') winCount++;
                else if (n.os === 'darwin') macCount++;

                if (n.hardware) {
                    totalMemory += n.hardware.total_ram_gb || 0;
                    totalStorage += n.hardware.total_disk_gb || 0;
                    totalCores += n.hardware.cpu_cores || 0;
                }
                totalThroughput += n.throughput || 0;
            });

            div.innerHTML = 
                '<div style="font-weight: 700; color: #fff; margin-bottom: 8px; font-size: 15px; color: var(--accent-teal);">📊 Central Fleet Aggregates</div>' +
                '<div style="font-size: 12px; color: var(--text-muted); margin-bottom: 15px;">Real-time resource metrics across all connected servers</div>' +
                
                '<div style="background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.04); border-radius: 12px; padding: 15px; font-size:12px; line-height:1.6;">' +
                    '<div style="font-weight:700; color:var(--text-main); margin-bottom:10px;">💾 GLOBAL HARDWARE CAPACITIES</div>' +
                    '<div style="display:flex; justify-content:space-between;"><span>Total Monitored Servers:</span> <strong>' + nodes.length + ' Nodes</strong></div>' +
                    '<div style="display:flex; justify-content:space-between;"><span>Total Memory Managed:</span> <strong>' + totalMemory.toFixed(0) + ' GB RAM</strong></div>' +
                    '<div style="display:flex; justify-content:space-between;"><span>Total Disk Storage Managed:</span> <strong>' + (totalStorage / 1024).toFixed(2) + ' TB SSD</strong></div>' +
                    '<div style="display:flex; justify-content:space-between;"><span>Total CPU Cores Managed:</span> <strong>' + totalCores + ' Cores</strong></div>' +
                    '<div style="display:flex; justify-content:space-between; border-top:1px solid rgba(255,255,255,0.06); margin-top:8px; padding-top:8px;"><span>Total Fleet Ingest:</span> <strong style="color:var(--accent-green);">' + totalThroughput.toFixed(1) + ' EPS</strong></div>' +
                '</div>' +
                
                '<div class="aggregate-grid">' +
                    '<div class="aggregate-card">' +
                        '<div style="font-size:11px; color:var(--accent-bronze);">🏛️ Legacy v1</div>' +
                        '<div class="aggregate-val">' + legacyCount + '</div>' +
                    '</div>' +
                    '<div class="aggregate-card">' +
                        '<div style="font-size:11px; color:var(--accent-teal);">🐧 Linux v2</div>' +
                        '<div class="aggregate-val">' + linuxCount + '</div>' +
                    '</div>' +
                    '<div class="aggregate-card">' +
                        '<div style="font-size:11px; color:var(--accent-gold);">🪟 Windows v2</div>' +
                        '<div class="aggregate-val">' + winCount + '</div>' +
                    '</div>' +
                    '<div class="aggregate-card">' +
                        '<div style="font-size:11px; color:var(--accent-orange);">🍎 macOS v2</div>' +
                        '<div class="aggregate-val">' + macCount + '</div>' +
                    '</div>' +
                '</div>';
        }

        // Full Tabular Spreadsheet Modal Logic
        function openHardwareTableModal() {
            document.getElementById('hardware-table-modal').style.display = 'flex';
            document.getElementById('modal-table-search').value = '';
            renderModalTable();
        }

        function closeHardwareTableModal() {
            document.getElementById('hardware-table-modal').style.display = 'none';
        }

        function renderModalTable(filterQuery = '') {
            const body = document.getElementById('modal-table-body');
            body.innerHTML = '';

            let nodes = Object.values(nodesData);

            // Filter
            if (filterQuery) {
                const query = filterQuery.toLowerCase().trim();
                nodes = nodes.filter(n => {
                    const matchesHw = n.hardware && (
                        n.hardware.sys_model.toLowerCase().includes(query) ||
                        n.hardware.cpu_model.toLowerCase().includes(query)
                    );
                    return n.hostname.toLowerCase().includes(query) ||
                           n.IP.includes(query) ||
                           n.os.toLowerCase().includes(query) ||
                           n.version.toLowerCase().includes(query) ||
                           matchesHw;
                });
            }

            // Sort logic
            if (sortedColumn !== -1) {
                nodes.sort((a, b) => {
                    let valA, valB;
                    switch (sortedColumn) {
                        case 0: valA = a.hostname; valB = b.hostname; break;
                        case 1: valA = a.IP; valB = b.IP; break;
                        case 2: valA = isLegacyNode(a) ? 'LegacyTel v1' : 'LegacyTel v2'; valB = isLegacyNode(b) ? 'LegacyTel v1' : 'LegacyTel v2'; break;
                        case 3: valA = a.os; valB = b.os; break;
                        case 4: valA = a.hardware ? a.hardware.sys_model : ''; valB = b.hardware ? b.hardware.sys_model : ''; break;
                        case 5: valA = a.hardware ? a.hardware.cpu_model : ''; valB = b.hardware ? b.hardware.cpu_model : ''; break;
                        case 6: valA = a.hardware ? a.hardware.cpu_cores : 0; valB = b.hardware ? b.hardware.cpu_cores : 0; break;
                        case 7: valA = a.hardware ? a.hardware.total_ram_gb : 0; valB = b.hardware ? b.hardware.total_ram_gb : 0; break;
                        case 8: valA = a.hardware ? a.hardware.total_disk_gb : 0; valB = b.hardware ? b.hardware.total_disk_gb : 0; break;
                        case 9: valA = a.hypervisor_name; valB = b.hypervisor_name; break;
                    }

                    if (typeof valA === 'string') {
                        return sortAscending ? valA.localeCompare(valB) : valB.localeCompare(valA);
                    } else {
                        return sortAscending ? (valA - valB) : (valB - valA);
                    }
                });
            }

            nodes.forEach(node => {
                const isLegacy = isLegacyNode(node);
                const tr = document.createElement('tr');
                
                const protocol = isLegacy ? 'LegacyTel v1 (Monolithic)' : 'LegacyTel v2 (OTel)';
                const hw = node.hardware || { sys_model: 'N/A', cpu_model: 'N/A', cpu_cores: 0, total_ram_gb: 0, total_disk_gb: 0 };
                
                const modelStr = hw.sys_model || 'Standard Server';
                const cpuStr = hw.cpu_model || 'Intel/AMD Processor';
                const coresStr = hw.cpu_cores ? hw.cpu_cores + ' Cores' : 'N/A';
                const ramStr = hw.total_ram_gb ? hw.total_ram_gb.toFixed(0) + ' GB' : 'N/A';
                const diskStr = hw.total_disk_gb ? hw.total_disk_gb.toFixed(0) + ' GB' : 'N/A';
                
                tr.innerHTML = 
                    '<td><strong>' + node.hostname + '</strong></td>' +
                    '<td>' + node.IP + '</td>' +
                    '<td><span style="color:' + (isLegacy ? 'var(--accent-bronze)' : 'var(--accent-teal)') + ';">' + protocol + '</span></td>' +
                    '<td style="text-transform:uppercase;">' + node.os + '</td>' +
                    '<td>' + modelStr + '</td>' +
                    '<td>' + cpuStr + '</td>' +
                    '<td>' + coresStr + '</td>' +
                    '<td>' + ramStr + '</td>' +
                    '<td>' + diskStr + '</td>' +
                    '<td>' + node.hypervisor_name + '</td>';
                body.appendChild(tr);
            });
        }

        function filterModalTable() {
            const query = document.getElementById('modal-table-search').value;
            renderModalTable(query);
        }

        function sortModalTable(colIndex) {
            if (sortedColumn === colIndex) {
                sortAscending = !sortAscending;
            } else {
                sortedColumn = colIndex;
                sortAscending = true;
            }

            // Update headers arrows
            for (let i = 0; i < 10; i++) {
                const el = document.getElementById('sort-icon-' + i);
                if (el) {
                    if (i === colIndex) {
                        el.textContent = sortAscending ? '▲' : '▼';
                    } else {
                        el.textContent = '⇅';
                    }
                }
            }

            const query = document.getElementById('modal-table-search').value;
            renderModalTable(query);
        }

        // CSV dynamic spreadsheet exporter
        function exportCSVData() {
            const query = document.getElementById('modal-table-search').value.toLowerCase().trim();
            let nodes = Object.values(nodesData);

            if (query) {
                nodes = nodes.filter(n => {
                    const matchesHw = n.hardware && (
                        n.hardware.sys_model.toLowerCase().includes(query) ||
                        n.hardware.cpu_model.toLowerCase().includes(query)
                    );
                    return n.hostname.toLowerCase().includes(query) ||
                           n.IP.includes(query) ||
                           n.os.toLowerCase().includes(query) ||
                           n.version.toLowerCase().includes(query) ||
                           matchesHw;
                });
            }

            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Hostname,IP Address,Agent Protocol,Operating System,System Model,CPU Model,Cores,RAM (GB),Disk (GB),Hypervisor\n";

            nodes.forEach(node => {
                const isLegacy = isLegacyNode(node);
                const protocol = isLegacy ? "LegacyTel v1 Monolithic" : "LegacyTel v2 OTel";
                const hw = node.hardware || { sys_model: "N/A", cpu_model: "N/A", cpu_cores: 0, total_ram_gb: 0, total_disk_gb: 0 };
                
                const row = [
                    node.hostname,
                    node.IP,
                    protocol,
                    node.os.toUpperCase(),
                    hw.sys_model.replace(/,/g, " "),
                    hw.cpu_model.replace(/,/g, " "),
                    hw.cpu_cores,
                    hw.total_ram_gb.toFixed(0),
                    hw.total_disk_gb.toFixed(0),
                    node.hypervisor_name
                ];
                
                csvContent += row.join(",") + "\n";
            });

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "legacytel_hardware_inventory.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // Security CSV dynamic spreadsheet exporter
        function exportSecurityCSVData() {
            const query = document.getElementById('log-auditor-search') ? document.getElementById('log-auditor-search').value.toLowerCase().trim() : '';
            let logs = [...auditLogsData].reverse();

            if (query) {
                logs = logs.filter(log => {
                    return log.event_code.toLowerCase().includes(query) ||
                           log.description.toLowerCase().includes(query) ||
                           log.host.toLowerCase().includes(query) ||
                           log.source_ip.includes(query) ||
                           log.dest_ip.includes(query) ||
                           log.user.toLowerCase().includes(query) ||
                           log.email.toLowerCase().includes(query) ||
                           log.domain.toLowerCase().includes(query) ||
                           log.raw_log.toLowerCase().includes(query);
                });
            }

            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Timestamp,Host,Code,Event Description,Source IP,Dest IP,User Name,Email,Domain,Raw Log\n";

            logs.forEach(log => {
                const row = [
                    log.timestamp,
                    log.host,
                    log.event_code,
                    log.description,
                    log.source_ip,
                    log.dest_ip,
                    log.user,
                    log.email,
                    log.domain,
                    '"' + log.raw_log.replace(/"/g, '""').replace(/,/g, " ") + '"'
                ];
                
                csvContent += row.join(",") + "\n";
            });

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "legacytel_security_audit_logs.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        function triggerUpgrade(nodeId) {
            const version = document.getElementById('select-' + nodeId).value;
            fetch('/api/v1/admin/upgrade', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ node_id: nodeId, target_version: version })
            })
            .then(res => res.json())
            .then(data => {
                console.log("Upgrade scheduled:", data);
            });
        }

        function triggerBulkUpgrade() {
            // Bulk upgrade only updates v2 fleet agents to preserve v1 classic systems
            fetch('/api/v1/admin/upgrade-all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_version: "v2.0.0" })
            })
            .then(res => res.json())
            .then(data => {
                console.log("Bulk upgrade scheduled:", data);
            });
        }

        function openUploadModal() {
            document.getElementById('upload-error').textContent = '';
            document.getElementById('upload-modal').style.display = 'flex';
        }

        function closeUploadModal() {
            document.getElementById('upload-modal').style.display = 'none';
        }

        function submitPackageUpload() {
            const osName = document.getElementById('upload-os').value;
            const arch = document.getElementById('upload-arch').value;
            const version = document.getElementById('upload-version').value;
            const channel = document.getElementById('upload-channel').value;

            if (!version) {
                document.getElementById('upload-error').textContent = 'Please enter a valid version.';
                return;
            }

            fetch('/api/v1/admin/binaries', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ version: version, os: osName, arch: arch, channel: channel })
            })
            .then(res => {
                if (res.status === 409) {
                    throw new Error('DUPLICATE_VERSION');
                }
                return res.json();
            })
            .then(data => {
                closeUploadModal();
            })
            .catch(err => {
                if (err.message === 'DUPLICATE_VERSION') {
                    document.getElementById('upload-error').textContent = 'Error: A package with this version already exists for this architecture!';
                } else {
                    document.getElementById('upload-error').textContent = 'Error uploading package details.';
                }
            });
        }

        function openPolicyModal() {
            document.getElementById('policy-modal').style.display = 'flex';
        }

        function closePolicyModal() {
            document.getElementById('policy-modal').style.display = 'none';
        }

        function savePolicyConfig() {
            const config = document.getElementById('policy-text').value;
            fetch('/api/v1/admin/policy/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ config: config })
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById('stat-policy').textContent = data.version;
                closePolicyModal();
            });
        }
    </script>
</body>
</html>`
