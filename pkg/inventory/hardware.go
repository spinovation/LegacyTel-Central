package inventory

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// HardwareInfo stores unprivileged system hardware attributes
type HardwareInfo struct {
	CPUModel    string  `json:"cpu_model"`
	CPUCores    int     `json:"cpu_cores"`
	TotalRAMGB  float64 `json:"total_ram_gb"`
	TotalDiskGB float64 `json:"total_disk_gb"`
	SysModel    string  `json:"sys_model"`
}

// ScanHardware programmatically scans the system hardware parameters in user-space
func ScanHardware() HardwareInfo {
	info := HardwareInfo{
		CPUCores: runtime.NumCPU(),
		CPUModel: "Intel/AMD Processor",
		SysModel: "Standard Server Host",
	}

	// 1. Scan CPU Model
	info.CPUModel = scanCPUModel()

	// 2. Scan Total RAM
	info.TotalRAMGB = scanTotalRAM()

	// 3. Scan Disk Size
	info.TotalDiskGB = scanDiskSize()

	// 4. Scan System Model
	info.SysModel = scanSystemModel()

	return info
}

func scanCPUModel() string {
	switch runtime.GOOS {
	case "linux":
		file, err := os.Open("/proc/cpuinfo")
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "model name") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	case "darwin":
		cmd := exec.Command("sysctl", "-n", "machdep.cpu.brand_string")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			return strings.TrimSpace(out.String())
		}
	case "windows":
		cmd := exec.Command("reg", "query", "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "/v", "ProcessorNameString")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			scanner := bufio.NewScanner(&out)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "ProcessorNameString") {
					parts := strings.SplitN(line, "REG_SZ", 2)
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return "Generic " + runtime.GOARCH + " CPU"
}

func scanTotalRAM() float64 {
	switch runtime.GOOS {
	case "linux":
		file, err := os.Open("/proc/meminfo")
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "MemTotal:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						kb, _ := strconv.ParseFloat(fields[1], 64)
						return kb / (1024 * 1024) // Convert KB to GB
					}
				}
			}
		}
	case "darwin":
		cmd := exec.Command("sysctl", "-n", "hw.memsize")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			bytesVal, _ := strconv.ParseFloat(strings.TrimSpace(out.String()), 64)
			return bytesVal / (1024 * 1024 * 1024) // Convert bytes to GB
		}
	case "windows":
		cmd := exec.Command("wmic", "ComputerSystem", "get", "TotalPhysicalMemory", "/value")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			scanner := bufio.NewScanner(&out)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "TotalPhysicalMemory=") {
					bytesStr := strings.TrimPrefix(line, "TotalPhysicalMemory=")
					bytesVal, _ := strconv.ParseFloat(strings.TrimSpace(bytesStr), 64)
					return bytesVal / (1024 * 1024 * 1024)
				}
			}
		}
	}
	return 16.0 // Default fallback
}

func scanDiskSize() float64 {
	// Standard library unprivileged Syscall.Statfs for Linux/macOS
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		var stat syscall.Statfs_t
		err := syscall.Statfs("/", &stat)
		if err == nil {
			// Bsize is block size. Blocks is total block count.
			// Cast fields to uint64 since Bsize type varies across linux/darwin
			totalBytes := uint64(stat.Blocks) * uint64(stat.Bsize)
			return float64(totalBytes) / (1024 * 1024 * 1024) // Convert bytes to GB
		}
	} else if runtime.GOOS == "windows" {
		// Windows unprivileged wmic disk drive query
		cmd := exec.Command("wmic", "diskdrive", "get", "size", "/value")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			scanner := bufio.NewScanner(&out)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Size=") {
					sizeStr := strings.TrimPrefix(line, "Size=")
					sizeVal, _ := strconv.ParseFloat(strings.TrimSpace(sizeStr), 64)
					return sizeVal / (1024 * 1024 * 1024)
				}
			}
		}
	}
	return 256.0 // Default fallback
}

func scanSystemModel() string {
	switch runtime.GOOS {
	case "linux":
		product, err := os.ReadFile("/sys/class/dmi/id/product_name")
		if err == nil {
			return strings.TrimSpace(string(product))
		}
	case "windows":
		cmd := exec.Command("reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "/v", "SystemProductName")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			scanner := bufio.NewScanner(&out)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "SystemProductName") {
					parts := strings.SplitN(line, "REG_SZ", 2)
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	case "darwin":
		cmd := exec.Command("sysctl", "-n", "hw.model")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			return strings.TrimSpace(out.String())
		}
	}
	return "Standard Physical Machine"
}
