package sysinfo

import (
	"os/exec"
	"strings"
)

func collect(info *Info) {
	info.OS = "macOS"
	info.OSVersion = swvers("ProductVersion")

	// sysctl gives us the human-readable chip name on Apple Silicon and Intel.
	if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
		info.Chip = strings.TrimSpace(string(out))
	}
}

func swvers(key string) string {
	out, err := exec.Command("sw_vers", "-"+strings.ToLower(key[:1])+key[1:]).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
