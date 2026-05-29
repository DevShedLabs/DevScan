package sysinfo

import (
	"os/exec"
	"strings"
)

func collect(info *Info) {
	info.OS = "Windows"
	if out, err := exec.Command("cmd", "/c", "ver").Output(); err == nil {
		info.OSVersion = strings.TrimSpace(string(out))
	}
}
