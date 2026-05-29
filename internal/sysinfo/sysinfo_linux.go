package sysinfo

import (
	"os"
	"strings"
)

func collect(info *Info) {
	info.OS = "Linux"
	info.OSVersion = osRelease("PRETTY_NAME")
}

func osRelease(key string) string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.Trim(strings.TrimPrefix(line, key+"="), `"`)
		}
	}
	return ""
}
