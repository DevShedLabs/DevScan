package sysinfo

import "runtime"

// Info holds basic system information.
type Info struct {
	OS        string
	OSVersion string
	Arch      string
	Chip      string
}

// Collect returns system information for the current host.
func Collect() Info {
	info := Info{
		Arch: runtime.GOARCH,
	}
	collect(&info)
	return info
}
