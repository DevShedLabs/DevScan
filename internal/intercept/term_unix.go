//go:build !windows

package intercept

import (
	"golang.org/x/sys/unix"
)

func termWidth() int {
	ws, err := unix.IoctlGetWinsize(int(unix.Stdout), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(ws.Col)
}
