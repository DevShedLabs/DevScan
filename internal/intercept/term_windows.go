//go:build windows

package intercept

func termWidth() int {
	return 0 // fallback to default; Windows console width detection skipped
}
