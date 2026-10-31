//go:build windows

package main

// Windows has no signal-0 probe; the marker's one-hour age limit bounds a
// stale badge after a crash.
func processAlive(pid int) bool { return pid > 0 }
