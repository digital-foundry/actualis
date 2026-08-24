//go:build !darwin

package main

// Linux and Windows have no single reliable cross-desktop appearance signal,
// so the theme is not probed there. setIcon falls back to the dark-menu-bar
// colourway, which suits the common dark taskbar; ACTUALIS_TRAY_THEME=light
// overrides it. See setIcon.
func menuBarIsDark() (dark, known bool) { return false, false }
