package main

import "testing"

// Qwen Code's approval modes reach permission_modes as qwen:<mode>. yolo and
// auto do not ask; accept-edits (Qwen's auto-edit) still asks before a shell
// command. Mirrors the CLI's is_ungated_mode.
func TestQwenModesMatchTheCLI(t *testing.T) {
	for k, want := range map[string]bool{
		"qwen:yolo": true, "qwen:auto": true,
		"qwen:default": false, "qwen:plan": false, "qwen:accept-edits": false,
	} {
		if got := isUngatedMode(k); got != want {
			t.Errorf("isUngatedMode(%q) = %v, want %v", k, got, want)
		}
	}
}
