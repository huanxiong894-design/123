//go:build windows

package sandbox

import (
	"context"
	"os/exec"
)

// Prefer a POSIX-compatible shell when present (for example, Git Bash). Fall
// back to cmd.exe so the binary remains usable on a stock Windows installation.
func newShellCommand(ctx context.Context, script string) *exec.Cmd {
	if sh, err := exec.LookPath("sh"); err == nil {
		return exec.CommandContext(ctx, sh, "-c", script)
	}
	return exec.CommandContext(ctx, "cmd.exe", "/C", script)
}

// Windows does not expose Unix process groups through os/exec. CommandContext
// kills the launched process; WaitDelay bounds how long inherited pipes can hold
// up the caller.
func configureProcessCancellation(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
