//go:build !windows

package sandbox

import (
	"context"
	"os/exec"
	"syscall"
)

func newShellCommand(ctx context.Context, script string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", script)
}

// Terminate the whole process group so child processes cannot keep stdout/stderr
// pipes open after a command timeout.
func configureProcessCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
