package ops

import (
	"context"
	"errors"
	"os/exec"

	"np2auto/internal/runner"
)

// localRunner ejecuta el script con bash en este equipo. Solo para pruebas de
// scripts que únicamente leen información.
type localRunner struct{}

func (localRunner) Transport() string { return "local" }
func (localRunner) Describe() string  { return "bash local" }
func (localRunner) Run(ctx context.Context, script string) (runner.Result, error) {
	cmd := exec.CommandContext(ctx, "bash", "-c", "export LC_ALL=C.UTF-8\nset -eu\n"+script)
	out, err := cmd.Output()
	r := runner.Result{Command: "bash", Script: script, Stdout: string(out)}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.Stderr, r.ExitCode = string(ee.Stderr), ee.ExitCode()
		return r, &runner.Error{Kind: runner.KindExit, Result: r, Err: err}
	}
	return r, err
}
