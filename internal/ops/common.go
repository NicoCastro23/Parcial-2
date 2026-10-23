package ops

import (
	"context"
	"errors"
	"time"

	"np2auto/internal/runner"
)

// Result es el resultado de una operación por pasos (todos los módulos salvo
// la llave de root, que tiene su propio tipo con datos de la llave).
type Result struct {
	Steps []Step
	OK    bool
}

// opRun agrupa lo que comparten los pasos de una operación: el canal, el
// nombre de la operación para el registro y la lista de pasos.
type opRun struct {
	ctx context.Context
	rn  runner.Runner
	op  string
	res *Result
}

func newRun(ctx context.Context, rn runner.Runner, op string) *opRun {
	return &opRun{ctx: ctx, rn: rn, op: op, res: &Result{}}
}

// step ejecuta un paso, lo agrega al resultado y devuelve si salió bien. Si
// falla, el detalle visible es el mensaje comprensible de runner.Explain y el
// técnico conserva comando, salida y código de salida.
func (o *opRun) step(name string, fn func() (detail, technical string, err error)) bool {
	d, tech, err := fn()
	s := Step{Name: name, OK: err == nil, Detail: d, Technical: tech}
	if err != nil {
		s.Detail = runner.Explain(err)
		var re *runner.Error
		if errors.As(err, &re) {
			s.Technical = joinTech(re.Result)
		} else if tech == "" {
			s.Technical = err.Error()
		}
	}
	o.res.Steps = append(o.res.Steps, s)
	return err == nil
}

// remote ejecuta un script en la VM con su propio límite de tiempo; sub
// aparece en el registro como "<operación>/<sub>".
func (o *opRun) remote(sub, script string, timeout time.Duration) (runner.Result, error) {
	c, cancel := context.WithTimeout(runner.WithOp(o.ctx, o.op+"/"+sub), timeout)
	defer cancel()
	return o.rn.Run(c, script)
}

// done marca la operación como completa y devuelve el resultado.
func (o *opRun) done() *Result {
	o.res.OK = true
	return o.res
}
