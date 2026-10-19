package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type opKey struct{}

// WithOp etiqueta el contexto con el nombre de la operación; aparece en el
// registro (por ejemplo "rootkey/autorizar-llave").
func WithOp(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, opKey{}, op)
}

func opFrom(ctx context.Context) string {
	op, _ := ctx.Value(opKey{}).(string)
	return op
}

// Entry es una línea del registro de operaciones (JSON Lines).
type Entry struct {
	Time       time.Time `json:"time"`
	Target     string    `json:"target"`
	Op         string    `json:"op"`
	Transport  string    `json:"transport"`
	Command    string    `json:"command"`
	Script     string    `json:"script"`
	ExitCode   int       `json:"exit_code"`
	DurationMs int64     `json:"duration_ms"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	Error      string    `json:"error,omitempty"`
}

// Journal guarda cada ejecución para diagnóstico y para la documentación de
// pruebas: qué se ejecutó, dónde, qué respondió y cuánto tardó.
type Journal struct {
	mu   sync.Mutex
	path string
}

// NewJournal crea (si hace falta) el directorio del registro.
func NewJournal(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &Journal{path: path}, nil
}

// Append agrega una entrada. Un fallo al registrar nunca debe romper la
// operación, así que se ignora.
func (j *Journal) Append(e Entry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
}

// Tail devuelve las últimas n entradas, la más reciente primero.
func (j *Journal) Tail(n int) ([]Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.Open(j.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	for i, k := 0, len(all)-1; i < k; i, k = i+1, k-1 {
		all[i], all[k] = all[k], all[i]
	}
	return all, nil
}

// Journaled envuelve un Runner y registra cada ejecución.
type Journaled struct {
	Runner
	J      *Journal
	Target string
}

func (j Journaled) Run(ctx context.Context, script string) (Result, error) {
	res, err := j.Runner.Run(ctx, script)
	e := Entry{
		Time: res.Started, Target: j.Target, Op: opFrom(ctx),
		Transport: j.Runner.Transport(), Command: res.Command, Script: res.Script,
		ExitCode: res.ExitCode, DurationMs: res.Duration.Milliseconds(),
		Stdout: res.Stdout, Stderr: res.Stderr,
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if err != nil {
		e.Error = err.Error()
	}
	if j.J != nil {
		j.J.Append(e)
	}
	return res, err
}
