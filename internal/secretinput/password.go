package secretinput

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type Source struct {
	Env, File     string
	Stdin, Prompt bool
}

func (s Source) Read(in io.Reader, errOut io.Writer) ([]byte, error) {
	n := 0
	for _, v := range []bool{len(s.Env) > 0, len(s.File) > 0, s.Stdin, s.Prompt} {
		if v {
			n++
		}
	}
	if n > 1 {
		return nil, errors.New("choose one password source")
	}
	if len(s.Env) > 0 {
		v, ok := os.LookupEnv(s.Env)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", s.Env)
		}

		return []byte(v), nil
	}
	if len(s.File) > 0 {
		b, e := os.ReadFile(s.File)
		return []byte(strings.TrimRight(string(b), "\r\n")), e
	}
	if s.Prompt {
		f, ok := in.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return nil, errors.New("password prompt requires a terminal")
		}

		fmt.Fprint(errOut, "Password: ")
		b, e := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(errOut)
		return b, e
	}
	if s.Stdin {
		b, e := io.ReadAll(in)
		return []byte(strings.TrimRight(string(b), "\r\n")), e
	}

	return nil, nil
}

func Clear(v []byte) {
	for i := range v {
		v[i] = 0
	}
}
