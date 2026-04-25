package internal

import "os"

func Bootstrap(command []string, env []string) error {
	if len(command) == 0 {
		command = []string{"/bin/sh"}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	return ServePTY(command, cwd, env)
}
