package clipassword

import (
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/crypto/ssh/terminal"
)

var (
	u2fFacet  string
	keyfile   string
	verbose   bool
	tty       bool
	enrollkey bool
)

var oldState *terminal.State

func BackupTerminalState() error {
	var err error
	oldState, err = terminal.GetState(0)
	if err != nil {
		return fmt.Errorf("Could not get state of terminal: %w", err)
	}

	// Dont leave terminal broken on ctrl-c
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	go func() {
		for sig := range sigch {
			if sig != nil {
				RestoreTerminalState()
				os.Exit(1)
			}
		}
	}()
	return nil
}

func RestoreTerminalState() {
	if oldState != nil {
		if err := terminal.Restore(0, oldState); err != nil {
			panic("Could not restore terminal:" + err.Error())
		}
	}
}

func Prompt(prompt string) (string, error) {
	if _, err := fmt.Fprintf(os.Stderr, prompt); err != nil {
		return "", err
	}
	password, err := terminal.ReadPassword(0)
	return string(password), err
}
