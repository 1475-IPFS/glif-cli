/*
Copyright © 2023 Glif LTD
*/
package cmd

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/glifio/cli/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// createAccountCmd represents the create-account command
var importAccountCmd = &cobra.Command{
	Use:   "import-account [account-name]",
	Short: "import a single named account",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		as := util.AccountsStore()

		var name string
		if len(args) == 1 {
			name = strings.ToLower(args[0])
		} else {
			name = "default"
		}

		_, err := as.Get(name)
		var e *util.ErrKeyNotFound
		if !errors.As(err, &e) {
			logFatalf("Account %s already exists", name)
		}

		if name == string(util.OwnerKey) ||
			name == string(util.OperatorKey) ||
			name == string(util.RequestKey) {
			logFatalf("Account name %s reserved for agent, try: glif wallet create-agent-accounts", name)
		}

		re := regexp.MustCompile(`^[tf][0-9]`)
		if strings.HasPrefix(name, "0x") || re.MatchString(name) {
			logFatalf("Invalid name")
		}

		fmt.Println("Importing account:", name)

		var hexKey string

		prompt := &survey.Password{
			Message: "Please input your private key",
		}

		survey.AskOne(prompt, &hexKey)
		if strings.HasPrefix(hexKey, "0x") {
			hexKey = hexKey[2:]
		}
		privateKey, err := crypto.HexToECDSA(hexKey)
		if err != nil {
			logFatal(err)
		}
		passphrase, envSet := os.LookupEnv("GLIF_PASSPHRASE")
		if !envSet {
			prompt := &survey.Password{
				Message: "Please type a passphrase to encrypt your private key",
			}
			survey.AskOne(prompt, &passphrase)
			var confirmPassphrase string
			confirmPrompt := &survey.Password{
				Message: "Confirm passphrase",
			}
			survey.AskOne(confirmPrompt, &confirmPassphrase)
			if passphrase != confirmPassphrase {
				logFatal("Aborting. Passphrase confirmation did not match.")
			}
		}

		ks := util.KeyStore()

		account, err := ks.ImportECDSA(privateKey, passphrase)
		if err != nil {
			logFatal(err)
		}

		as.Set(name, account.Address.String())

		if err := viper.WriteConfig(); err != nil {
			logFatal(err)
		}

		accountAddr, accountDelAddr, err := as.GetAddrs(name)
		if err != nil {
			logFatal(err)
		}

		bs := util.BackupsStore()
		bs.Invalidate()

		log.Printf("%s address: %s (ETH), %s (FIL)\n", name, accountAddr, accountDelAddr)
	},
}

func init() {
	walletCmd.AddCommand(importAccountCmd)
}
