package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	pdns2ublib "github.com/kxn/pdns2ub/lib"
	"github.com/spf13/viper"
)

var (
	configName = flag.String("config", "pdns2ub.yml", "")
)

func setDefaultConfigs() {
	viper.SetDefault("database.user", "root")
	viper.SetDefault("database.pass", "")
	viper.SetDefault("database.host", "127.0.0.1")
	viper.SetDefault("database.port", 3306)
	viper.SetDefault("database.dbname", "pdns")
	viper.SetDefault("database.maxidle", "120s")
	viper.SetDefault("output.name", "stdout")
}

func makeDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		viper.GetString("database.user"),
		viper.GetString("database.pass"),
		viper.GetString("database.host"),
		viper.GetUint32("database.port"),
		viper.GetString("database.dbname"))
}

func main() {
	flag.Parse()
	viper.SetConfigName(*configName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath(filepath.Dir(os.Args[0]))
	var err error
	if err = viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
		} else {
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
	}

	d, err := pdns2ublib.LoadDataFromMySQL(makeDSN())
	if err != nil {
		log.Fatalf("err %v", err)
		os.Exit(-1)
	}
	var newdata bytes.Buffer
	var olddata []byte
	d.OutputConfig(&newdata)
	outfile := viper.GetString("output.name")
	if outfile != "stdout" {
		// try to read old data
		wd, _ := os.Getwd()

		if !filepath.IsAbs(outfile) {
			outfile = filepath.Join(wd, outfile)
		}
		olddata, err = ioutil.ReadFile(outfile)
		if err == nil && bytes.Compare(olddata, newdata.Bytes()) == 0 {
			// Identical
			log.Println("output data not changed")
			os.Exit(0)
		}
		if err := ioutil.WriteFile(outfile, newdata.Bytes(), 0644); err != nil {
			log.Fatalf("err %v", err)
			os.Exit(-1)
		}
		os.Exit(1)
	} else {
		os.Stdout.Write(newdata.Bytes())
		os.Exit(0)
	}

}
