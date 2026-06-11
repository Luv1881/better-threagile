/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package examples

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func CreateExampleModelFile(appFolder, outputDir, inputFile string) error {
	err := copyFile(filepath.Join(appFolder, "threagile-example-model.yaml"), filepath.Join(outputDir, "threagile-example-model.yaml"))
	if err == nil {
		return nil
	}

	altError := copyFile(filepath.Join(appFolder, inputFile), filepath.Join(outputDir, "threagile-example-model.yaml"))
	if altError != nil {
		return err
	}

	return nil
}

func CreateStubModelFile(appFolder, outputDir, inputFile string) error {
	err := copyFile(filepath.Join(appFolder, "threagile-stub-model.yaml"), filepath.Join(outputDir, "threagile-stub-model.yaml"))
	if err == nil {
		return nil
	}

	altError := copyFile(filepath.Join(appFolder, inputFile), filepath.Join(outputDir, "threagile-stub-model.yaml"))
	if altError != nil {
		return err
	}

	return nil
}

func CreateEditingSupportFiles(appFolder, outputDir string) error {
	schemaError := copyFile(filepath.Join(appFolder, "schema.json"), filepath.Join(outputDir, "schema.json"))
	if schemaError != nil {
		return schemaError
	}

	templateError := copyFile(filepath.Join(appFolder, "live-templates.txt"), filepath.Join(outputDir, "live-templates.txt"))
	return templateError
}

func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.Create(filepath.Clean(dst))
	if err != nil {
		return err
	}
	defer func() { _ = destination.Close() }()
	_, err = io.Copy(destination, source)
	return err
}
