package main

import (
	"fmt"

	ewf "github.com/laenix/ewfgo"
)

func main() {
	filename := "E:\\取证\\PC.E01"
	if ewf.IsEWFFile(filename) {
		ewfimage := ewf.NewWithFilePath(filename)
		ewfimage.Parse()
		for _, section := range ewfimage.Sections {
			fmt.Println(section.SectionTypeDefinition)
		}
	}
}
