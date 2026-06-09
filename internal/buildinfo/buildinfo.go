// Package buildinfo хранит версию и номер сборки.
// Значения подставляются при сборке через -ldflags -X.
package buildinfo

var (
	Version = "dev" // версия (тег)
	Build   = "0"   // номер сборки
)
