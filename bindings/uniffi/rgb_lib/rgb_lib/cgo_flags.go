//go:build !windows

package rgb_lib

/*
#cgo LDFLAGS: -L${SRCDIR} -lrgblibuniffi
#cgo darwin LDFLAGS: -Wl,-rpath,${SRCDIR}
#cgo linux LDFLAGS: -Wl,-rpath,${SRCDIR}
*/
import "C"
