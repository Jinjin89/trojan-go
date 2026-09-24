package common

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
)

type Error struct {
	info string
	base error
}

func (e *Error) Error() string {
	return e.info
}

func (e *Error) Base(err error) *Error {
	if err != nil {
		e.info += " | " + err.Error()
		e.base = err
	}
	return e
}

// Unwrap allows errors.Is / errors.As to see the underlying error
func (e *Error) Unwrap() error {
	return e.base
}

func NewError(info string) *Error {
	return &Error{
		info: info,
	}
}

func Must(err error) {
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}

func Must2(_ interface{}, err error) {
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}

// IsClosedError reports whether err is caused by a normal connection shutdown
// (EOF, closed connection, reset by peer, broken pipe). These are expected on
// a busy proxy and should not be logged as errors.
func IsClosedError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}
