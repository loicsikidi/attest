package utils

import "errors"

var ErrArgNotProvided = errors.New("argument not provided")

func OptionalArg[T any](arg []T) (T, error) {
	if len(arg) == 0 {
		var zero T
		return zero, ErrArgNotProvided
	}
	return arg[0], nil
}

func OptionalArgWithDefault[T any](defaultValue T, arg []T) T {
	val, err := OptionalArg(arg)
	if err != nil {
		return defaultValue
	}
	return val
}
