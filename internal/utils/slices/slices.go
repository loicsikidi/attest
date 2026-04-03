package slices

import (
	"fmt"
	"strconv"
)

func Convert[T, U any](slice []T, fn func(T) U) []U {
	result := make([]U, len(slice))
	for i, v := range slice {
		result[i] = fn(v)
	}
	return result
}

func IntToUint(slice []int) []uint {
	return Convert(slice, func(i int) uint {
		return uint(i)
	})
}

func UintToInt(slice []uint) []int {
	return Convert(slice, func(u uint) int {
		return int(u)
	})
}

func UintToString(slice []uint) []string {
	return Convert(slice, func(u uint) string {
		return strconv.FormatUint(uint64(u), 10)
	})
}

func ConvertWithError[T, U any](slice []T, fn func(T) (U, error)) ([]U, error) {
	result := make([]U, len(slice))
	for i, v := range slice {
		converted, err := fn(v)
		if err != nil {
			return nil, fmt.Errorf("error converting element %d: %w", i, err)
		}
		result[i] = converted
	}
	return result, nil
}

// RemoveFromSlice makes a copy of the slice and removes the passed in values from the copy.
func RemoveFromSlice[T comparable](slice []T, toRemove ...T) []T {
	if len(slice) == 0 || len(toRemove) == 0 {
		result := make([]T, len(slice))
		copy(result, slice)
		return result
	}

	removeMap := make(map[T]struct{}, len(toRemove))
	for _, item := range toRemove {
		removeMap[item] = struct{}{}
	}

	result := make([]T, 0, len(slice))
	for _, item := range slice {
		if _, shouldRemove := removeMap[item]; !shouldRemove {
			result = append(result, item)
		}
	}

	return result
}

func Map[T, S any](items []T, fn func(T) S) []S {
	result := make([]S, len(items))
	for i, item := range items {
		result[i] = fn(item)
	}
	return result
}

func Reduce[T, S any](items []T, initial S, fn func(S, T) S) S {
	result := initial
	for _, item := range items {
		result = fn(result, item)
	}
	return result
}
