package utils_test

import (
	"slices"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/attest/internal/utils"
)

type TestCase[T any] struct {
	name string
	args []T
	want T
}

func TestOptionalArg(t *testing.T) {
	t.Parallel()
	tint := []TestCase[int]{
		{
			name: "argument provided",
			args: []int{42},
			want: 42,
		},
		{
			name: "argument not provided",
			args: []int{},
			want: 0,
		},
	}
	talgid := []TestCase[tpm2.TPMAlgID]{
		{
			name: "argument provided",
			args: []tpm2.TPMAlgID{tpm2.TPMAlgAES},
			want: tpm2.TPMAlgAES,
		},
		{
			name: "argument not provided",
			args: []tpm2.TPMAlgID{},
			want: 0,
		},
	}
	tslice := []TestCase[[]int]{
		{
			name: "argument provided",
			args: [][]int{{1, 2, 3}, {4, 5, 6}},
			want: []int{1, 2, 3},
		},
		{
			name: "argument not provided",
			args: [][]int{},
			want: nil,
		},
	}

	testOptionalArg(t, tint)
	testOptionalArg(t, talgid)
	testOptionalArgWithSlice(t, tslice)
}

func testOptionalArg[T comparable](t *testing.T, tests []TestCase[T]) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := utils.OptionalArg(tt.args)
			if got != tt.want {
				t.Errorf("OptionalArg() = %v, want %v", got, tt.want)
			}
		})
	}
}
func testOptionalArgWithSlice[S ~[]E, E comparable](t *testing.T, tests []TestCase[S]) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := utils.OptionalArg(tt.args)
			if !slices.Equal(got, tt.want) {
				t.Errorf("OptionalArg() = %v, want %v", got, tt.want)
			}
		})
	}
}
