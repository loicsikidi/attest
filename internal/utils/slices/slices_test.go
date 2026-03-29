package slices

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestConvert(t *testing.T) {
	t.Parallel()

	t.Run("convert strings to int", func(t *testing.T) {
		t.Parallel()
		input := []string{"1", "2", "3"}
		result := Convert(input, func(s string) int {
			i, _ := strconv.Atoi(s)
			return i
		})
		expected := []int{1, 2, 3}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		input := []string{}
		result := Convert(input, func(s string) int {
			return len(s)
		})
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("convert to uppercase", func(t *testing.T) {
		t.Parallel()
		input := []string{"hello", "world"}
		result := Convert(input, strings.ToUpper)
		expected := []string{"HELLO", "WORLD"}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}

func TestIntToUint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []int
		expected []uint
	}{
		{
			name:     "positive integers",
			input:    []int{1, 2, 3, 4, 5},
			expected: []uint{1, 2, 3, 4, 5},
		},
		{
			name:     "with zeros",
			input:    []int{0, 1, 0, 2},
			expected: []uint{0, 1, 0, 2},
		},
		{
			name:     "empty slice",
			input:    []int{},
			expected: []uint{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IntToUint(tt.input)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestUintToInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []uint
		expected []int
	}{
		{
			name:     "positive integers",
			input:    []uint{1, 2, 3, 4, 5},
			expected: []int{1, 2, 3, 4, 5},
		},
		{
			name:     "with zeros",
			input:    []uint{0, 1, 0, 2},
			expected: []int{0, 1, 0, 2},
		},
		{
			name:     "empty slice",
			input:    []uint{},
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := UintToInt(tt.input)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestUintToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []uint
		expected []string
	}{
		{
			name:     "positive integers",
			input:    []uint{1, 2, 3, 42, 100},
			expected: []string{"1", "2", "3", "42", "100"},
		},
		{
			name:     "with zero",
			input:    []uint{0, 5, 0},
			expected: []string{"0", "5", "0"},
		},
		{
			name:     "empty slice",
			input:    []uint{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := UintToString(tt.input)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConvertWithError(t *testing.T) {
	t.Parallel()

	t.Run("successful conversion", func(t *testing.T) {
		t.Parallel()
		input := []string{"1", "2", "3"}
		result, err := ConvertWithError(input, func(s string) (int, error) {
			return strconv.Atoi(s)
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []int{1, 2, 3}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("conversion with error", func(t *testing.T) {
		t.Parallel()
		input := []string{"1", "invalid", "3"}
		result, err := ConvertWithError(input, func(s string) (int, error) {
			return strconv.Atoi(s)
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if result != nil {
			t.Errorf("expected nil result, got %v", result)
		}
		if !strings.Contains(err.Error(), "error converting element 1") {
			t.Errorf("error message should contain 'error converting element 1', got: %v", err.Error())
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		input := []string{}
		result, err := ConvertWithError(input, func(s string) (int, error) {
			return strconv.Atoi(s)
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}

func TestRemoveFromSlice(t *testing.T) {
	t.Parallel()

	t.Run("remove single element", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3, 4, 5}
		result := RemoveFromSlice(input, 3)
		expected := []int{1, 2, 4, 5}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
		originalInput := []int{1, 2, 3, 4, 5}
		if !reflect.DeepEqual(originalInput, input) {
			t.Errorf("input should not be modified, expected %v, got %v", originalInput, input)
		}
	})

	t.Run("remove multiple elements", func(t *testing.T) {
		t.Parallel()
		input := []string{"a", "b", "c", "d", "e"}
		result := RemoveFromSlice(input, "b", "d")
		expected := []string{"a", "c", "e"}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
		originalInput := []string{"a", "b", "c", "d", "e"}
		if !reflect.DeepEqual(originalInput, input) {
			t.Errorf("input should not be modified, expected %v, got %v", originalInput, input)
		}
	})

	t.Run("remove all occurrences", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 2, 3, 2, 4}
		result := RemoveFromSlice(input, 2)
		expected := []int{1, 3, 4}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("remove non-existent element", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3}
		result := RemoveFromSlice(input, 5)
		expected := []int{1, 2, 3}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		input := []int{}
		result := RemoveFromSlice(input, 1)
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("remove from slice with single element", func(t *testing.T) {
		t.Parallel()
		input := []int{42}
		result := RemoveFromSlice(input, 42)
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("remove nothing", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3}
		result := RemoveFromSlice(input)
		expected := []int{1, 2, 3}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
		originalInput := []int{1, 2, 3}
		if !reflect.DeepEqual(originalInput, input) {
			t.Errorf("input should not be modified, expected %v, got %v", originalInput, input)
		}
	})

	t.Run("remove all elements", func(t *testing.T) {
		t.Parallel()
		input := []int{1, 2, 3}
		result := RemoveFromSlice(input, 1, 2, 3)
		expected := []int{}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("with custom struct", func(t *testing.T) {
		t.Parallel()
		type person struct {
			name string
			age  int
		}

		input := []person{
			{name: "Alice", age: 30},
			{name: "Bob", age: 25},
			{name: "Charlie", age: 35},
		}

		result := RemoveFromSlice(input, person{name: "Bob", age: 25})
		expected := []person{
			{name: "Alice", age: 30},
			{name: "Charlie", age: 35},
		}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("preserve order", func(t *testing.T) {
		t.Parallel()
		input := []int{5, 1, 3, 8, 2, 9, 4}
		result := RemoveFromSlice(input, 3, 9)
		expected := []int{5, 1, 8, 2, 4}
		if !reflect.DeepEqual(expected, result) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}
