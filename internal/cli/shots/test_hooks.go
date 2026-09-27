package shots

import (
	"context"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/screenshots"
)

// SetFrameFunc replaces the frame implementation for tests.
// It returns a restore function to reset the previous handler.
func SetFrameFunc(fn func(context.Context, screenshots.FrameRequest) (*screenshots.FrameResult, error)) func() {
	previous := shotsFrameFn
	if fn == nil {
		shotsFrameFn = screenshots.Frame
	} else {
		shotsFrameFn = fn
	}
	return func() {
		shotsFrameFn = previous
	}
}

// SetFrameOutputFoldsCase forces whether --input-dir treats output names as
// case-insensitive, for tests. It returns a restore function.
func SetFrameOutputFoldsCase(fold bool) func() {
	previous := frameOutputFoldsCaseFn
	frameOutputFoldsCaseFn = func(string) bool { return fold }
	return func() {
		frameOutputFoldsCaseFn = previous
	}
}
