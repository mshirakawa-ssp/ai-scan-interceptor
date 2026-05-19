package envvars

// MarkerStartLine and MarkerEndLine are the textual markers Connect uses to
// delimit its managed region in shell rc files. They live in a non-tagged file
// so they're reachable from Windows-side code (which uses them when building
// the WSL install script).
//
// These strings MUST stay byte-for-byte stable across Connect versions so an
// older binary can still strip the block written by a newer one.
const (
	MarkerStartLine = "# >>> ai-scan-connect managed block (DO NOT EDIT) v1 >>>"
	MarkerEndLine   = "# <<< ai-scan-connect managed block <<<"
)
