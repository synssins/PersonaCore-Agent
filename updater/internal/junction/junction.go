// Package junction wraps Windows directory-junction operations.
//
// Design choices:
//
//  1. Creation uses `cmd.exe /c mklink /J`. Reparse-point encoding is
//     fiddly; mklink is Windows's own reference implementation. Junction
//     creation happens at most twice per update, so a CreateProcess is
//     negligible next to the download step. No cgo, no
//     golang.org/x/sys — the package stays zero-dep.
//
//  2. Atomic replacement uses SetFileInformationByHandle with
//     FileRenameInfoEx and POSIX semantics (kernel32, resolved via
//     LazyDLL). This is the ONLY zero-dep Windows primitive that
//     atomically replaces an existing directory reparse point:
//       * `os.Remove(dst) + os.Rename(src, dst)` leaves a window in
//         which `dst` is gone — violates SPEC-06 crash-safety.
//       * `cmd.exe /c move /Y src dst` treats a directory destination
//         as a CONTAINER and copies `src` inside it — dst is untouched.
//       * MoveFileExW(MOVEFILE_REPLACE_EXISTING) documentably fails
//         with ERROR_ACCESS_DENIED when either operand is a directory.
//     POSIX-semantics rename via SetFileInformationByHandle collapses
//     remove-then-rename into a single atomic filesystem transaction.
//
// Both success and failure paths are validated by unit tests that
// create real junctions in %TEMP%.
package junction

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// Win32 constants for SetFileInformationByHandle + FILE_RENAME_INFO with
// POSIX semantics — the only Windows primitive that atomically replaces
// an existing directory reparse point (junction) with another one on
// the same volume. MoveFileExW(MOVEFILE_REPLACE_EXISTING) fails with
// ERROR_ACCESS_DENIED when the destination is a directory; `move /Y`
// treats a directory destination as a container. POSIX rename semantics
// require Windows 10 1709+; we assert Windows-only in Replace().
//
// Refs:
//   docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfileinformationbyhandle
//   docs.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info
const (
	// FileRenameInfoEx information class (22) — enables POSIX flags.
	fileRenameInfoExClass = 22

	fileRenameFlagReplaceIfExists = 0x1
	fileRenameFlagPosixSemantics  = 0x2

	// CreateFile flags/options for opening a reparse point without
	// following it — otherwise we open the target directory instead of
	// the junction itself and rename the wrong thing.
	fileFlagBackupSemantics  uint32 = 0x02000000
	fileFlagOpenReparsePoint uint32 = 0x00200000
	// DELETE access is the minimum required for a rename.
	genericDeleteAccess uint32 = 0x00010000 // DELETE
	// Share modes so any concurrent readers (rare) don't block us.
	shareRWD uint32 = 0x1 | 0x2 | 0x4 // READ | WRITE | DELETE
	openExisting uint32 = 3
)

// kernel32 / SetFileInformationByHandle are resolved lazily so this
// package still compiles on non-Windows GOOS values (tests may be
// cross-compiled). Doing so keeps the package zero-dep — no
// golang.org/x/sys/windows import.
var (
	kernel32DLL                     = syscall.NewLazyDLL("kernel32.dll")
	procSetFileInformationByHandle  = kernel32DLL.NewProc("SetFileInformationByHandle")
)

// atomicRenameOverJunction opens `staged` for DELETE without following
// its reparse point, then calls SetFileInformationByHandle with
// FileRenameInfoEx + POSIX_SEMANTICS to atomically rename it to `dst`.
// If `dst` exists (typically the previous `current` junction) it is
// replaced atomically at the filesystem-metadata level: a crash between
// two instructions leaves EITHER the old OR the new reparse point
// present at `dst`, never neither.
//
// POSIX semantics also permit renaming over an existing directory
// reparse point (classic Win32 rename refuses this), and defer any
// filename allocation until the operation is committed so no visible
// "half-there" state is possible.
func atomicRenameOverJunction(staged, dst string) error {
	stagedPtr, err := syscall.UTF16PtrFromString(staged)
	if err != nil {
		return fmt.Errorf("UTF16 staged: %w", err)
	}
	// Open the STAGED junction without following the reparse point.
	// Rename is performed on this handle.
	handle, err := syscall.CreateFile(
		stagedPtr,
		genericDeleteAccess,
		shareRWD,
		nil,
		openExisting,
		fileFlagBackupSemantics|fileFlagOpenReparsePoint,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile(%s): %w", staged, err)
	}
	defer syscall.CloseHandle(handle)

	dstU16, err := syscall.UTF16FromString(dst)
	if err != nil {
		return fmt.Errorf("UTF16 dst: %w", err)
	}
	// The dst UTF-16 code units may or may not include a trailing NUL;
	// syscall.UTF16FromString includes it. FILE_RENAME_INFO.FileNameLength
	// is the length in BYTES of the filename NOT counting the NUL.
	nameBytes := (len(dstU16) - 1) * 2

	// Layout must match Win32 FILE_RENAME_INFO (x64):
	//   offset  size  field
	//     0       4   ULONG Flags
	//     4       4   (padding — HANDLE below is 8-aligned)
	//     8       8   HANDLE RootDirectory
	//    16       4   ULONG FileNameLength
	//    20    2*N    WCHAR FileName[N]
	// The trailing WCHAR NUL from UTF16FromString is included in the
	// allocated buffer but is NOT counted in FileNameLength.
	const headerSize = 20
	buf := make([]byte, headerSize+len(dstU16)*2)
	// Flags (little-endian uint32)
	buf[0] = byte(fileRenameFlagReplaceIfExists | fileRenameFlagPosixSemantics)
	// bytes 1..7 (padding, RootDirectory = 0) already zero.
	// FileNameLength at offset 16 (little-endian uint32)
	buf[16] = byte(nameBytes)
	buf[17] = byte(nameBytes >> 8)
	buf[18] = byte(nameBytes >> 16)
	buf[19] = byte(nameBytes >> 24)
	// FileName — copy UTF-16 code units little-endian.
	for i, u := range dstU16 {
		buf[headerSize+i*2] = byte(u)
		buf[headerSize+i*2+1] = byte(u >> 8)
	}

	r1, _, e1 := procSetFileInformationByHandle.Call(
		uintptr(handle),
		uintptr(fileRenameInfoExClass),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return fmt.Errorf("SetFileInformationByHandle: %w", e1)
	}
	return nil
}

// Create creates a directory junction at linkPath pointing to targetDir.
// Both paths are absolute. targetDir must already exist. If a file or
// junction already exists at linkPath, Create returns an error — call
// Replace instead for atomic swaps.
func Create(linkPath, targetDir string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("junction.Create: only supported on windows (got %s)", runtime.GOOS)
	}
	if _, err := os.Stat(targetDir); err != nil {
		return fmt.Errorf("junction.Create: target %s: %w", targetDir, err)
	}
	if _, err := os.Lstat(linkPath); err == nil {
		return fmt.Errorf("junction.Create: %s already exists", linkPath)
	}

	absLink, err := filepath.Abs(linkPath)
	if err != nil {
		return err
	}
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}

	// mklink is a cmd builtin, not a standalone exe.
	cmd := exec.Command("cmd.exe", "/c", "mklink", "/J", absLink, absTarget)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Replace atomically swaps the junction at linkPath to point at targetDir.
//
// Strategy: create `<linkPath>.new` as a junction to targetDir, then
// call SetFileInformationByHandle with FileRenameInfoEx (info class 22)
// and the flags FILE_RENAME_FLAG_REPLACE_IF_EXISTS |
// FILE_RENAME_FLAG_POSIX_SEMANTICS. On Windows 10 1709+ (NTFS same-
// volume) this atomically renames the staged reparse point over the
// existing one at the filesystem-metadata level: at any observable
// moment `linkPath` resolves to either the old target or the new one,
// never to nothing.
//
// Why not `cmd.exe /c move /Y` (as SPEC-06 originally suggested)?
// `move` treats a directory-typed destination as a container and copies
// the source INSIDE it — the destination junction is not replaced.
// Why not MoveFileExW(MOVEFILE_REPLACE_EXISTING)? That flag is
// explicitly documented to fail with ERROR_ACCESS_DENIED when either
// operand is a directory. POSIX-semantics rename via
// SetFileInformationByHandle is the only zero-dep primitive that does
// what we need.
//
// If linkPath doesn't exist yet, we simply Create it.
//
// Crash-safety contract (SPEC-06): if this function returns an error,
// the previous `current` junction is guaranteed to still resolve to its
// original target. There is no code path that both removes the old
// junction AND fails to install the new one — the POSIX rename
// collapses those two steps into a single atomic filesystem
// transaction. On crash between any two instructions inside Replace,
// `linkPath` resolves to either the old or the new target.
func Replace(linkPath, targetDir string) error {
	if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
		return Create(linkPath, targetDir)
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("junction.Replace: only supported on windows (got %s)", runtime.GOOS)
	}
	stagedName := linkPath + ".new"
	_ = os.Remove(stagedName) // clean any leftover from a prior aborted swap
	if err := Create(stagedName, targetDir); err != nil {
		return err
	}
	absLink, err := filepath.Abs(linkPath)
	if err != nil {
		_ = os.Remove(stagedName)
		return err
	}
	absStaged, err := filepath.Abs(stagedName)
	if err != nil {
		_ = os.Remove(stagedName)
		return err
	}
	if err := atomicRenameOverJunction(absStaged, absLink); err != nil {
		_ = os.Remove(stagedName)
		return fmt.Errorf("junction.Replace: atomic rename %s -> %s: %w",
			stagedName, linkPath, err)
	}
	return nil
}

// ReadTarget returns the target of the junction at linkPath, or an
// error if linkPath is not a symlink/junction. Used by tests.
func ReadTarget(linkPath string) (string, error) {
	target, err := os.Readlink(linkPath)
	if err != nil {
		return "", err
	}
	// Windows Readlink returns paths with \??\ prefix for junctions.
	target = strings.TrimPrefix(target, `\??\`)
	return target, nil
}
