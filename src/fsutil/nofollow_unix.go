//go:build !windows

package fsutil

import "syscall"

const noFollow = syscall.O_NOFOLLOW
