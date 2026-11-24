// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && s390x

package secretconsumer

import (
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// Linux arch/s390/include/uapi/asm/uvdevice.h; the masks use LSB0 ordering.
// Query only: no Add, Lock or Retrieve operation is performed here.
func NativeCapabilities() (Capabilities, error) {
	guest, e := os.ReadFile("/sys/firmware/uv/prot_virt_guest")
	if e != nil || strings.TrimSpace(string(guest)) != "1" {
		return Capabilities{}, fail("SE_GUEST_REQUIRED", "Run this consumer inside the intended Secure Execution guest.")
	}
	file, e := os.OpenFile("/dev/uv", os.O_RDWR, 0)
	if e != nil {
		return Capabilities{}, fail("UV_DEVICE_UNAVAILABLE", "The workload helper needs explicitly granted access to /dev/uv inside the guest.")
	}
	defer file.Close()
	info := [2]uint64{}
	cb := struct {
		Flags    uint32
		RC, RRC  uint16
		Address  uint64
		Length   uint32
		Reserved [44]byte
	}{Address: uint64(uintptr(unsafe.Pointer(&info))), Length: 16}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), 0xc0407500, uintptr(unsafe.Pointer(&cb)))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&cb)
	if errno != 0 || cb.RC != 1 {
		return Capabilities{}, fail("UV_CAPABILITIES_UNAVAILABLE", "The guest kernel could not report supported UV operations; native retrieval stays disabled.")
	}
	return Capabilities{Kernel: info[0], UV: info[1]}, nil
}
