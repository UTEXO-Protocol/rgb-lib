package rgb_lib

// #include <rgb_lib.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

// C.RustBuffer fields exposed as an interface so they can be accessed in different Go packages.
// See https://github.com/golang/go/issues/13467
type ExternalCRustBuffer interface {
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromC(b C.RustBuffer) ExternalCRustBuffer {
	return GoRustBuffer{
		inner: b,
	}
}

func CFromRustBuffer(b ExternalCRustBuffer) C.RustBuffer {
	return C.RustBuffer{
		capacity: C.uint64_t(b.Capacity()),
		len:      C.uint64_t(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func RustBufferFromExternal(b ExternalCRustBuffer) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_rgblibuniffi_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_rgblibuniffi_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter BufReader[E], callback func(*C.RustCallStatus) U) (U, E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[E], status C.RustCallStatus) E {
	switch status.code {
	case 0:
		var zero E
		return zero
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 30
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_rgblibuniffi_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("rgb_lib: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_func_generate_keys()
		})
		if checksum != 63042 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_func_generate_keys: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_func_restore_backup()
		})
		if checksum != 4743 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_func_restore_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_func_restore_from_vss()
		})
		if checksum != 44861 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_func_restore_from_vss: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_func_restore_keys()
		})
		if checksum != 2392 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_func_restore_keys: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_func_script_hex_from_recipient_id()
		})
		if checksum != 59753 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_func_script_hex_from_recipient_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_func_validate_consignment()
		})
		if checksum != 1840 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_func_validate_consignment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_func_validate_consignment_offchain()
		})
		if checksum != 14655 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_func_validate_consignment_offchain: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_cosigner_cosigner_data()
		})
		if checksum != 1643 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_cosigner_cosigner_data: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_cosigner_cosigner_string()
		})
		if checksum != 41862 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_cosigner_cosigner_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_invoice_invoice_data()
		})
		if checksum != 9066 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_invoice_invoice_data: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_invoice_invoice_string()
		})
		if checksum != 26609 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_invoice_invoice_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_backup()
		})
		if checksum != 42548 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_backup_info()
		})
		if checksum != 2266 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_backup_info: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_blind_receive()
		})
		if checksum != 36277 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_blind_receive: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_burn_init()
		})
		if checksum != 21469 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_burn_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_configure_vss_backup()
		})
		if checksum != 22727 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_configure_vss_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_create_utxos_init()
		})
		if checksum != 30968 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_create_utxos_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_delete_transfers()
		})
		if checksum != 40748 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_delete_transfers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_disable_vss_auto_backup()
		})
		if checksum != 17112 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_disable_vss_auto_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_fail_transfers()
		})
		if checksum != 35998 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_fail_transfers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_finalize_psbt()
		})
		if checksum != 5884 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_finalize_psbt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_address()
		})
		if checksum != 56936 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_address: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_asset_balance()
		})
		if checksum != 14712 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_asset_balance: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_asset_metadata()
		})
		if checksum != 50236 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_asset_metadata: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_btc_balance()
		})
		if checksum != 49406 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_btc_balance: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_descriptors()
		})
		if checksum != 20698 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_descriptors: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_fee_estimation()
		})
		if checksum != 65015 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_fee_estimation: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_keys()
		})
		if checksum != 42699 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_keys: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_local_last_processed_operation_idx()
		})
		if checksum != 35330 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_local_last_processed_operation_idx: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_media_dir()
		})
		if checksum != 54414 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_media_dir: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_wallet_data()
		})
		if checksum != 22080 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_wallet_data: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_get_wallet_dir()
		})
		if checksum != 50443 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_get_wallet_dir: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_go_online()
		})
		if checksum != 1758 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_go_online: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_hub_info()
		})
		if checksum != 13471 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_hub_info: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_inflate_init()
		})
		if checksum != 46509 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_inflate_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_inspect_psbt()
		})
		if checksum != 4385 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_inspect_psbt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_inspect_rgb_transfer()
		})
		if checksum != 34229 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_inspect_rgb_transfer: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_cfa()
		})
		if checksum != 44678 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_cfa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_ifa()
		})
		if checksum != 14808 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_ifa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_nia()
		})
		if checksum != 24678 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_nia: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_uda()
		})
		if checksum != 48866 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_issue_asset_uda: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_list_assets()
		})
		if checksum != 323 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_list_assets: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_list_transactions()
		})
		if checksum != 65474 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_list_transactions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_list_transfers()
		})
		if checksum != 19629 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_list_transfers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_list_unspents()
		})
		if checksum != 12847 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_list_unspents: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_refresh()
		})
		if checksum != 55834 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_refresh: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_respond_to_operation()
		})
		if checksum != 62160 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_respond_to_operation: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_send_btc_init()
		})
		if checksum != 36072 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_send_btc_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_send_init()
		})
		if checksum != 62562 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_send_init: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_sync()
		})
		if checksum != 33649 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_sync: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_sync_with_hub()
		})
		if checksum != 51547 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_sync_with_hub: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_vss_backup()
		})
		if checksum != 4593 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_vss_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_vss_backup_info()
		})
		if checksum != 42573 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_vss_backup_info: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_multisigwallet_witness_receive()
		})
		if checksum != 5941 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_multisigwallet_witness_receive: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_recipientinfo_network()
		})
		if checksum != 1417 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_recipientinfo_network: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_recipientinfo_recipient_type()
		})
		if checksum != 32592 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_recipientinfo_recipient_type: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_transportendpoint_transport_type()
		})
		if checksum != 38302 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_transportendpoint_transport_type: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_vssbackupclient_delete_backup()
		})
		if checksum != 31430 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_vssbackupclient_delete_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_vssbackupclient_encryption_enabled()
		})
		if checksum != 58799 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_vssbackupclient_encryption_enabled: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_abort_pending_vanilla_tx()
		})
		if checksum != 13247 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_abort_pending_vanilla_tx: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_backup()
		})
		if checksum != 30471 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_backup_info()
		})
		if checksum != 41657 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_backup_info: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_blind_receive()
		})
		if checksum != 893 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_blind_receive: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_burn()
		})
		if checksum != 22805 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_burn: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_burn_begin()
		})
		if checksum != 57754 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_burn_begin: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_burn_end()
		})
		if checksum != 11483 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_burn_end: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_color_psbt_and_consume()
		})
		if checksum != 7177 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_color_psbt_and_consume: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_color_psbt_for_outpoints_and_consume()
		})
		if checksum != 35916 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_color_psbt_for_outpoints_and_consume: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_configure_vss_backup()
		})
		if checksum != 25515 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_configure_vss_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_contract_assignments_for_outpoints()
		})
		if checksum != 54689 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_contract_assignments_for_outpoints: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_create_utxos()
		})
		if checksum != 17853 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_create_utxos: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_create_utxos_begin()
		})
		if checksum != 59037 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_create_utxos_begin: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_create_utxos_end()
		})
		if checksum != 56607 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_create_utxos_end: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_delete_transfers()
		})
		if checksum != 10688 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_delete_transfers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_disable_vss_auto_backup()
		})
		if checksum != 51650 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_disable_vss_auto_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_drain_to()
		})
		if checksum != 25593 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_drain_to: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_drain_to_begin()
		})
		if checksum != 28912 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_drain_to_begin: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_drain_to_end()
		})
		if checksum != 57158 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_drain_to_end: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_fail_transfers()
		})
		if checksum != 51416 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_fail_transfers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_fetch_and_accept_transfer_by_recipient_id()
		})
		if checksum != 28469 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_fetch_and_accept_transfer_by_recipient_id: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_finalize_psbt()
		})
		if checksum != 20458 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_finalize_psbt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_address()
		})
		if checksum != 12087 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_address: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_asset_balance()
		})
		if checksum != 55514 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_asset_balance: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_asset_metadata()
		})
		if checksum != 20601 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_asset_metadata: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_btc_balance()
		})
		if checksum != 40234 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_btc_balance: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_descriptors()
		})
		if checksum != 12098 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_descriptors: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_fee_estimation()
		})
		if checksum != 11189 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_fee_estimation: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_keys()
		})
		if checksum != 2773 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_keys: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_media_dir()
		})
		if checksum != 44399 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_media_dir: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_wallet_data()
		})
		if checksum != 6456 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_wallet_data: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_get_wallet_dir()
		})
		if checksum != 29077 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_get_wallet_dir: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_go_online()
		})
		if checksum != 7516 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_go_online: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_inflate()
		})
		if checksum != 1580 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_inflate: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_inflate_begin()
		})
		if checksum != 14627 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_inflate_begin: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_inflate_end()
		})
		if checksum != 38888 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_inflate_end: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_inspect_psbt()
		})
		if checksum != 58723 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_inspect_psbt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_inspect_rgb_transfer()
		})
		if checksum != 6432 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_inspect_rgb_transfer: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_cfa()
		})
		if checksum != 22119 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_cfa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_ifa()
		})
		if checksum != 50733 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_ifa: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_nia()
		})
		if checksum != 36451 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_nia: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_uda()
		})
		if checksum != 30524 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_issue_asset_uda: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_list_assets()
		})
		if checksum != 51413 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_list_assets: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_list_pending_vanilla_txs()
		})
		if checksum != 31555 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_list_pending_vanilla_txs: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_list_transactions()
		})
		if checksum != 41427 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_list_transactions: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_list_transfers()
		})
		if checksum != 1523 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_list_transfers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_list_unspents()
		})
		if checksum != 51361 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_list_unspents: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_refresh()
		})
		if checksum != 61884 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_refresh: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_rotate_colored_address()
		})
		if checksum != 27482 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_rotate_colored_address: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_rotate_vanilla_address()
		})
		if checksum != 19346 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_rotate_vanilla_address: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_send()
		})
		if checksum != 40886 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_send: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_send_begin()
		})
		if checksum != 16093 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_send_begin: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_send_btc()
		})
		if checksum != 62052 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_send_btc: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_send_btc_begin()
		})
		if checksum != 53025 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_send_btc_begin: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_send_btc_end()
		})
		if checksum != 49705 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_send_btc_end: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_send_end()
		})
		if checksum != 13068 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_send_end: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_sign_psbt()
		})
		if checksum != 30879 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_sign_psbt: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_sync()
		})
		if checksum != 26651 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_sync: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_vss_backup()
		})
		if checksum != 11257 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_vss_backup: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_vss_backup_info()
		})
		if checksum != 27393 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_vss_backup_info: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_method_wallet_witness_receive()
		})
		if checksum != 40343 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_method_wallet_witness_receive: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_address_new()
		})
		if checksum != 14676 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_address_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_cosigner_from_data()
		})
		if checksum != 29537 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_cosigner_from_data: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_cosigner_new()
		})
		if checksum != 55714 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_cosigner_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_invoice_new()
		})
		if checksum != 33585 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_invoice_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_multisigwallet_new()
		})
		if checksum != 12203 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_multisigwallet_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_recipientinfo_new()
		})
		if checksum != 56664 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_recipientinfo_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_transportendpoint_new()
		})
		if checksum != 38802 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_transportendpoint_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_vssbackupclient_new()
		})
		if checksum != 26908 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_vssbackupclient_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_rgblibuniffi_checksum_constructor_wallet_new()
		})
		if checksum != 27138 {
			// If this happens try cleaning and rebuilding your project
			panic("rgb_lib: uniffi_rgblibuniffi_checksum_constructor_wallet_new: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint8 struct{}

var FfiConverterUint8INSTANCE = FfiConverterUint8{}

func (FfiConverterUint8) Lower(value uint8) C.uint8_t {
	return C.uint8_t(value)
}

func (FfiConverterUint8) Write(writer io.Writer, value uint8) {
	writeUint8(writer, value)
}

func (FfiConverterUint8) Lift(value C.uint8_t) uint8 {
	return uint8(value)
}

func (FfiConverterUint8) Read(reader io.Reader) uint8 {
	return readUint8(reader)
}

type FfiDestroyerUint8 struct{}

func (FfiDestroyerUint8) Destroy(_ uint8) {}

type FfiConverterUint16 struct{}

var FfiConverterUint16INSTANCE = FfiConverterUint16{}

func (FfiConverterUint16) Lower(value uint16) C.uint16_t {
	return C.uint16_t(value)
}

func (FfiConverterUint16) Write(writer io.Writer, value uint16) {
	writeUint16(writer, value)
}

func (FfiConverterUint16) Lift(value C.uint16_t) uint16 {
	return uint16(value)
}

func (FfiConverterUint16) Read(reader io.Reader) uint16 {
	return readUint16(reader)
}

type FfiDestroyerUint16 struct{}

func (FfiDestroyerUint16) Destroy(_ uint16) {}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterInt32 struct{}

var FfiConverterInt32INSTANCE = FfiConverterInt32{}

func (FfiConverterInt32) Lower(value int32) C.int32_t {
	return C.int32_t(value)
}

func (FfiConverterInt32) Write(writer io.Writer, value int32) {
	writeInt32(writer, value)
}

func (FfiConverterInt32) Lift(value C.int32_t) int32 {
	return int32(value)
}

func (FfiConverterInt32) Read(reader io.Reader) int32 {
	return readInt32(reader)
}

type FfiDestroyerInt32 struct{}

func (FfiDestroyerInt32) Destroy(_ int32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterInt64 struct{}

var FfiConverterInt64INSTANCE = FfiConverterInt64{}

func (FfiConverterInt64) Lower(value int64) C.int64_t {
	return C.int64_t(value)
}

func (FfiConverterInt64) Write(writer io.Writer, value int64) {
	writeInt64(writer, value)
}

func (FfiConverterInt64) Lift(value C.int64_t) int64 {
	return int64(value)
}

func (FfiConverterInt64) Read(reader io.Reader) int64 {
	return readInt64(reader)
}

type FfiDestroyerInt64 struct{}

func (FfiDestroyerInt64) Destroy(_ int64) {}

type FfiConverterFloat64 struct{}

var FfiConverterFloat64INSTANCE = FfiConverterFloat64{}

func (FfiConverterFloat64) Lower(value float64) C.double {
	return C.double(value)
}

func (FfiConverterFloat64) Write(writer io.Writer, value float64) {
	writeFloat64(writer, value)
}

func (FfiConverterFloat64) Lift(value C.double) float64 {
	return float64(value)
}

func (FfiConverterFloat64) Read(reader io.Reader) float64 {
	return readFloat64(reader)
}

type FfiDestroyerFloat64 struct{}

func (FfiDestroyerFloat64) Destroy(_ float64) {}

type FfiConverterBool struct{}

var FfiConverterBoolINSTANCE = FfiConverterBool{}

func (FfiConverterBool) Lower(value bool) C.int8_t {
	if value {
		return C.int8_t(1)
	}
	return C.int8_t(0)
}

func (FfiConverterBool) Write(writer io.Writer, value bool) {
	if value {
		writeInt8(writer, 1)
	} else {
		writeInt8(writer, 0)
	}
}

func (FfiConverterBool) Lift(value C.int8_t) bool {
	return value != 0
}

func (FfiConverterBool) Read(reader io.Reader) bool {
	return readInt8(reader) != 0
}

type FfiDestroyerBool struct{}

func (FfiDestroyerBool) Destroy(_ bool) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (c FfiConverterString) LowerExternal(value string) ExternalCRustBuffer {
	return RustBufferFromC(stringToRustBuffer(value))
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	handle        C.uint64_t
	callCounter   atomic.Int64
	cloneFunction func(C.uint64_t, *C.RustCallStatus) C.uint64_t
	freeFunction  func(C.uint64_t, *C.RustCallStatus)
	destroyed     atomic.Bool
}

func newFfiObject(
	handle C.uint64_t,
	cloneFunction func(C.uint64_t, *C.RustCallStatus) C.uint64_t,
	freeFunction func(C.uint64_t, *C.RustCallStatus),
) FfiObject {
	return FfiObject{
		handle:        handle,
		cloneFunction: cloneFunction,
		freeFunction:  freeFunction,
	}
}

func (ffiObject *FfiObject) incrementPointer(debugName string) C.uint64_t {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return rustCall(func(status *C.RustCallStatus) C.uint64_t {
		return ffiObject.cloneFunction(ffiObject.handle, status)
	})
}

func (ffiObject *FfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject) freeRustArcPtr() {
	if ffiObject.handle == 0 {
		return
	}
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.handle, status)
		return 0
	})
}

type AddressInterface interface {
}
type Address struct {
	ffiObject FfiObject
}

func NewAddress(addressString string, bitcoinNetwork BitcoinNetwork) (*Address, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_address_new(FfiConverterStringINSTANCE.Lower(addressString), FfiConverterBitcoinNetworkINSTANCE.Lower(bitcoinNetwork), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Address
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAddressINSTANCE.Lift(_uniffiRV), nil
	}
}

func (object *Address) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterAddress struct{}

var FfiConverterAddressINSTANCE = FfiConverterAddress{}

func (c FfiConverterAddress) Lift(handle C.uint64_t) *Address {
	result := &Address{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_address(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_address(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Address).Destroy)
	return result
}

func (c FfiConverterAddress) Read(reader io.Reader) *Address {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterAddress) Lower(value *Address) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Address")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterAddress) Write(writer io.Writer, value *Address) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalAddress(handle uint64) *Address {
	return FfiConverterAddressINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalAddress(value *Address) uint64 {
	return uint64(FfiConverterAddressINSTANCE.Lower(value))
}

type FfiDestroyerAddress struct{}

func (_ FfiDestroyerAddress) Destroy(value *Address) {
	value.Destroy()
}

type CosignerInterface interface {
	CosignerData() CosignerData
	CosignerString() string
}
type Cosigner struct {
	ffiObject FfiObject
}

func NewCosigner(cosignerString string) (*Cosigner, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_cosigner_new(FfiConverterStringINSTANCE.Lower(cosignerString), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Cosigner
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterCosignerINSTANCE.Lift(_uniffiRV), nil
	}
}

func CosignerFromData(data CosignerData) (*Cosigner, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_cosigner_from_data(FfiConverterCosignerDataINSTANCE.Lower(data), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Cosigner
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterCosignerINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Cosigner) CosignerData() CosignerData {
	_pointer := _self.ffiObject.incrementPointer("*Cosigner")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterCosignerDataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_cosigner_cosigner_data(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *Cosigner) CosignerString() string {
	_pointer := _self.ffiObject.incrementPointer("*Cosigner")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_cosigner_cosigner_string(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *Cosigner) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterCosigner struct{}

var FfiConverterCosignerINSTANCE = FfiConverterCosigner{}

func (c FfiConverterCosigner) Lift(handle C.uint64_t) *Cosigner {
	result := &Cosigner{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_cosigner(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_cosigner(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Cosigner).Destroy)
	return result
}

func (c FfiConverterCosigner) Read(reader io.Reader) *Cosigner {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterCosigner) Lower(value *Cosigner) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Cosigner")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterCosigner) Write(writer io.Writer, value *Cosigner) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalCosigner(handle uint64) *Cosigner {
	return FfiConverterCosignerINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalCosigner(value *Cosigner) uint64 {
	return uint64(FfiConverterCosignerINSTANCE.Lower(value))
}

type FfiDestroyerCosigner struct{}

func (_ FfiDestroyerCosigner) Destroy(value *Cosigner) {
	value.Destroy()
}

type InvoiceInterface interface {
	InvoiceData() InvoiceData
	InvoiceString() string
}
type Invoice struct {
	ffiObject FfiObject
}

func NewInvoice(invoiceString string) (*Invoice, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_invoice_new(FfiConverterStringINSTANCE.Lower(invoiceString), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Invoice
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInvoiceINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Invoice) InvoiceData() InvoiceData {
	_pointer := _self.ffiObject.incrementPointer("*Invoice")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterInvoiceDataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_invoice_invoice_data(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *Invoice) InvoiceString() string {
	_pointer := _self.ffiObject.incrementPointer("*Invoice")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_invoice_invoice_string(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *Invoice) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterInvoice struct{}

var FfiConverterInvoiceINSTANCE = FfiConverterInvoice{}

func (c FfiConverterInvoice) Lift(handle C.uint64_t) *Invoice {
	result := &Invoice{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_invoice(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_invoice(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Invoice).Destroy)
	return result
}

func (c FfiConverterInvoice) Read(reader io.Reader) *Invoice {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterInvoice) Lower(value *Invoice) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Invoice")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterInvoice) Write(writer io.Writer, value *Invoice) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalInvoice(handle uint64) *Invoice {
	return FfiConverterInvoiceINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalInvoice(value *Invoice) uint64 {
	return uint64(FfiConverterInvoiceINSTANCE.Lower(value))
}

type FfiDestroyerInvoice struct{}

func (_ FfiDestroyerInvoice) Destroy(value *Invoice) {
	value.Destroy()
}

type MultisigWalletInterface interface {
	Backup(backupPath string, password string) error
	BackupInfo() (bool, error)
	BlindReceive(online Online, assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error)
	BurnInit(online Online, assetId string, amount uint64, feeRate uint64, minConfirmations uint8) (InitOperationResult, error)
	ConfigureVssBackup(config VssBackupConfig) error
	CreateUtxosInit(online Online, upTo bool, num *uint8, size *uint32, feeRate uint64, skipSync bool) (InitOperationResult, error)
	DeleteTransfers(batchTransferIdx *int32, noAssetOnly bool) (bool, error)
	DisableVssAutoBackup()
	FailTransfers(online Online, batchTransferIdx *int32, noAssetOnly bool, skipSync bool) (bool, error)
	FinalizePsbt(signedPsbt string) (string, error)
	GetAddress(online Online) (string, error)
	GetAssetBalance(assetId string) (Balance, error)
	GetAssetMetadata(assetId string) (Metadata, error)
	GetBtcBalance(online *Online, skipSync bool) (BtcBalance, error)
	GetDescriptors() WalletDescriptors
	GetFeeEstimation(online Online, blocks uint16) (float64, error)
	GetKeys() MultisigKeys
	GetLocalLastProcessedOperationIdx() (int32, error)
	GetMediaDir() string
	GetWalletData() WalletData
	GetWalletDir() string
	GoOnline(onlineOptions OnlineOptions, multisigOnlineOptions MultisigOnlineOptions) (Online, error)
	HubInfo(online Online) (HubInfo, error)
	InflateInit(online Online, assetId string, inflationAmounts []uint64, feeRate uint64, minConfirmations uint8) (InitOperationResult, error)
	InspectPsbt(psbt string) (PsbtInspection, error)
	InspectRgbTransfer(psbt string, fasciaPath string, entropy uint64) (RgbInspection, error)
	IssueAssetCfa(online Online, name string, details *string, precision uint8, amounts []uint64, filePath *string) (AssetCfa, error)
	IssueAssetIfa(online Online, ticker string, name string, precision uint8, amounts []uint64, inflationAmounts []uint64, rejectListUrl *string) (AssetIfa, error)
	IssueAssetNia(online Online, ticker string, name string, precision uint8, amounts []uint64) (AssetNia, error)
	IssueAssetUda(online Online, ticker string, name string, details *string, precision uint8, mediaFilePath *string, attachmentsFilePaths []string) (AssetUda, error)
	ListAssets(filterAssetSchemas []AssetSchema) (Assets, error)
	ListTransactions(online *Online, skipSync bool) ([]Transaction, error)
	ListTransfers(assetFilter AssetFilter, txid *string) ([]Transfer, error)
	ListUnspents(online *Online, settledOnly bool, skipSync bool) ([]Unspent, error)
	Refresh(online Online, assetId *string, filter []RefreshFilter, skipSync bool) (map[int32]RefreshedTransfer, error)
	RespondToOperation(online Online, operationIdx int32, respondToOperation RespondToOperation) (OperationInfo, error)
	SendBtcInit(online Online, address string, amount uint64, feeRate uint64, skipSync bool) (InitOperationResult, error)
	SendInit(online Online, recipientMap map[string][]Recipient, donation bool, feeRate uint64, minConfirmations uint8, expirationTimestamp *uint64) (InitOperationResult, error)
	Sync(online Online, options SyncOptions) error
	SyncWithHub(online Online) (*OperationInfo, error)
	VssBackup(client *VssBackupClient) (int64, error)
	VssBackupInfo(client *VssBackupClient) (VssBackupInfo, error)
	WitnessReceive(online Online, assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error)
}
type MultisigWallet struct {
	ffiObject FfiObject
}

func NewMultisigWallet(walletData WalletData, keys MultisigKeys) (*MultisigWallet, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_multisigwallet_new(FfiConverterWalletDataINSTANCE.Lower(walletData), FfiConverterMultisigKeysINSTANCE.Lower(keys), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *MultisigWallet
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMultisigWalletINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) Backup(backupPath string, password string) error {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_multisigwallet_backup(
			_pointer, FfiConverterStringINSTANCE.Lower(backupPath), FfiConverterStringINSTANCE.Lower(password), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *MultisigWallet) BackupInfo() (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rgblibuniffi_fn_method_multisigwallet_backup_info(
			_pointer, _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBoolINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) BlindReceive(online Online, assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_blind_receive(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterOptionalStringINSTANCE.Lower(assetId), FfiConverterAssignmentINSTANCE.Lower(assignment), FfiConverterOptionalUint64INSTANCE.Lower(expirationTimestamp), FfiConverterSequenceStringINSTANCE.Lower(transportEndpoints), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ReceiveData
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterReceiveDataINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) BurnInit(online Online, assetId string, amount uint64, feeRate uint64, minConfirmations uint8) (InitOperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_burn_init(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(assetId), FfiConverterUint64INSTANCE.Lower(amount), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue InitOperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInitOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) ConfigureVssBackup(config VssBackupConfig) error {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_multisigwallet_configure_vss_backup(
			_pointer, FfiConverterVssBackupConfigINSTANCE.Lower(config), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *MultisigWallet) CreateUtxosInit(online Online, upTo bool, num *uint8, size *uint32, feeRate uint64, skipSync bool) (InitOperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_create_utxos_init(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(upTo), FfiConverterOptionalUint8INSTANCE.Lower(num), FfiConverterOptionalUint32INSTANCE.Lower(size), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue InitOperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInitOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) DeleteTransfers(batchTransferIdx *int32, noAssetOnly bool) (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rgblibuniffi_fn_method_multisigwallet_delete_transfers(
			_pointer, FfiConverterOptionalInt32INSTANCE.Lower(batchTransferIdx), FfiConverterBoolINSTANCE.Lower(noAssetOnly), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBoolINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) DisableVssAutoBackup() {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_multisigwallet_disable_vss_auto_backup(
			_pointer, _uniffiStatus)
		return false
	})
}

func (_self *MultisigWallet) FailTransfers(online Online, batchTransferIdx *int32, noAssetOnly bool, skipSync bool) (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rgblibuniffi_fn_method_multisigwallet_fail_transfers(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterOptionalInt32INSTANCE.Lower(batchTransferIdx), FfiConverterBoolINSTANCE.Lower(noAssetOnly), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBoolINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) FinalizePsbt(signedPsbt string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_finalize_psbt(
				_pointer, FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) GetAddress(online Online) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_address(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) GetAssetBalance(assetId string) (Balance, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_asset_balance(
				_pointer, FfiConverterStringINSTANCE.Lower(assetId), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Balance
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBalanceINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) GetAssetMetadata(assetId string) (Metadata, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_asset_metadata(
				_pointer, FfiConverterStringINSTANCE.Lower(assetId), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Metadata
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMetadataINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) GetBtcBalance(online *Online, skipSync bool) (BtcBalance, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_btc_balance(
				_pointer, FfiConverterOptionalOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BtcBalance
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBtcBalanceINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) GetDescriptors() WalletDescriptors {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterWalletDescriptorsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_descriptors(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *MultisigWallet) GetFeeEstimation(online Online, blocks uint16) (float64, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.double {
		return C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_fee_estimation(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterUint16INSTANCE.Lower(blocks), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue float64
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterFloat64INSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) GetKeys() MultisigKeys {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterMultisigKeysINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_keys(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *MultisigWallet) GetLocalLastProcessedOperationIdx() (int32, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int32_t {
		return C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_local_last_processed_operation_idx(
			_pointer, _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue int32
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInt32INSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) GetMediaDir() string {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_media_dir(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *MultisigWallet) GetWalletData() WalletData {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterWalletDataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_wallet_data(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *MultisigWallet) GetWalletDir() string {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_get_wallet_dir(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *MultisigWallet) GoOnline(onlineOptions OnlineOptions, multisigOnlineOptions MultisigOnlineOptions) (Online, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_go_online(
				_pointer, FfiConverterOnlineOptionsINSTANCE.Lower(onlineOptions), FfiConverterMultisigOnlineOptionsINSTANCE.Lower(multisigOnlineOptions), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Online
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOnlineINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) HubInfo(online Online) (HubInfo, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_hub_info(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue HubInfo
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterHubInfoINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) InflateInit(online Online, assetId string, inflationAmounts []uint64, feeRate uint64, minConfirmations uint8) (InitOperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_inflate_init(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(assetId), FfiConverterSequenceUint64INSTANCE.Lower(inflationAmounts), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue InitOperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInitOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) InspectPsbt(psbt string) (PsbtInspection, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_inspect_psbt(
				_pointer, FfiConverterStringINSTANCE.Lower(psbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue PsbtInspection
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterPsbtInspectionINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) InspectRgbTransfer(psbt string, fasciaPath string, entropy uint64) (RgbInspection, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_inspect_rgb_transfer(
				_pointer, FfiConverterStringINSTANCE.Lower(psbt), FfiConverterStringINSTANCE.Lower(fasciaPath), FfiConverterUint64INSTANCE.Lower(entropy), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue RgbInspection
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterRgbInspectionINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) IssueAssetCfa(online Online, name string, details *string, precision uint8, amounts []uint64, filePath *string) (AssetCfa, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_issue_asset_cfa(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(name), FfiConverterOptionalStringINSTANCE.Lower(details), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterSequenceUint64INSTANCE.Lower(amounts), FfiConverterOptionalStringINSTANCE.Lower(filePath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetCfa
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetCfaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) IssueAssetIfa(online Online, ticker string, name string, precision uint8, amounts []uint64, inflationAmounts []uint64, rejectListUrl *string) (AssetIfa, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_issue_asset_ifa(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(ticker), FfiConverterStringINSTANCE.Lower(name), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterSequenceUint64INSTANCE.Lower(amounts), FfiConverterSequenceUint64INSTANCE.Lower(inflationAmounts), FfiConverterOptionalStringINSTANCE.Lower(rejectListUrl), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetIfa
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetIfaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) IssueAssetNia(online Online, ticker string, name string, precision uint8, amounts []uint64) (AssetNia, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_issue_asset_nia(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(ticker), FfiConverterStringINSTANCE.Lower(name), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterSequenceUint64INSTANCE.Lower(amounts), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetNia
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetNiaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) IssueAssetUda(online Online, ticker string, name string, details *string, precision uint8, mediaFilePath *string, attachmentsFilePaths []string) (AssetUda, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_issue_asset_uda(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(ticker), FfiConverterStringINSTANCE.Lower(name), FfiConverterOptionalStringINSTANCE.Lower(details), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterOptionalStringINSTANCE.Lower(mediaFilePath), FfiConverterSequenceStringINSTANCE.Lower(attachmentsFilePaths), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetUda
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetUdaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) ListAssets(filterAssetSchemas []AssetSchema) (Assets, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_list_assets(
				_pointer, FfiConverterSequenceAssetSchemaINSTANCE.Lower(filterAssetSchemas), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Assets
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetsINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) ListTransactions(online *Online, skipSync bool) ([]Transaction, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_list_transactions(
				_pointer, FfiConverterOptionalOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Transaction
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceTransactionINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) ListTransfers(assetFilter AssetFilter, txid *string) ([]Transfer, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_list_transfers(
				_pointer, FfiConverterAssetFilterINSTANCE.Lower(assetFilter), FfiConverterOptionalStringINSTANCE.Lower(txid), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Transfer
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceTransferINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) ListUnspents(online *Online, settledOnly bool, skipSync bool) ([]Unspent, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_list_unspents(
				_pointer, FfiConverterOptionalOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(settledOnly), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Unspent
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUnspentINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) Refresh(online Online, assetId *string, filter []RefreshFilter, skipSync bool) (map[int32]RefreshedTransfer, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_refresh(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterOptionalStringINSTANCE.Lower(assetId), FfiConverterSequenceRefreshFilterINSTANCE.Lower(filter), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue map[int32]RefreshedTransfer
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMapInt32RefreshedTransferINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) RespondToOperation(online Online, operationIdx int32, respondToOperation RespondToOperation) (OperationInfo, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_respond_to_operation(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterInt32INSTANCE.Lower(operationIdx), FfiConverterRespondToOperationINSTANCE.Lower(respondToOperation), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue OperationInfo
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOperationInfoINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) SendBtcInit(online Online, address string, amount uint64, feeRate uint64, skipSync bool) (InitOperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_send_btc_init(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(address), FfiConverterUint64INSTANCE.Lower(amount), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue InitOperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInitOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) SendInit(online Online, recipientMap map[string][]Recipient, donation bool, feeRate uint64, minConfirmations uint8, expirationTimestamp *uint64) (InitOperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_send_init(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterMapStringSequenceRecipientINSTANCE.Lower(recipientMap), FfiConverterBoolINSTANCE.Lower(donation), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), FfiConverterOptionalUint64INSTANCE.Lower(expirationTimestamp), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue InitOperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInitOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) Sync(online Online, options SyncOptions) error {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_multisigwallet_sync(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterSyncOptionsINSTANCE.Lower(options), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *MultisigWallet) SyncWithHub(online Online) (*OperationInfo, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_sync_with_hub(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *OperationInfo
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOptionalOperationInfoINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) VssBackup(client *VssBackupClient) (int64, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int64_t {
		return C.uniffi_rgblibuniffi_fn_method_multisigwallet_vss_backup(
			_pointer, FfiConverterVssBackupClientINSTANCE.Lower(client), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue int64
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInt64INSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) VssBackupInfo(client *VssBackupClient) (VssBackupInfo, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_vss_backup_info(
				_pointer, FfiConverterVssBackupClientINSTANCE.Lower(client), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue VssBackupInfo
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterVssBackupInfoINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *MultisigWallet) WitnessReceive(online Online, assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error) {
	_pointer := _self.ffiObject.incrementPointer("*MultisigWallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_multisigwallet_witness_receive(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterOptionalStringINSTANCE.Lower(assetId), FfiConverterAssignmentINSTANCE.Lower(assignment), FfiConverterOptionalUint64INSTANCE.Lower(expirationTimestamp), FfiConverterSequenceStringINSTANCE.Lower(transportEndpoints), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ReceiveData
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterReceiveDataINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *MultisigWallet) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterMultisigWallet struct{}

var FfiConverterMultisigWalletINSTANCE = FfiConverterMultisigWallet{}

func (c FfiConverterMultisigWallet) Lift(handle C.uint64_t) *MultisigWallet {
	result := &MultisigWallet{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_multisigwallet(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_multisigwallet(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*MultisigWallet).Destroy)
	return result
}

func (c FfiConverterMultisigWallet) Read(reader io.Reader) *MultisigWallet {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterMultisigWallet) Lower(value *MultisigWallet) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*MultisigWallet")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterMultisigWallet) Write(writer io.Writer, value *MultisigWallet) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalMultisigWallet(handle uint64) *MultisigWallet {
	return FfiConverterMultisigWalletINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalMultisigWallet(value *MultisigWallet) uint64 {
	return uint64(FfiConverterMultisigWalletINSTANCE.Lower(value))
}

type FfiDestroyerMultisigWallet struct{}

func (_ FfiDestroyerMultisigWallet) Destroy(value *MultisigWallet) {
	value.Destroy()
}

type RecipientInfoInterface interface {
	Network() BitcoinNetwork
	RecipientType() RecipientType
}
type RecipientInfo struct {
	ffiObject FfiObject
}

func NewRecipientInfo(recipientId string) (*RecipientInfo, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_recipientinfo_new(FfiConverterStringINSTANCE.Lower(recipientId), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *RecipientInfo
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterRecipientInfoINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *RecipientInfo) Network() BitcoinNetwork {
	_pointer := _self.ffiObject.incrementPointer("*RecipientInfo")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBitcoinNetworkINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_recipientinfo_network(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *RecipientInfo) RecipientType() RecipientType {
	_pointer := _self.ffiObject.incrementPointer("*RecipientInfo")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterRecipientTypeINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_recipientinfo_recipient_type(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *RecipientInfo) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterRecipientInfo struct{}

var FfiConverterRecipientInfoINSTANCE = FfiConverterRecipientInfo{}

func (c FfiConverterRecipientInfo) Lift(handle C.uint64_t) *RecipientInfo {
	result := &RecipientInfo{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_recipientinfo(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_recipientinfo(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*RecipientInfo).Destroy)
	return result
}

func (c FfiConverterRecipientInfo) Read(reader io.Reader) *RecipientInfo {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterRecipientInfo) Lower(value *RecipientInfo) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*RecipientInfo")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterRecipientInfo) Write(writer io.Writer, value *RecipientInfo) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalRecipientInfo(handle uint64) *RecipientInfo {
	return FfiConverterRecipientInfoINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalRecipientInfo(value *RecipientInfo) uint64 {
	return uint64(FfiConverterRecipientInfoINSTANCE.Lower(value))
}

type FfiDestroyerRecipientInfo struct{}

func (_ FfiDestroyerRecipientInfo) Destroy(value *RecipientInfo) {
	value.Destroy()
}

type TransportEndpointInterface interface {
	TransportType() TransportType
}
type TransportEndpoint struct {
	ffiObject FfiObject
}

func NewTransportEndpoint(transportEndpoint string) (*TransportEndpoint, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_transportendpoint_new(FfiConverterStringINSTANCE.Lower(transportEndpoint), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *TransportEndpoint
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTransportEndpointINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *TransportEndpoint) TransportType() TransportType {
	_pointer := _self.ffiObject.incrementPointer("*TransportEndpoint")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterTransportTypeINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_transportendpoint_transport_type(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *TransportEndpoint) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterTransportEndpoint struct{}

var FfiConverterTransportEndpointINSTANCE = FfiConverterTransportEndpoint{}

func (c FfiConverterTransportEndpoint) Lift(handle C.uint64_t) *TransportEndpoint {
	result := &TransportEndpoint{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_transportendpoint(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_transportendpoint(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*TransportEndpoint).Destroy)
	return result
}

func (c FfiConverterTransportEndpoint) Read(reader io.Reader) *TransportEndpoint {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterTransportEndpoint) Lower(value *TransportEndpoint) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*TransportEndpoint")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterTransportEndpoint) Write(writer io.Writer, value *TransportEndpoint) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalTransportEndpoint(handle uint64) *TransportEndpoint {
	return FfiConverterTransportEndpointINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalTransportEndpoint(value *TransportEndpoint) uint64 {
	return uint64(FfiConverterTransportEndpointINSTANCE.Lower(value))
}

type FfiDestroyerTransportEndpoint struct{}

func (_ FfiDestroyerTransportEndpoint) Destroy(value *TransportEndpoint) {
	value.Destroy()
}

type VssBackupClientInterface interface {
	DeleteBackup() error
	EncryptionEnabled() bool
}
type VssBackupClient struct {
	ffiObject FfiObject
}

func NewVssBackupClient(config VssBackupConfig) (*VssBackupClient, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_vssbackupclient_new(FfiConverterVssBackupConfigINSTANCE.Lower(config), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *VssBackupClient
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterVssBackupClientINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *VssBackupClient) DeleteBackup() error {
	_pointer := _self.ffiObject.incrementPointer("*VssBackupClient")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_vssbackupclient_delete_backup(
			_pointer, _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *VssBackupClient) EncryptionEnabled() bool {
	_pointer := _self.ffiObject.incrementPointer("*VssBackupClient")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBoolINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rgblibuniffi_fn_method_vssbackupclient_encryption_enabled(
			_pointer, _uniffiStatus)
	}))
}
func (object *VssBackupClient) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterVssBackupClient struct{}

var FfiConverterVssBackupClientINSTANCE = FfiConverterVssBackupClient{}

func (c FfiConverterVssBackupClient) Lift(handle C.uint64_t) *VssBackupClient {
	result := &VssBackupClient{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_vssbackupclient(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_vssbackupclient(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*VssBackupClient).Destroy)
	return result
}

func (c FfiConverterVssBackupClient) Read(reader io.Reader) *VssBackupClient {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterVssBackupClient) Lower(value *VssBackupClient) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*VssBackupClient")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterVssBackupClient) Write(writer io.Writer, value *VssBackupClient) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalVssBackupClient(handle uint64) *VssBackupClient {
	return FfiConverterVssBackupClientINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalVssBackupClient(value *VssBackupClient) uint64 {
	return uint64(FfiConverterVssBackupClientINSTANCE.Lower(value))
}

type FfiDestroyerVssBackupClient struct{}

func (_ FfiDestroyerVssBackupClient) Destroy(value *VssBackupClient) {
	value.Destroy()
}

type WalletInterface interface {
	AbortPendingVanillaTx(txid string) error
	Backup(backupPath string, password string) error
	BackupInfo() (bool, error)
	BlindReceive(assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error)
	Burn(online Online, assetId string, amount uint64, feeRate uint64, minConfirmations uint8) (OperationResult, error)
	BurnBegin(online Online, assetId string, amount uint64, feeRate uint64, minConfirmations uint8, dryRun bool) (BurnBeginResult, error)
	BurnEnd(online Online, signedPsbt string) (OperationResult, error)
	ColorPsbtAndConsume(psbt string, coloringInfo ColoringInfo) (ColorPsbtResult, error)
	ColorPsbtForOutpointsAndConsume(psbt string, coloringInfo ColoringInfo, inputOutpoints []Outpoint) (ColorPsbtResult, error)
	ConfigureVssBackup(config VssBackupConfig) error
	ContractAssignmentsForOutpoints(assetId string, outpoints []Outpoint) ([]OutpointAssignments, error)
	CreateUtxos(online Online, upTo bool, num *uint8, size *uint32, feeRate uint64, skipSync bool) (uint8, error)
	CreateUtxosBegin(online Online, upTo bool, num *uint8, size *uint32, feeRate uint64, skipSync bool, dryRun bool) (string, error)
	CreateUtxosEnd(online Online, signedPsbt string) (uint8, error)
	DeleteTransfers(batchTransferIdx *int32, noAssetOnly bool) (bool, error)
	DisableVssAutoBackup()
	DrainTo(online Online, address string, feeRate uint64) (string, error)
	DrainToBegin(online Online, address string, feeRate uint64, dryRun bool) (string, error)
	DrainToEnd(online Online, signedPsbt string) (string, error)
	FailTransfers(online Online, batchTransferIdx *int32, noAssetOnly bool, skipSync bool) (bool, error)
	FetchAndAcceptTransferByRecipientId(proxyRecipientId string, witnessRecipientId string, consignmentEndpoint string, blinding uint64, minConfirmations uint8) (AcceptTransferResult, error)
	FinalizePsbt(signedPsbt string) (string, error)
	GetAddress() (string, error)
	GetAssetBalance(assetId string) (Balance, error)
	GetAssetMetadata(assetId string) (Metadata, error)
	GetBtcBalance(online *Online, skipSync bool) (BtcBalance, error)
	GetDescriptors() WalletDescriptors
	GetFeeEstimation(online Online, blocks uint16) (float64, error)
	GetKeys() SinglesigKeys
	GetMediaDir() string
	GetWalletData() WalletData
	GetWalletDir() string
	GoOnline(onlineOptions OnlineOptions) (Online, error)
	Inflate(online Online, assetId string, inflationAmounts []uint64, feeRate uint64, minConfirmations uint8) (OperationResult, error)
	InflateBegin(online Online, assetId string, inflationAmounts []uint64, feeRate uint64, minConfirmations uint8, dryRun bool) (InflateBeginResult, error)
	InflateEnd(online Online, signedPsbt string) (OperationResult, error)
	InspectPsbt(psbt string) (PsbtInspection, error)
	InspectRgbTransfer(psbt string, fasciaPath string, entropy uint64) (RgbInspection, error)
	IssueAssetCfa(name string, details *string, precision uint8, amounts []uint64, filePath *string) (AssetCfa, error)
	IssueAssetIfa(ticker string, name string, precision uint8, amounts []uint64, inflationAmounts []uint64, rejectListUrl *string) (AssetIfa, error)
	IssueAssetNia(ticker string, name string, precision uint8, amounts []uint64) (AssetNia, error)
	IssueAssetUda(ticker string, name string, details *string, precision uint8, mediaFilePath *string, attachmentsFilePaths []string) (AssetUda, error)
	ListAssets(filterAssetSchemas []AssetSchema) (Assets, error)
	ListPendingVanillaTxs() ([]PendingVanillaTx, error)
	ListTransactions(online *Online, skipSync bool) ([]Transaction, error)
	ListTransfers(assetFilter AssetFilter, txid *string) ([]Transfer, error)
	ListUnspents(online *Online, settledOnly bool, skipSync bool) ([]Unspent, error)
	Refresh(online Online, assetId *string, filter []RefreshFilter, skipSync bool) (map[int32]RefreshedTransfer, error)
	RotateColoredAddress() (string, error)
	RotateVanillaAddress() (string, error)
	Send(online Online, recipientMap map[string][]Recipient, donation bool, feeRate uint64, minConfirmations uint8, expirationTimestamp *uint64) (OperationResult, error)
	SendBegin(online Online, recipientMap map[string][]Recipient, donation bool, feeRate uint64, minConfirmations uint8, expirationTimestamp *uint64, dryRun bool) (SendBeginResult, error)
	SendBtc(online Online, address string, amount uint64, feeRate uint64, skipSync bool) (string, error)
	SendBtcBegin(online Online, address string, amount uint64, feeRate uint64, skipSync bool, dryRun bool) (string, error)
	SendBtcEnd(online Online, signedPsbt string) (string, error)
	SendEnd(online Online, signedPsbt string) (OperationResult, error)
	SignPsbt(unsignedPsbt string) (string, error)
	Sync(online Online, options SyncOptions) error
	VssBackup(client *VssBackupClient) (int64, error)
	VssBackupInfo(client *VssBackupClient) (VssBackupInfo, error)
	WitnessReceive(assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error)
}
type Wallet struct {
	ffiObject FfiObject
}

func NewWallet(walletData WalletData, keys SinglesigKeys) (*Wallet, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_rgblibuniffi_fn_constructor_wallet_new(FfiConverterWalletDataINSTANCE.Lower(walletData), FfiConverterSinglesigKeysINSTANCE.Lower(keys), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Wallet
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterWalletINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) AbortPendingVanillaTx(txid string) error {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_wallet_abort_pending_vanilla_tx(
			_pointer, FfiConverterStringINSTANCE.Lower(txid), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *Wallet) Backup(backupPath string, password string) error {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_wallet_backup(
			_pointer, FfiConverterStringINSTANCE.Lower(backupPath), FfiConverterStringINSTANCE.Lower(password), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *Wallet) BackupInfo() (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rgblibuniffi_fn_method_wallet_backup_info(
			_pointer, _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBoolINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) BlindReceive(assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_blind_receive(
				_pointer, FfiConverterOptionalStringINSTANCE.Lower(assetId), FfiConverterAssignmentINSTANCE.Lower(assignment), FfiConverterOptionalUint64INSTANCE.Lower(expirationTimestamp), FfiConverterSequenceStringINSTANCE.Lower(transportEndpoints), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ReceiveData
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterReceiveDataINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) Burn(online Online, assetId string, amount uint64, feeRate uint64, minConfirmations uint8) (OperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_burn(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(assetId), FfiConverterUint64INSTANCE.Lower(amount), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue OperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) BurnBegin(online Online, assetId string, amount uint64, feeRate uint64, minConfirmations uint8, dryRun bool) (BurnBeginResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_burn_begin(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(assetId), FfiConverterUint64INSTANCE.Lower(amount), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), FfiConverterBoolINSTANCE.Lower(dryRun), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BurnBeginResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBurnBeginResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) BurnEnd(online Online, signedPsbt string) (OperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_burn_end(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue OperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ColorPsbtAndConsume(psbt string, coloringInfo ColoringInfo) (ColorPsbtResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_color_psbt_and_consume(
				_pointer, FfiConverterStringINSTANCE.Lower(psbt), FfiConverterColoringInfoINSTANCE.Lower(coloringInfo), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ColorPsbtResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterColorPsbtResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ColorPsbtForOutpointsAndConsume(psbt string, coloringInfo ColoringInfo, inputOutpoints []Outpoint) (ColorPsbtResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_color_psbt_for_outpoints_and_consume(
				_pointer, FfiConverterStringINSTANCE.Lower(psbt), FfiConverterColoringInfoINSTANCE.Lower(coloringInfo), FfiConverterSequenceOutpointINSTANCE.Lower(inputOutpoints), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ColorPsbtResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterColorPsbtResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ConfigureVssBackup(config VssBackupConfig) error {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_wallet_configure_vss_backup(
			_pointer, FfiConverterVssBackupConfigINSTANCE.Lower(config), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *Wallet) ContractAssignmentsForOutpoints(assetId string, outpoints []Outpoint) ([]OutpointAssignments, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_contract_assignments_for_outpoints(
				_pointer, FfiConverterStringINSTANCE.Lower(assetId), FfiConverterSequenceOutpointINSTANCE.Lower(outpoints), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []OutpointAssignments
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceOutpointAssignmentsINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) CreateUtxos(online Online, upTo bool, num *uint8, size *uint32, feeRate uint64, skipSync bool) (uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint8_t {
		return C.uniffi_rgblibuniffi_fn_method_wallet_create_utxos(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(upTo), FfiConverterOptionalUint8INSTANCE.Lower(num), FfiConverterOptionalUint32INSTANCE.Lower(size), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterUint8INSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) CreateUtxosBegin(online Online, upTo bool, num *uint8, size *uint32, feeRate uint64, skipSync bool, dryRun bool) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_create_utxos_begin(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(upTo), FfiConverterOptionalUint8INSTANCE.Lower(num), FfiConverterOptionalUint32INSTANCE.Lower(size), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterBoolINSTANCE.Lower(skipSync), FfiConverterBoolINSTANCE.Lower(dryRun), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) CreateUtxosEnd(online Online, signedPsbt string) (uint8, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.uint8_t {
		return C.uniffi_rgblibuniffi_fn_method_wallet_create_utxos_end(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue uint8
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterUint8INSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) DeleteTransfers(batchTransferIdx *int32, noAssetOnly bool) (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rgblibuniffi_fn_method_wallet_delete_transfers(
			_pointer, FfiConverterOptionalInt32INSTANCE.Lower(batchTransferIdx), FfiConverterBoolINSTANCE.Lower(noAssetOnly), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBoolINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) DisableVssAutoBackup() {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	rustCall(func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_wallet_disable_vss_auto_backup(
			_pointer, _uniffiStatus)
		return false
	})
}

func (_self *Wallet) DrainTo(online Online, address string, feeRate uint64) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_drain_to(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(address), FfiConverterUint64INSTANCE.Lower(feeRate), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) DrainToBegin(online Online, address string, feeRate uint64, dryRun bool) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_drain_to_begin(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(address), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterBoolINSTANCE.Lower(dryRun), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) DrainToEnd(online Online, signedPsbt string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_drain_to_end(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) FailTransfers(online Online, batchTransferIdx *int32, noAssetOnly bool, skipSync bool) (bool, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int8_t {
		return C.uniffi_rgblibuniffi_fn_method_wallet_fail_transfers(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterOptionalInt32INSTANCE.Lower(batchTransferIdx), FfiConverterBoolINSTANCE.Lower(noAssetOnly), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue bool
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBoolINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) FetchAndAcceptTransferByRecipientId(proxyRecipientId string, witnessRecipientId string, consignmentEndpoint string, blinding uint64, minConfirmations uint8) (AcceptTransferResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_fetch_and_accept_transfer_by_recipient_id(
				_pointer, FfiConverterStringINSTANCE.Lower(proxyRecipientId), FfiConverterStringINSTANCE.Lower(witnessRecipientId), FfiConverterStringINSTANCE.Lower(consignmentEndpoint), FfiConverterUint64INSTANCE.Lower(blinding), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AcceptTransferResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAcceptTransferResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) FinalizePsbt(signedPsbt string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_finalize_psbt(
				_pointer, FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) GetAddress() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_address(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) GetAssetBalance(assetId string) (Balance, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_asset_balance(
				_pointer, FfiConverterStringINSTANCE.Lower(assetId), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Balance
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBalanceINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) GetAssetMetadata(assetId string) (Metadata, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_asset_metadata(
				_pointer, FfiConverterStringINSTANCE.Lower(assetId), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Metadata
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMetadataINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) GetBtcBalance(online *Online, skipSync bool) (BtcBalance, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_btc_balance(
				_pointer, FfiConverterOptionalOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue BtcBalance
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBtcBalanceINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) GetDescriptors() WalletDescriptors {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterWalletDescriptorsINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_descriptors(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *Wallet) GetFeeEstimation(online Online, blocks uint16) (float64, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.double {
		return C.uniffi_rgblibuniffi_fn_method_wallet_get_fee_estimation(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterUint16INSTANCE.Lower(blocks), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue float64
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterFloat64INSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) GetKeys() SinglesigKeys {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterSinglesigKeysINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_keys(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *Wallet) GetMediaDir() string {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_media_dir(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *Wallet) GetWalletData() WalletData {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterWalletDataINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_wallet_data(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *Wallet) GetWalletDir() string {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_get_wallet_dir(
				_pointer, _uniffiStatus),
		}
	}))
}

func (_self *Wallet) GoOnline(onlineOptions OnlineOptions) (Online, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_go_online(
				_pointer, FfiConverterOnlineOptionsINSTANCE.Lower(onlineOptions), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Online
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOnlineINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) Inflate(online Online, assetId string, inflationAmounts []uint64, feeRate uint64, minConfirmations uint8) (OperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_inflate(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(assetId), FfiConverterSequenceUint64INSTANCE.Lower(inflationAmounts), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue OperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) InflateBegin(online Online, assetId string, inflationAmounts []uint64, feeRate uint64, minConfirmations uint8, dryRun bool) (InflateBeginResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_inflate_begin(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(assetId), FfiConverterSequenceUint64INSTANCE.Lower(inflationAmounts), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), FfiConverterBoolINSTANCE.Lower(dryRun), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue InflateBeginResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInflateBeginResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) InflateEnd(online Online, signedPsbt string) (OperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_inflate_end(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue OperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) InspectPsbt(psbt string) (PsbtInspection, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_inspect_psbt(
				_pointer, FfiConverterStringINSTANCE.Lower(psbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue PsbtInspection
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterPsbtInspectionINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) InspectRgbTransfer(psbt string, fasciaPath string, entropy uint64) (RgbInspection, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_inspect_rgb_transfer(
				_pointer, FfiConverterStringINSTANCE.Lower(psbt), FfiConverterStringINSTANCE.Lower(fasciaPath), FfiConverterUint64INSTANCE.Lower(entropy), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue RgbInspection
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterRgbInspectionINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) IssueAssetCfa(name string, details *string, precision uint8, amounts []uint64, filePath *string) (AssetCfa, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_issue_asset_cfa(
				_pointer, FfiConverterStringINSTANCE.Lower(name), FfiConverterOptionalStringINSTANCE.Lower(details), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterSequenceUint64INSTANCE.Lower(amounts), FfiConverterOptionalStringINSTANCE.Lower(filePath), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetCfa
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetCfaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) IssueAssetIfa(ticker string, name string, precision uint8, amounts []uint64, inflationAmounts []uint64, rejectListUrl *string) (AssetIfa, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_issue_asset_ifa(
				_pointer, FfiConverterStringINSTANCE.Lower(ticker), FfiConverterStringINSTANCE.Lower(name), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterSequenceUint64INSTANCE.Lower(amounts), FfiConverterSequenceUint64INSTANCE.Lower(inflationAmounts), FfiConverterOptionalStringINSTANCE.Lower(rejectListUrl), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetIfa
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetIfaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) IssueAssetNia(ticker string, name string, precision uint8, amounts []uint64) (AssetNia, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_issue_asset_nia(
				_pointer, FfiConverterStringINSTANCE.Lower(ticker), FfiConverterStringINSTANCE.Lower(name), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterSequenceUint64INSTANCE.Lower(amounts), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetNia
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetNiaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) IssueAssetUda(ticker string, name string, details *string, precision uint8, mediaFilePath *string, attachmentsFilePaths []string) (AssetUda, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_issue_asset_uda(
				_pointer, FfiConverterStringINSTANCE.Lower(ticker), FfiConverterStringINSTANCE.Lower(name), FfiConverterOptionalStringINSTANCE.Lower(details), FfiConverterUint8INSTANCE.Lower(precision), FfiConverterOptionalStringINSTANCE.Lower(mediaFilePath), FfiConverterSequenceStringINSTANCE.Lower(attachmentsFilePaths), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue AssetUda
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetUdaINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ListAssets(filterAssetSchemas []AssetSchema) (Assets, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_list_assets(
				_pointer, FfiConverterSequenceAssetSchemaINSTANCE.Lower(filterAssetSchemas), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Assets
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAssetsINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ListPendingVanillaTxs() ([]PendingVanillaTx, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_list_pending_vanilla_txs(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []PendingVanillaTx
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequencePendingVanillaTxINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ListTransactions(online *Online, skipSync bool) ([]Transaction, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_list_transactions(
				_pointer, FfiConverterOptionalOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Transaction
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceTransactionINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ListTransfers(assetFilter AssetFilter, txid *string) ([]Transfer, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_list_transfers(
				_pointer, FfiConverterAssetFilterINSTANCE.Lower(assetFilter), FfiConverterOptionalStringINSTANCE.Lower(txid), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Transfer
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceTransferINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) ListUnspents(online *Online, settledOnly bool, skipSync bool) ([]Unspent, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_list_unspents(
				_pointer, FfiConverterOptionalOnlineINSTANCE.Lower(online), FfiConverterBoolINSTANCE.Lower(settledOnly), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []Unspent
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSequenceUnspentINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) Refresh(online Online, assetId *string, filter []RefreshFilter, skipSync bool) (map[int32]RefreshedTransfer, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_refresh(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterOptionalStringINSTANCE.Lower(assetId), FfiConverterSequenceRefreshFilterINSTANCE.Lower(filter), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue map[int32]RefreshedTransfer
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterMapInt32RefreshedTransferINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) RotateColoredAddress() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_rotate_colored_address(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) RotateVanillaAddress() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_rotate_vanilla_address(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) Send(online Online, recipientMap map[string][]Recipient, donation bool, feeRate uint64, minConfirmations uint8, expirationTimestamp *uint64) (OperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_send(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterMapStringSequenceRecipientINSTANCE.Lower(recipientMap), FfiConverterBoolINSTANCE.Lower(donation), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), FfiConverterOptionalUint64INSTANCE.Lower(expirationTimestamp), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue OperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) SendBegin(online Online, recipientMap map[string][]Recipient, donation bool, feeRate uint64, minConfirmations uint8, expirationTimestamp *uint64, dryRun bool) (SendBeginResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_send_begin(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterMapStringSequenceRecipientINSTANCE.Lower(recipientMap), FfiConverterBoolINSTANCE.Lower(donation), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterUint8INSTANCE.Lower(minConfirmations), FfiConverterOptionalUint64INSTANCE.Lower(expirationTimestamp), FfiConverterBoolINSTANCE.Lower(dryRun), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue SendBeginResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterSendBeginResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) SendBtc(online Online, address string, amount uint64, feeRate uint64, skipSync bool) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_send_btc(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(address), FfiConverterUint64INSTANCE.Lower(amount), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterBoolINSTANCE.Lower(skipSync), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) SendBtcBegin(online Online, address string, amount uint64, feeRate uint64, skipSync bool, dryRun bool) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_send_btc_begin(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(address), FfiConverterUint64INSTANCE.Lower(amount), FfiConverterUint64INSTANCE.Lower(feeRate), FfiConverterBoolINSTANCE.Lower(skipSync), FfiConverterBoolINSTANCE.Lower(dryRun), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) SendBtcEnd(online Online, signedPsbt string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_send_btc_end(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) SendEnd(online Online, signedPsbt string) (OperationResult, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_send_end(
				_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterStringINSTANCE.Lower(signedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue OperationResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOperationResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) SignPsbt(unsignedPsbt string) (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_sign_psbt(
				_pointer, FfiConverterStringINSTANCE.Lower(unsignedPsbt), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) Sync(online Online, options SyncOptions) error {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_method_wallet_sync(
			_pointer, FfiConverterOnlineINSTANCE.Lower(online), FfiConverterSyncOptionsINSTANCE.Lower(options), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func (_self *Wallet) VssBackup(client *VssBackupClient) (int64, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) C.int64_t {
		return C.uniffi_rgblibuniffi_fn_method_wallet_vss_backup(
			_pointer, FfiConverterVssBackupClientINSTANCE.Lower(client), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue int64
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInt64INSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) VssBackupInfo(client *VssBackupClient) (VssBackupInfo, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_vss_backup_info(
				_pointer, FfiConverterVssBackupClientINSTANCE.Lower(client), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue VssBackupInfo
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterVssBackupInfoINSTANCE.Lift(_uniffiRV), nil
	}
}

func (_self *Wallet) WitnessReceive(assetId *string, assignment Assignment, expirationTimestamp *uint64, transportEndpoints []string, minConfirmations uint8) (ReceiveData, error) {
	_pointer := _self.ffiObject.incrementPointer("*Wallet")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_method_wallet_witness_receive(
				_pointer, FfiConverterOptionalStringINSTANCE.Lower(assetId), FfiConverterAssignmentINSTANCE.Lower(assignment), FfiConverterOptionalUint64INSTANCE.Lower(expirationTimestamp), FfiConverterSequenceStringINSTANCE.Lower(transportEndpoints), FfiConverterUint8INSTANCE.Lower(minConfirmations), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ReceiveData
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterReceiveDataINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *Wallet) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterWallet struct{}

var FfiConverterWalletINSTANCE = FfiConverterWallet{}

func (c FfiConverterWallet) Lift(handle C.uint64_t) *Wallet {
	result := &Wallet{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_rgblibuniffi_fn_clone_wallet(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_rgblibuniffi_fn_free_wallet(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Wallet).Destroy)
	return result
}

func (c FfiConverterWallet) Read(reader io.Reader) *Wallet {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterWallet) Lower(value *Wallet) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Wallet")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterWallet) Write(writer io.Writer, value *Wallet) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalWallet(handle uint64) *Wallet {
	return FfiConverterWalletINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalWallet(value *Wallet) uint64 {
	return uint64(FfiConverterWalletINSTANCE.Lower(value))
}

type FfiDestroyerWallet struct{}

func (_ FfiDestroyerWallet) Destroy(value *Wallet) {
	value.Destroy()
}

type AcceptTransferResult struct {
	Consignment []uint8
	Assignments []Assignment
}

func (r *AcceptTransferResult) Destroy() {
	FfiDestroyerSequenceUint8{}.Destroy(r.Consignment)
	FfiDestroyerSequenceAssignment{}.Destroy(r.Assignments)
}

type FfiConverterAcceptTransferResult struct{}

var FfiConverterAcceptTransferResultINSTANCE = FfiConverterAcceptTransferResult{}

func (c FfiConverterAcceptTransferResult) Lift(rb RustBufferI) AcceptTransferResult {
	return LiftFromRustBuffer[AcceptTransferResult](c, rb)
}

func (c FfiConverterAcceptTransferResult) Read(reader io.Reader) AcceptTransferResult {
	return AcceptTransferResult{
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterSequenceAssignmentINSTANCE.Read(reader),
	}
}

func (c FfiConverterAcceptTransferResult) Lower(value AcceptTransferResult) C.RustBuffer {
	return LowerIntoRustBuffer[AcceptTransferResult](c, value)
}

func (c FfiConverterAcceptTransferResult) LowerExternal(value AcceptTransferResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AcceptTransferResult](c, value))
}

func (c FfiConverterAcceptTransferResult) Write(writer io.Writer, value AcceptTransferResult) {
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Consignment)
	FfiConverterSequenceAssignmentINSTANCE.Write(writer, value.Assignments)
}

type FfiDestroyerAcceptTransferResult struct{}

func (_ FfiDestroyerAcceptTransferResult) Destroy(value AcceptTransferResult) {
	value.Destroy()
}

type AssetCfa struct {
	AssetId      string
	Name         string
	Details      *string
	Precision    uint8
	IssuedSupply uint64
	Timestamp    int64
	AddedAt      int64
	Balance      Balance
	Media        *Media
}

func (r *AssetCfa) Destroy() {
	FfiDestroyerString{}.Destroy(r.AssetId)
	FfiDestroyerString{}.Destroy(r.Name)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
	FfiDestroyerUint8{}.Destroy(r.Precision)
	FfiDestroyerUint64{}.Destroy(r.IssuedSupply)
	FfiDestroyerInt64{}.Destroy(r.Timestamp)
	FfiDestroyerInt64{}.Destroy(r.AddedAt)
	FfiDestroyerBalance{}.Destroy(r.Balance)
	FfiDestroyerOptionalMedia{}.Destroy(r.Media)
}

type FfiConverterAssetCfa struct{}

var FfiConverterAssetCfaINSTANCE = FfiConverterAssetCfa{}

func (c FfiConverterAssetCfa) Lift(rb RustBufferI) AssetCfa {
	return LiftFromRustBuffer[AssetCfa](c, rb)
}

func (c FfiConverterAssetCfa) Read(reader io.Reader) AssetCfa {
	return AssetCfa{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterBalanceINSTANCE.Read(reader),
		FfiConverterOptionalMediaINSTANCE.Read(reader),
	}
}

func (c FfiConverterAssetCfa) Lower(value AssetCfa) C.RustBuffer {
	return LowerIntoRustBuffer[AssetCfa](c, value)
}

func (c FfiConverterAssetCfa) LowerExternal(value AssetCfa) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetCfa](c, value))
}

func (c FfiConverterAssetCfa) Write(writer io.Writer, value AssetCfa) {
	FfiConverterStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterStringINSTANCE.Write(writer, value.Name)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
	FfiConverterUint8INSTANCE.Write(writer, value.Precision)
	FfiConverterUint64INSTANCE.Write(writer, value.IssuedSupply)
	FfiConverterInt64INSTANCE.Write(writer, value.Timestamp)
	FfiConverterInt64INSTANCE.Write(writer, value.AddedAt)
	FfiConverterBalanceINSTANCE.Write(writer, value.Balance)
	FfiConverterOptionalMediaINSTANCE.Write(writer, value.Media)
}

type FfiDestroyerAssetCfa struct{}

func (_ FfiDestroyerAssetCfa) Destroy(value AssetCfa) {
	value.Destroy()
}

type AssetColoringInfo struct {
	AssetId        string
	OutputMap      map[uint32]uint64
	StaticBlinding *uint64
}

func (r *AssetColoringInfo) Destroy() {
	FfiDestroyerString{}.Destroy(r.AssetId)
	FfiDestroyerMapUint32Uint64{}.Destroy(r.OutputMap)
	FfiDestroyerOptionalUint64{}.Destroy(r.StaticBlinding)
}

type FfiConverterAssetColoringInfo struct{}

var FfiConverterAssetColoringInfoINSTANCE = FfiConverterAssetColoringInfo{}

func (c FfiConverterAssetColoringInfo) Lift(rb RustBufferI) AssetColoringInfo {
	return LiftFromRustBuffer[AssetColoringInfo](c, rb)
}

func (c FfiConverterAssetColoringInfo) Read(reader io.Reader) AssetColoringInfo {
	return AssetColoringInfo{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterMapUint32Uint64INSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterAssetColoringInfo) Lower(value AssetColoringInfo) C.RustBuffer {
	return LowerIntoRustBuffer[AssetColoringInfo](c, value)
}

func (c FfiConverterAssetColoringInfo) LowerExternal(value AssetColoringInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetColoringInfo](c, value))
}

func (c FfiConverterAssetColoringInfo) Write(writer io.Writer, value AssetColoringInfo) {
	FfiConverterStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterMapUint32Uint64INSTANCE.Write(writer, value.OutputMap)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.StaticBlinding)
}

type FfiDestroyerAssetColoringInfo struct{}

func (_ FfiDestroyerAssetColoringInfo) Destroy(value AssetColoringInfo) {
	value.Destroy()
}

type AssetConsignment struct {
	AssetId     string
	Consignment []uint8
}

func (r *AssetConsignment) Destroy() {
	FfiDestroyerString{}.Destroy(r.AssetId)
	FfiDestroyerSequenceUint8{}.Destroy(r.Consignment)
}

type FfiConverterAssetConsignment struct{}

var FfiConverterAssetConsignmentINSTANCE = FfiConverterAssetConsignment{}

func (c FfiConverterAssetConsignment) Lift(rb RustBufferI) AssetConsignment {
	return LiftFromRustBuffer[AssetConsignment](c, rb)
}

func (c FfiConverterAssetConsignment) Read(reader io.Reader) AssetConsignment {
	return AssetConsignment{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterAssetConsignment) Lower(value AssetConsignment) C.RustBuffer {
	return LowerIntoRustBuffer[AssetConsignment](c, value)
}

func (c FfiConverterAssetConsignment) LowerExternal(value AssetConsignment) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetConsignment](c, value))
}

func (c FfiConverterAssetConsignment) Write(writer io.Writer, value AssetConsignment) {
	FfiConverterStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Consignment)
}

type FfiDestroyerAssetConsignment struct{}

func (_ FfiDestroyerAssetConsignment) Destroy(value AssetConsignment) {
	value.Destroy()
}

type AssetIfa struct {
	AssetId                   string
	Ticker                    string
	Name                      string
	Details                   *string
	Precision                 uint8
	InitialSupply             uint64
	MaxSupply                 uint64
	KnownCirculatingSupply    uint64
	Timestamp                 int64
	AddedAt                   int64
	Balance                   Balance
	Media                     *Media
	RejectListUrl             *string
	IssuanceLinkRightOutpoint *Outpoint
	LinkedFromAssetId         *string
	LinkedToAssetId           *string
}

func (r *AssetIfa) Destroy() {
	FfiDestroyerString{}.Destroy(r.AssetId)
	FfiDestroyerString{}.Destroy(r.Ticker)
	FfiDestroyerString{}.Destroy(r.Name)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
	FfiDestroyerUint8{}.Destroy(r.Precision)
	FfiDestroyerUint64{}.Destroy(r.InitialSupply)
	FfiDestroyerUint64{}.Destroy(r.MaxSupply)
	FfiDestroyerUint64{}.Destroy(r.KnownCirculatingSupply)
	FfiDestroyerInt64{}.Destroy(r.Timestamp)
	FfiDestroyerInt64{}.Destroy(r.AddedAt)
	FfiDestroyerBalance{}.Destroy(r.Balance)
	FfiDestroyerOptionalMedia{}.Destroy(r.Media)
	FfiDestroyerOptionalString{}.Destroy(r.RejectListUrl)
	FfiDestroyerOptionalOutpoint{}.Destroy(r.IssuanceLinkRightOutpoint)
	FfiDestroyerOptionalString{}.Destroy(r.LinkedFromAssetId)
	FfiDestroyerOptionalString{}.Destroy(r.LinkedToAssetId)
}

type FfiConverterAssetIfa struct{}

var FfiConverterAssetIfaINSTANCE = FfiConverterAssetIfa{}

func (c FfiConverterAssetIfa) Lift(rb RustBufferI) AssetIfa {
	return LiftFromRustBuffer[AssetIfa](c, rb)
}

func (c FfiConverterAssetIfa) Read(reader io.Reader) AssetIfa {
	return AssetIfa{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterBalanceINSTANCE.Read(reader),
		FfiConverterOptionalMediaINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalOutpointINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterAssetIfa) Lower(value AssetIfa) C.RustBuffer {
	return LowerIntoRustBuffer[AssetIfa](c, value)
}

func (c FfiConverterAssetIfa) LowerExternal(value AssetIfa) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetIfa](c, value))
}

func (c FfiConverterAssetIfa) Write(writer io.Writer, value AssetIfa) {
	FfiConverterStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterStringINSTANCE.Write(writer, value.Ticker)
	FfiConverterStringINSTANCE.Write(writer, value.Name)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
	FfiConverterUint8INSTANCE.Write(writer, value.Precision)
	FfiConverterUint64INSTANCE.Write(writer, value.InitialSupply)
	FfiConverterUint64INSTANCE.Write(writer, value.MaxSupply)
	FfiConverterUint64INSTANCE.Write(writer, value.KnownCirculatingSupply)
	FfiConverterInt64INSTANCE.Write(writer, value.Timestamp)
	FfiConverterInt64INSTANCE.Write(writer, value.AddedAt)
	FfiConverterBalanceINSTANCE.Write(writer, value.Balance)
	FfiConverterOptionalMediaINSTANCE.Write(writer, value.Media)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.RejectListUrl)
	FfiConverterOptionalOutpointINSTANCE.Write(writer, value.IssuanceLinkRightOutpoint)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.LinkedFromAssetId)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.LinkedToAssetId)
}

type FfiDestroyerAssetIfa struct{}

func (_ FfiDestroyerAssetIfa) Destroy(value AssetIfa) {
	value.Destroy()
}

type AssetNia struct {
	AssetId      string
	Ticker       string
	Name         string
	Details      *string
	Precision    uint8
	IssuedSupply uint64
	Timestamp    int64
	AddedAt      int64
	Balance      Balance
	Media        *Media
}

func (r *AssetNia) Destroy() {
	FfiDestroyerString{}.Destroy(r.AssetId)
	FfiDestroyerString{}.Destroy(r.Ticker)
	FfiDestroyerString{}.Destroy(r.Name)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
	FfiDestroyerUint8{}.Destroy(r.Precision)
	FfiDestroyerUint64{}.Destroy(r.IssuedSupply)
	FfiDestroyerInt64{}.Destroy(r.Timestamp)
	FfiDestroyerInt64{}.Destroy(r.AddedAt)
	FfiDestroyerBalance{}.Destroy(r.Balance)
	FfiDestroyerOptionalMedia{}.Destroy(r.Media)
}

type FfiConverterAssetNia struct{}

var FfiConverterAssetNiaINSTANCE = FfiConverterAssetNia{}

func (c FfiConverterAssetNia) Lift(rb RustBufferI) AssetNia {
	return LiftFromRustBuffer[AssetNia](c, rb)
}

func (c FfiConverterAssetNia) Read(reader io.Reader) AssetNia {
	return AssetNia{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterBalanceINSTANCE.Read(reader),
		FfiConverterOptionalMediaINSTANCE.Read(reader),
	}
}

func (c FfiConverterAssetNia) Lower(value AssetNia) C.RustBuffer {
	return LowerIntoRustBuffer[AssetNia](c, value)
}

func (c FfiConverterAssetNia) LowerExternal(value AssetNia) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetNia](c, value))
}

func (c FfiConverterAssetNia) Write(writer io.Writer, value AssetNia) {
	FfiConverterStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterStringINSTANCE.Write(writer, value.Ticker)
	FfiConverterStringINSTANCE.Write(writer, value.Name)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
	FfiConverterUint8INSTANCE.Write(writer, value.Precision)
	FfiConverterUint64INSTANCE.Write(writer, value.IssuedSupply)
	FfiConverterInt64INSTANCE.Write(writer, value.Timestamp)
	FfiConverterInt64INSTANCE.Write(writer, value.AddedAt)
	FfiConverterBalanceINSTANCE.Write(writer, value.Balance)
	FfiConverterOptionalMediaINSTANCE.Write(writer, value.Media)
}

type FfiDestroyerAssetNia struct{}

func (_ FfiDestroyerAssetNia) Destroy(value AssetNia) {
	value.Destroy()
}

type AssetUda struct {
	AssetId   string
	Ticker    string
	Name      string
	Details   *string
	Precision uint8
	Timestamp int64
	AddedAt   int64
	Balance   Balance
	Media     *Media
	Token     *TokenLight
}

func (r *AssetUda) Destroy() {
	FfiDestroyerString{}.Destroy(r.AssetId)
	FfiDestroyerString{}.Destroy(r.Ticker)
	FfiDestroyerString{}.Destroy(r.Name)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
	FfiDestroyerUint8{}.Destroy(r.Precision)
	FfiDestroyerInt64{}.Destroy(r.Timestamp)
	FfiDestroyerInt64{}.Destroy(r.AddedAt)
	FfiDestroyerBalance{}.Destroy(r.Balance)
	FfiDestroyerOptionalMedia{}.Destroy(r.Media)
	FfiDestroyerOptionalTokenLight{}.Destroy(r.Token)
}

type FfiConverterAssetUda struct{}

var FfiConverterAssetUdaINSTANCE = FfiConverterAssetUda{}

func (c FfiConverterAssetUda) Lift(rb RustBufferI) AssetUda {
	return LiftFromRustBuffer[AssetUda](c, rb)
}

func (c FfiConverterAssetUda) Read(reader io.Reader) AssetUda {
	return AssetUda{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterBalanceINSTANCE.Read(reader),
		FfiConverterOptionalMediaINSTANCE.Read(reader),
		FfiConverterOptionalTokenLightINSTANCE.Read(reader),
	}
}

func (c FfiConverterAssetUda) Lower(value AssetUda) C.RustBuffer {
	return LowerIntoRustBuffer[AssetUda](c, value)
}

func (c FfiConverterAssetUda) LowerExternal(value AssetUda) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetUda](c, value))
}

func (c FfiConverterAssetUda) Write(writer io.Writer, value AssetUda) {
	FfiConverterStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterStringINSTANCE.Write(writer, value.Ticker)
	FfiConverterStringINSTANCE.Write(writer, value.Name)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
	FfiConverterUint8INSTANCE.Write(writer, value.Precision)
	FfiConverterInt64INSTANCE.Write(writer, value.Timestamp)
	FfiConverterInt64INSTANCE.Write(writer, value.AddedAt)
	FfiConverterBalanceINSTANCE.Write(writer, value.Balance)
	FfiConverterOptionalMediaINSTANCE.Write(writer, value.Media)
	FfiConverterOptionalTokenLightINSTANCE.Write(writer, value.Token)
}

type FfiDestroyerAssetUda struct{}

func (_ FfiDestroyerAssetUda) Destroy(value AssetUda) {
	value.Destroy()
}

type Assets struct {
	Nia *[]AssetNia
	Uda *[]AssetUda
	Cfa *[]AssetCfa
	Ifa *[]AssetIfa
}

func (r *Assets) Destroy() {
	FfiDestroyerOptionalSequenceAssetNia{}.Destroy(r.Nia)
	FfiDestroyerOptionalSequenceAssetUda{}.Destroy(r.Uda)
	FfiDestroyerOptionalSequenceAssetCfa{}.Destroy(r.Cfa)
	FfiDestroyerOptionalSequenceAssetIfa{}.Destroy(r.Ifa)
}

type FfiConverterAssets struct{}

var FfiConverterAssetsINSTANCE = FfiConverterAssets{}

func (c FfiConverterAssets) Lift(rb RustBufferI) Assets {
	return LiftFromRustBuffer[Assets](c, rb)
}

func (c FfiConverterAssets) Read(reader io.Reader) Assets {
	return Assets{
		FfiConverterOptionalSequenceAssetNiaINSTANCE.Read(reader),
		FfiConverterOptionalSequenceAssetUdaINSTANCE.Read(reader),
		FfiConverterOptionalSequenceAssetCfaINSTANCE.Read(reader),
		FfiConverterOptionalSequenceAssetIfaINSTANCE.Read(reader),
	}
}

func (c FfiConverterAssets) Lower(value Assets) C.RustBuffer {
	return LowerIntoRustBuffer[Assets](c, value)
}

func (c FfiConverterAssets) LowerExternal(value Assets) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Assets](c, value))
}

func (c FfiConverterAssets) Write(writer io.Writer, value Assets) {
	FfiConverterOptionalSequenceAssetNiaINSTANCE.Write(writer, value.Nia)
	FfiConverterOptionalSequenceAssetUdaINSTANCE.Write(writer, value.Uda)
	FfiConverterOptionalSequenceAssetCfaINSTANCE.Write(writer, value.Cfa)
	FfiConverterOptionalSequenceAssetIfaINSTANCE.Write(writer, value.Ifa)
}

type FfiDestroyerAssets struct{}

func (_ FfiDestroyerAssets) Destroy(value Assets) {
	value.Destroy()
}

type AssignmentsCollection struct {
	Fungible    uint64
	NonFungible bool
	Inflation   uint64
}

func (r *AssignmentsCollection) Destroy() {
	FfiDestroyerUint64{}.Destroy(r.Fungible)
	FfiDestroyerBool{}.Destroy(r.NonFungible)
	FfiDestroyerUint64{}.Destroy(r.Inflation)
}

type FfiConverterAssignmentsCollection struct{}

var FfiConverterAssignmentsCollectionINSTANCE = FfiConverterAssignmentsCollection{}

func (c FfiConverterAssignmentsCollection) Lift(rb RustBufferI) AssignmentsCollection {
	return LiftFromRustBuffer[AssignmentsCollection](c, rb)
}

func (c FfiConverterAssignmentsCollection) Read(reader io.Reader) AssignmentsCollection {
	return AssignmentsCollection{
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterAssignmentsCollection) Lower(value AssignmentsCollection) C.RustBuffer {
	return LowerIntoRustBuffer[AssignmentsCollection](c, value)
}

func (c FfiConverterAssignmentsCollection) LowerExternal(value AssignmentsCollection) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssignmentsCollection](c, value))
}

func (c FfiConverterAssignmentsCollection) Write(writer io.Writer, value AssignmentsCollection) {
	FfiConverterUint64INSTANCE.Write(writer, value.Fungible)
	FfiConverterBoolINSTANCE.Write(writer, value.NonFungible)
	FfiConverterUint64INSTANCE.Write(writer, value.Inflation)
}

type FfiDestroyerAssignmentsCollection struct{}

func (_ FfiDestroyerAssignmentsCollection) Destroy(value AssignmentsCollection) {
	value.Destroy()
}

type Balance struct {
	Settled   uint64
	Future    uint64
	Spendable uint64
}

func (r *Balance) Destroy() {
	FfiDestroyerUint64{}.Destroy(r.Settled)
	FfiDestroyerUint64{}.Destroy(r.Future)
	FfiDestroyerUint64{}.Destroy(r.Spendable)
}

type FfiConverterBalance struct{}

var FfiConverterBalanceINSTANCE = FfiConverterBalance{}

func (c FfiConverterBalance) Lift(rb RustBufferI) Balance {
	return LiftFromRustBuffer[Balance](c, rb)
}

func (c FfiConverterBalance) Read(reader io.Reader) Balance {
	return Balance{
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterBalance) Lower(value Balance) C.RustBuffer {
	return LowerIntoRustBuffer[Balance](c, value)
}

func (c FfiConverterBalance) LowerExternal(value Balance) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Balance](c, value))
}

func (c FfiConverterBalance) Write(writer io.Writer, value Balance) {
	FfiConverterUint64INSTANCE.Write(writer, value.Settled)
	FfiConverterUint64INSTANCE.Write(writer, value.Future)
	FfiConverterUint64INSTANCE.Write(writer, value.Spendable)
}

type FfiDestroyerBalance struct{}

func (_ FfiDestroyerBalance) Destroy(value Balance) {
	value.Destroy()
}

type BlockTime struct {
	Height    uint32
	Timestamp uint64
}

func (r *BlockTime) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.Height)
	FfiDestroyerUint64{}.Destroy(r.Timestamp)
}

type FfiConverterBlockTime struct{}

var FfiConverterBlockTimeINSTANCE = FfiConverterBlockTime{}

func (c FfiConverterBlockTime) Lift(rb RustBufferI) BlockTime {
	return LiftFromRustBuffer[BlockTime](c, rb)
}

func (c FfiConverterBlockTime) Read(reader io.Reader) BlockTime {
	return BlockTime{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterBlockTime) Lower(value BlockTime) C.RustBuffer {
	return LowerIntoRustBuffer[BlockTime](c, value)
}

func (c FfiConverterBlockTime) LowerExternal(value BlockTime) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[BlockTime](c, value))
}

func (c FfiConverterBlockTime) Write(writer io.Writer, value BlockTime) {
	FfiConverterUint32INSTANCE.Write(writer, value.Height)
	FfiConverterUint64INSTANCE.Write(writer, value.Timestamp)
}

type FfiDestroyerBlockTime struct{}

func (_ FfiDestroyerBlockTime) Destroy(value BlockTime) {
	value.Destroy()
}

type BtcBalance struct {
	Vanilla Balance
	Colored Balance
}

func (r *BtcBalance) Destroy() {
	FfiDestroyerBalance{}.Destroy(r.Vanilla)
	FfiDestroyerBalance{}.Destroy(r.Colored)
}

type FfiConverterBtcBalance struct{}

var FfiConverterBtcBalanceINSTANCE = FfiConverterBtcBalance{}

func (c FfiConverterBtcBalance) Lift(rb RustBufferI) BtcBalance {
	return LiftFromRustBuffer[BtcBalance](c, rb)
}

func (c FfiConverterBtcBalance) Read(reader io.Reader) BtcBalance {
	return BtcBalance{
		FfiConverterBalanceINSTANCE.Read(reader),
		FfiConverterBalanceINSTANCE.Read(reader),
	}
}

func (c FfiConverterBtcBalance) Lower(value BtcBalance) C.RustBuffer {
	return LowerIntoRustBuffer[BtcBalance](c, value)
}

func (c FfiConverterBtcBalance) LowerExternal(value BtcBalance) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[BtcBalance](c, value))
}

func (c FfiConverterBtcBalance) Write(writer io.Writer, value BtcBalance) {
	FfiConverterBalanceINSTANCE.Write(writer, value.Vanilla)
	FfiConverterBalanceINSTANCE.Write(writer, value.Colored)
}

type FfiDestroyerBtcBalance struct{}

func (_ FfiDestroyerBtcBalance) Destroy(value BtcBalance) {
	value.Destroy()
}

type BurnBeginResult struct {
	Psbt             string
	BatchTransferIdx *int32
	Details          BurnDetails
}

func (r *BurnBeginResult) Destroy() {
	FfiDestroyerString{}.Destroy(r.Psbt)
	FfiDestroyerOptionalInt32{}.Destroy(r.BatchTransferIdx)
	FfiDestroyerBurnDetails{}.Destroy(r.Details)
}

type FfiConverterBurnBeginResult struct{}

var FfiConverterBurnBeginResultINSTANCE = FfiConverterBurnBeginResult{}

func (c FfiConverterBurnBeginResult) Lift(rb RustBufferI) BurnBeginResult {
	return LiftFromRustBuffer[BurnBeginResult](c, rb)
}

func (c FfiConverterBurnBeginResult) Read(reader io.Reader) BurnBeginResult {
	return BurnBeginResult{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalInt32INSTANCE.Read(reader),
		FfiConverterBurnDetailsINSTANCE.Read(reader),
	}
}

func (c FfiConverterBurnBeginResult) Lower(value BurnBeginResult) C.RustBuffer {
	return LowerIntoRustBuffer[BurnBeginResult](c, value)
}

func (c FfiConverterBurnBeginResult) LowerExternal(value BurnBeginResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[BurnBeginResult](c, value))
}

func (c FfiConverterBurnBeginResult) Write(writer io.Writer, value BurnBeginResult) {
	FfiConverterStringINSTANCE.Write(writer, value.Psbt)
	FfiConverterOptionalInt32INSTANCE.Write(writer, value.BatchTransferIdx)
	FfiConverterBurnDetailsINSTANCE.Write(writer, value.Details)
}

type FfiDestroyerBurnBeginResult struct{}

func (_ FfiDestroyerBurnBeginResult) Destroy(value BurnBeginResult) {
	value.Destroy()
}

type BurnDetails struct {
	FasciaPath       string
	MinConfirmations uint8
	Entropy          uint64
}

func (r *BurnDetails) Destroy() {
	FfiDestroyerString{}.Destroy(r.FasciaPath)
	FfiDestroyerUint8{}.Destroy(r.MinConfirmations)
	FfiDestroyerUint64{}.Destroy(r.Entropy)
}

type FfiConverterBurnDetails struct{}

var FfiConverterBurnDetailsINSTANCE = FfiConverterBurnDetails{}

func (c FfiConverterBurnDetails) Lift(rb RustBufferI) BurnDetails {
	return LiftFromRustBuffer[BurnDetails](c, rb)
}

func (c FfiConverterBurnDetails) Read(reader io.Reader) BurnDetails {
	return BurnDetails{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterBurnDetails) Lower(value BurnDetails) C.RustBuffer {
	return LowerIntoRustBuffer[BurnDetails](c, value)
}

func (c FfiConverterBurnDetails) LowerExternal(value BurnDetails) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[BurnDetails](c, value))
}

func (c FfiConverterBurnDetails) Write(writer io.Writer, value BurnDetails) {
	FfiConverterStringINSTANCE.Write(writer, value.FasciaPath)
	FfiConverterUint8INSTANCE.Write(writer, value.MinConfirmations)
	FfiConverterUint64INSTANCE.Write(writer, value.Entropy)
}

type FfiDestroyerBurnDetails struct{}

func (_ FfiDestroyerBurnDetails) Destroy(value BurnDetails) {
	value.Destroy()
}

type ColorPsbtResult struct {
	Psbt         string
	Consignments []AssetConsignment
}

func (r *ColorPsbtResult) Destroy() {
	FfiDestroyerString{}.Destroy(r.Psbt)
	FfiDestroyerSequenceAssetConsignment{}.Destroy(r.Consignments)
}

type FfiConverterColorPsbtResult struct{}

var FfiConverterColorPsbtResultINSTANCE = FfiConverterColorPsbtResult{}

func (c FfiConverterColorPsbtResult) Lift(rb RustBufferI) ColorPsbtResult {
	return LiftFromRustBuffer[ColorPsbtResult](c, rb)
}

func (c FfiConverterColorPsbtResult) Read(reader io.Reader) ColorPsbtResult {
	return ColorPsbtResult{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceAssetConsignmentINSTANCE.Read(reader),
	}
}

func (c FfiConverterColorPsbtResult) Lower(value ColorPsbtResult) C.RustBuffer {
	return LowerIntoRustBuffer[ColorPsbtResult](c, value)
}

func (c FfiConverterColorPsbtResult) LowerExternal(value ColorPsbtResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[ColorPsbtResult](c, value))
}

func (c FfiConverterColorPsbtResult) Write(writer io.Writer, value ColorPsbtResult) {
	FfiConverterStringINSTANCE.Write(writer, value.Psbt)
	FfiConverterSequenceAssetConsignmentINSTANCE.Write(writer, value.Consignments)
}

type FfiDestroyerColorPsbtResult struct{}

func (_ FfiDestroyerColorPsbtResult) Destroy(value ColorPsbtResult) {
	value.Destroy()
}

type ColoringInfo struct {
	Assets         []AssetColoringInfo
	StaticBlinding *uint64
	Nonce          *uint64
}

func (r *ColoringInfo) Destroy() {
	FfiDestroyerSequenceAssetColoringInfo{}.Destroy(r.Assets)
	FfiDestroyerOptionalUint64{}.Destroy(r.StaticBlinding)
	FfiDestroyerOptionalUint64{}.Destroy(r.Nonce)
}

type FfiConverterColoringInfo struct{}

var FfiConverterColoringInfoINSTANCE = FfiConverterColoringInfo{}

func (c FfiConverterColoringInfo) Lift(rb RustBufferI) ColoringInfo {
	return LiftFromRustBuffer[ColoringInfo](c, rb)
}

func (c FfiConverterColoringInfo) Read(reader io.Reader) ColoringInfo {
	return ColoringInfo{
		FfiConverterSequenceAssetColoringInfoINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterColoringInfo) Lower(value ColoringInfo) C.RustBuffer {
	return LowerIntoRustBuffer[ColoringInfo](c, value)
}

func (c FfiConverterColoringInfo) LowerExternal(value ColoringInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[ColoringInfo](c, value))
}

func (c FfiConverterColoringInfo) Write(writer io.Writer, value ColoringInfo) {
	FfiConverterSequenceAssetColoringInfoINSTANCE.Write(writer, value.Assets)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.StaticBlinding)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.Nonce)
}

type FfiDestroyerColoringInfo struct{}

func (_ FfiDestroyerColoringInfo) Destroy(value ColoringInfo) {
	value.Destroy()
}

type CosignerData struct {
	AccountXpubVanilla string
	AccountXpubColored string
	VanillaKeychain    *uint8
	MasterFingerprint  string
}

func (r *CosignerData) Destroy() {
	FfiDestroyerString{}.Destroy(r.AccountXpubVanilla)
	FfiDestroyerString{}.Destroy(r.AccountXpubColored)
	FfiDestroyerOptionalUint8{}.Destroy(r.VanillaKeychain)
	FfiDestroyerString{}.Destroy(r.MasterFingerprint)
}

type FfiConverterCosignerData struct{}

var FfiConverterCosignerDataINSTANCE = FfiConverterCosignerData{}

func (c FfiConverterCosignerData) Lift(rb RustBufferI) CosignerData {
	return LiftFromRustBuffer[CosignerData](c, rb)
}

func (c FfiConverterCosignerData) Read(reader io.Reader) CosignerData {
	return CosignerData{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalUint8INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterCosignerData) Lower(value CosignerData) C.RustBuffer {
	return LowerIntoRustBuffer[CosignerData](c, value)
}

func (c FfiConverterCosignerData) LowerExternal(value CosignerData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[CosignerData](c, value))
}

func (c FfiConverterCosignerData) Write(writer io.Writer, value CosignerData) {
	FfiConverterStringINSTANCE.Write(writer, value.AccountXpubVanilla)
	FfiConverterStringINSTANCE.Write(writer, value.AccountXpubColored)
	FfiConverterOptionalUint8INSTANCE.Write(writer, value.VanillaKeychain)
	FfiConverterStringINSTANCE.Write(writer, value.MasterFingerprint)
}

type FfiDestroyerCosignerData struct{}

func (_ FfiDestroyerCosignerData) Destroy(value CosignerData) {
	value.Destroy()
}

type EmbeddedMedia struct {
	Mime string
	Data []uint8
}

func (r *EmbeddedMedia) Destroy() {
	FfiDestroyerString{}.Destroy(r.Mime)
	FfiDestroyerSequenceUint8{}.Destroy(r.Data)
}

type FfiConverterEmbeddedMedia struct{}

var FfiConverterEmbeddedMediaINSTANCE = FfiConverterEmbeddedMedia{}

func (c FfiConverterEmbeddedMedia) Lift(rb RustBufferI) EmbeddedMedia {
	return LiftFromRustBuffer[EmbeddedMedia](c, rb)
}

func (c FfiConverterEmbeddedMedia) Read(reader io.Reader) EmbeddedMedia {
	return EmbeddedMedia{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterEmbeddedMedia) Lower(value EmbeddedMedia) C.RustBuffer {
	return LowerIntoRustBuffer[EmbeddedMedia](c, value)
}

func (c FfiConverterEmbeddedMedia) LowerExternal(value EmbeddedMedia) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[EmbeddedMedia](c, value))
}

func (c FfiConverterEmbeddedMedia) Write(writer io.Writer, value EmbeddedMedia) {
	FfiConverterStringINSTANCE.Write(writer, value.Mime)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Data)
}

type FfiDestroyerEmbeddedMedia struct{}

func (_ FfiDestroyerEmbeddedMedia) Destroy(value EmbeddedMedia) {
	value.Destroy()
}

type HubInfo struct {
	MinRgbLibVersion string
	MaxRgbLibVersion string
	RgbLibVersion    string
	LastOperationIdx *int32
	UserRole         UserRole
}

func (r *HubInfo) Destroy() {
	FfiDestroyerString{}.Destroy(r.MinRgbLibVersion)
	FfiDestroyerString{}.Destroy(r.MaxRgbLibVersion)
	FfiDestroyerString{}.Destroy(r.RgbLibVersion)
	FfiDestroyerOptionalInt32{}.Destroy(r.LastOperationIdx)
	FfiDestroyerUserRole{}.Destroy(r.UserRole)
}

type FfiConverterHubInfo struct{}

var FfiConverterHubInfoINSTANCE = FfiConverterHubInfo{}

func (c FfiConverterHubInfo) Lift(rb RustBufferI) HubInfo {
	return LiftFromRustBuffer[HubInfo](c, rb)
}

func (c FfiConverterHubInfo) Read(reader io.Reader) HubInfo {
	return HubInfo{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalInt32INSTANCE.Read(reader),
		FfiConverterUserRoleINSTANCE.Read(reader),
	}
}

func (c FfiConverterHubInfo) Lower(value HubInfo) C.RustBuffer {
	return LowerIntoRustBuffer[HubInfo](c, value)
}

func (c FfiConverterHubInfo) LowerExternal(value HubInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[HubInfo](c, value))
}

func (c FfiConverterHubInfo) Write(writer io.Writer, value HubInfo) {
	FfiConverterStringINSTANCE.Write(writer, value.MinRgbLibVersion)
	FfiConverterStringINSTANCE.Write(writer, value.MaxRgbLibVersion)
	FfiConverterStringINSTANCE.Write(writer, value.RgbLibVersion)
	FfiConverterOptionalInt32INSTANCE.Write(writer, value.LastOperationIdx)
	FfiConverterUserRoleINSTANCE.Write(writer, value.UserRole)
}

type FfiDestroyerHubInfo struct{}

func (_ FfiDestroyerHubInfo) Destroy(value HubInfo) {
	value.Destroy()
}

type InflateBeginResult struct {
	Psbt             string
	BatchTransferIdx *int32
	Details          InflateDetails
}

func (r *InflateBeginResult) Destroy() {
	FfiDestroyerString{}.Destroy(r.Psbt)
	FfiDestroyerOptionalInt32{}.Destroy(r.BatchTransferIdx)
	FfiDestroyerInflateDetails{}.Destroy(r.Details)
}

type FfiConverterInflateBeginResult struct{}

var FfiConverterInflateBeginResultINSTANCE = FfiConverterInflateBeginResult{}

func (c FfiConverterInflateBeginResult) Lift(rb RustBufferI) InflateBeginResult {
	return LiftFromRustBuffer[InflateBeginResult](c, rb)
}

func (c FfiConverterInflateBeginResult) Read(reader io.Reader) InflateBeginResult {
	return InflateBeginResult{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalInt32INSTANCE.Read(reader),
		FfiConverterInflateDetailsINSTANCE.Read(reader),
	}
}

func (c FfiConverterInflateBeginResult) Lower(value InflateBeginResult) C.RustBuffer {
	return LowerIntoRustBuffer[InflateBeginResult](c, value)
}

func (c FfiConverterInflateBeginResult) LowerExternal(value InflateBeginResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[InflateBeginResult](c, value))
}

func (c FfiConverterInflateBeginResult) Write(writer io.Writer, value InflateBeginResult) {
	FfiConverterStringINSTANCE.Write(writer, value.Psbt)
	FfiConverterOptionalInt32INSTANCE.Write(writer, value.BatchTransferIdx)
	FfiConverterInflateDetailsINSTANCE.Write(writer, value.Details)
}

type FfiDestroyerInflateBeginResult struct{}

func (_ FfiDestroyerInflateBeginResult) Destroy(value InflateBeginResult) {
	value.Destroy()
}

type InflateDetails struct {
	FasciaPath       string
	MinConfirmations uint8
	Entropy          uint64
}

func (r *InflateDetails) Destroy() {
	FfiDestroyerString{}.Destroy(r.FasciaPath)
	FfiDestroyerUint8{}.Destroy(r.MinConfirmations)
	FfiDestroyerUint64{}.Destroy(r.Entropy)
}

type FfiConverterInflateDetails struct{}

var FfiConverterInflateDetailsINSTANCE = FfiConverterInflateDetails{}

func (c FfiConverterInflateDetails) Lift(rb RustBufferI) InflateDetails {
	return LiftFromRustBuffer[InflateDetails](c, rb)
}

func (c FfiConverterInflateDetails) Read(reader io.Reader) InflateDetails {
	return InflateDetails{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterInflateDetails) Lower(value InflateDetails) C.RustBuffer {
	return LowerIntoRustBuffer[InflateDetails](c, value)
}

func (c FfiConverterInflateDetails) LowerExternal(value InflateDetails) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[InflateDetails](c, value))
}

func (c FfiConverterInflateDetails) Write(writer io.Writer, value InflateDetails) {
	FfiConverterStringINSTANCE.Write(writer, value.FasciaPath)
	FfiConverterUint8INSTANCE.Write(writer, value.MinConfirmations)
	FfiConverterUint64INSTANCE.Write(writer, value.Entropy)
}

type FfiDestroyerInflateDetails struct{}

func (_ FfiDestroyerInflateDetails) Destroy(value InflateDetails) {
	value.Destroy()
}

type InitOperationResult struct {
	Psbt         string
	OperationIdx int32
}

func (r *InitOperationResult) Destroy() {
	FfiDestroyerString{}.Destroy(r.Psbt)
	FfiDestroyerInt32{}.Destroy(r.OperationIdx)
}

type FfiConverterInitOperationResult struct{}

var FfiConverterInitOperationResultINSTANCE = FfiConverterInitOperationResult{}

func (c FfiConverterInitOperationResult) Lift(rb RustBufferI) InitOperationResult {
	return LiftFromRustBuffer[InitOperationResult](c, rb)
}

func (c FfiConverterInitOperationResult) Read(reader io.Reader) InitOperationResult {
	return InitOperationResult{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterInt32INSTANCE.Read(reader),
	}
}

func (c FfiConverterInitOperationResult) Lower(value InitOperationResult) C.RustBuffer {
	return LowerIntoRustBuffer[InitOperationResult](c, value)
}

func (c FfiConverterInitOperationResult) LowerExternal(value InitOperationResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[InitOperationResult](c, value))
}

func (c FfiConverterInitOperationResult) Write(writer io.Writer, value InitOperationResult) {
	FfiConverterStringINSTANCE.Write(writer, value.Psbt)
	FfiConverterInt32INSTANCE.Write(writer, value.OperationIdx)
}

type FfiDestroyerInitOperationResult struct{}

func (_ FfiDestroyerInitOperationResult) Destroy(value InitOperationResult) {
	value.Destroy()
}

type InvoiceData struct {
	RecipientId         string
	ProxyRecipientId    string
	AssetSchema         *AssetSchema
	AssetId             *string
	Assignment          Assignment
	AssignmentName      *string
	Network             BitcoinNetwork
	ExpirationTimestamp *uint64
	TransportEndpoints  []string
}

func (r *InvoiceData) Destroy() {
	FfiDestroyerString{}.Destroy(r.RecipientId)
	FfiDestroyerString{}.Destroy(r.ProxyRecipientId)
	FfiDestroyerOptionalAssetSchema{}.Destroy(r.AssetSchema)
	FfiDestroyerOptionalString{}.Destroy(r.AssetId)
	FfiDestroyerAssignment{}.Destroy(r.Assignment)
	FfiDestroyerOptionalString{}.Destroy(r.AssignmentName)
	FfiDestroyerBitcoinNetwork{}.Destroy(r.Network)
	FfiDestroyerOptionalUint64{}.Destroy(r.ExpirationTimestamp)
	FfiDestroyerSequenceString{}.Destroy(r.TransportEndpoints)
}

type FfiConverterInvoiceData struct{}

var FfiConverterInvoiceDataINSTANCE = FfiConverterInvoiceData{}

func (c FfiConverterInvoiceData) Lift(rb RustBufferI) InvoiceData {
	return LiftFromRustBuffer[InvoiceData](c, rb)
}

func (c FfiConverterInvoiceData) Read(reader io.Reader) InvoiceData {
	return InvoiceData{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalAssetSchemaINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterAssignmentINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBitcoinNetworkINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterInvoiceData) Lower(value InvoiceData) C.RustBuffer {
	return LowerIntoRustBuffer[InvoiceData](c, value)
}

func (c FfiConverterInvoiceData) LowerExternal(value InvoiceData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[InvoiceData](c, value))
}

func (c FfiConverterInvoiceData) Write(writer io.Writer, value InvoiceData) {
	FfiConverterStringINSTANCE.Write(writer, value.RecipientId)
	FfiConverterStringINSTANCE.Write(writer, value.ProxyRecipientId)
	FfiConverterOptionalAssetSchemaINSTANCE.Write(writer, value.AssetSchema)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterAssignmentINSTANCE.Write(writer, value.Assignment)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.AssignmentName)
	FfiConverterBitcoinNetworkINSTANCE.Write(writer, value.Network)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.ExpirationTimestamp)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.TransportEndpoints)
}

type FfiDestroyerInvoiceData struct{}

func (_ FfiDestroyerInvoiceData) Destroy(value InvoiceData) {
	value.Destroy()
}

type Keys struct {
	Mnemonic           string
	Xpub               string
	AccountXpubVanilla string
	AccountXpubColored string
	MasterFingerprint  string
	WitnessVersion     WitnessVersion
}

func (r *Keys) Destroy() {
	FfiDestroyerString{}.Destroy(r.Mnemonic)
	FfiDestroyerString{}.Destroy(r.Xpub)
	FfiDestroyerString{}.Destroy(r.AccountXpubVanilla)
	FfiDestroyerString{}.Destroy(r.AccountXpubColored)
	FfiDestroyerString{}.Destroy(r.MasterFingerprint)
	FfiDestroyerWitnessVersion{}.Destroy(r.WitnessVersion)
}

type FfiConverterKeys struct{}

var FfiConverterKeysINSTANCE = FfiConverterKeys{}

func (c FfiConverterKeys) Lift(rb RustBufferI) Keys {
	return LiftFromRustBuffer[Keys](c, rb)
}

func (c FfiConverterKeys) Read(reader io.Reader) Keys {
	return Keys{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterWitnessVersionINSTANCE.Read(reader),
	}
}

func (c FfiConverterKeys) Lower(value Keys) C.RustBuffer {
	return LowerIntoRustBuffer[Keys](c, value)
}

func (c FfiConverterKeys) LowerExternal(value Keys) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Keys](c, value))
}

func (c FfiConverterKeys) Write(writer io.Writer, value Keys) {
	FfiConverterStringINSTANCE.Write(writer, value.Mnemonic)
	FfiConverterStringINSTANCE.Write(writer, value.Xpub)
	FfiConverterStringINSTANCE.Write(writer, value.AccountXpubVanilla)
	FfiConverterStringINSTANCE.Write(writer, value.AccountXpubColored)
	FfiConverterStringINSTANCE.Write(writer, value.MasterFingerprint)
	FfiConverterWitnessVersionINSTANCE.Write(writer, value.WitnessVersion)
}

type FfiDestroyerKeys struct{}

func (_ FfiDestroyerKeys) Destroy(value Keys) {
	value.Destroy()
}

type Media struct {
	FilePath string
	Digest   string
	Mime     string
}

func (r *Media) Destroy() {
	FfiDestroyerString{}.Destroy(r.FilePath)
	FfiDestroyerString{}.Destroy(r.Digest)
	FfiDestroyerString{}.Destroy(r.Mime)
}

type FfiConverterMedia struct{}

var FfiConverterMediaINSTANCE = FfiConverterMedia{}

func (c FfiConverterMedia) Lift(rb RustBufferI) Media {
	return LiftFromRustBuffer[Media](c, rb)
}

func (c FfiConverterMedia) Read(reader io.Reader) Media {
	return Media{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterMedia) Lower(value Media) C.RustBuffer {
	return LowerIntoRustBuffer[Media](c, value)
}

func (c FfiConverterMedia) LowerExternal(value Media) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Media](c, value))
}

func (c FfiConverterMedia) Write(writer io.Writer, value Media) {
	FfiConverterStringINSTANCE.Write(writer, value.FilePath)
	FfiConverterStringINSTANCE.Write(writer, value.Digest)
	FfiConverterStringINSTANCE.Write(writer, value.Mime)
}

type FfiDestroyerMedia struct{}

func (_ FfiDestroyerMedia) Destroy(value Media) {
	value.Destroy()
}

type Metadata struct {
	AssetSchema              AssetSchema
	InitialSupply            uint64
	MaxSupply                uint64
	KnownCirculatingSupply   uint64
	Timestamp                int64
	Name                     string
	Precision                uint8
	Ticker                   *string
	Details                  *string
	Token                    *Token
	RejectListUrl            *string
	LinkedFromAssetId        *string
	LinkedToAssetId          *string
	UnspentLinkRightOutpoint *Outpoint
}

func (r *Metadata) Destroy() {
	FfiDestroyerAssetSchema{}.Destroy(r.AssetSchema)
	FfiDestroyerUint64{}.Destroy(r.InitialSupply)
	FfiDestroyerUint64{}.Destroy(r.MaxSupply)
	FfiDestroyerUint64{}.Destroy(r.KnownCirculatingSupply)
	FfiDestroyerInt64{}.Destroy(r.Timestamp)
	FfiDestroyerString{}.Destroy(r.Name)
	FfiDestroyerUint8{}.Destroy(r.Precision)
	FfiDestroyerOptionalString{}.Destroy(r.Ticker)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
	FfiDestroyerOptionalToken{}.Destroy(r.Token)
	FfiDestroyerOptionalString{}.Destroy(r.RejectListUrl)
	FfiDestroyerOptionalString{}.Destroy(r.LinkedFromAssetId)
	FfiDestroyerOptionalString{}.Destroy(r.LinkedToAssetId)
	FfiDestroyerOptionalOutpoint{}.Destroy(r.UnspentLinkRightOutpoint)
}

type FfiConverterMetadata struct{}

var FfiConverterMetadataINSTANCE = FfiConverterMetadata{}

func (c FfiConverterMetadata) Lift(rb RustBufferI) Metadata {
	return LiftFromRustBuffer[Metadata](c, rb)
}

func (c FfiConverterMetadata) Read(reader io.Reader) Metadata {
	return Metadata{
		FfiConverterAssetSchemaINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalTokenINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalOutpointINSTANCE.Read(reader),
	}
}

func (c FfiConverterMetadata) Lower(value Metadata) C.RustBuffer {
	return LowerIntoRustBuffer[Metadata](c, value)
}

func (c FfiConverterMetadata) LowerExternal(value Metadata) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Metadata](c, value))
}

func (c FfiConverterMetadata) Write(writer io.Writer, value Metadata) {
	FfiConverterAssetSchemaINSTANCE.Write(writer, value.AssetSchema)
	FfiConverterUint64INSTANCE.Write(writer, value.InitialSupply)
	FfiConverterUint64INSTANCE.Write(writer, value.MaxSupply)
	FfiConverterUint64INSTANCE.Write(writer, value.KnownCirculatingSupply)
	FfiConverterInt64INSTANCE.Write(writer, value.Timestamp)
	FfiConverterStringINSTANCE.Write(writer, value.Name)
	FfiConverterUint8INSTANCE.Write(writer, value.Precision)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Ticker)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
	FfiConverterOptionalTokenINSTANCE.Write(writer, value.Token)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.RejectListUrl)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.LinkedFromAssetId)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.LinkedToAssetId)
	FfiConverterOptionalOutpointINSTANCE.Write(writer, value.UnspentLinkRightOutpoint)
}

type FfiDestroyerMetadata struct{}

func (_ FfiDestroyerMetadata) Destroy(value Metadata) {
	value.Destroy()
}

type MultisigKeys struct {
	Cosigners        []CosignerData
	ThresholdColored uint8
	ThresholdVanilla uint8
}

func (r *MultisigKeys) Destroy() {
	FfiDestroyerSequenceCosignerData{}.Destroy(r.Cosigners)
	FfiDestroyerUint8{}.Destroy(r.ThresholdColored)
	FfiDestroyerUint8{}.Destroy(r.ThresholdVanilla)
}

type FfiConverterMultisigKeys struct{}

var FfiConverterMultisigKeysINSTANCE = FfiConverterMultisigKeys{}

func (c FfiConverterMultisigKeys) Lift(rb RustBufferI) MultisigKeys {
	return LiftFromRustBuffer[MultisigKeys](c, rb)
}

func (c FfiConverterMultisigKeys) Read(reader io.Reader) MultisigKeys {
	return MultisigKeys{
		FfiConverterSequenceCosignerDataINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterMultisigKeys) Lower(value MultisigKeys) C.RustBuffer {
	return LowerIntoRustBuffer[MultisigKeys](c, value)
}

func (c FfiConverterMultisigKeys) LowerExternal(value MultisigKeys) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[MultisigKeys](c, value))
}

func (c FfiConverterMultisigKeys) Write(writer io.Writer, value MultisigKeys) {
	FfiConverterSequenceCosignerDataINSTANCE.Write(writer, value.Cosigners)
	FfiConverterUint8INSTANCE.Write(writer, value.ThresholdColored)
	FfiConverterUint8INSTANCE.Write(writer, value.ThresholdVanilla)
}

type FfiDestroyerMultisigKeys struct{}

func (_ FfiDestroyerMultisigKeys) Destroy(value MultisigKeys) {
	value.Destroy()
}

type MultisigOnlineOptions struct {
	HubUrl   string
	HubToken string
}

func (r *MultisigOnlineOptions) Destroy() {
	FfiDestroyerString{}.Destroy(r.HubUrl)
	FfiDestroyerString{}.Destroy(r.HubToken)
}

type FfiConverterMultisigOnlineOptions struct{}

var FfiConverterMultisigOnlineOptionsINSTANCE = FfiConverterMultisigOnlineOptions{}

func (c FfiConverterMultisigOnlineOptions) Lift(rb RustBufferI) MultisigOnlineOptions {
	return LiftFromRustBuffer[MultisigOnlineOptions](c, rb)
}

func (c FfiConverterMultisigOnlineOptions) Read(reader io.Reader) MultisigOnlineOptions {
	return MultisigOnlineOptions{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterMultisigOnlineOptions) Lower(value MultisigOnlineOptions) C.RustBuffer {
	return LowerIntoRustBuffer[MultisigOnlineOptions](c, value)
}

func (c FfiConverterMultisigOnlineOptions) LowerExternal(value MultisigOnlineOptions) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[MultisigOnlineOptions](c, value))
}

func (c FfiConverterMultisigOnlineOptions) Write(writer io.Writer, value MultisigOnlineOptions) {
	FfiConverterStringINSTANCE.Write(writer, value.HubUrl)
	FfiConverterStringINSTANCE.Write(writer, value.HubToken)
}

type FfiDestroyerMultisigOnlineOptions struct{}

func (_ FfiDestroyerMultisigOnlineOptions) Destroy(value MultisigOnlineOptions) {
	value.Destroy()
}

type MultisigVotingStatus struct {
	AckedBy    []string
	NackedBy   []string
	Threshold  uint8
	MyResponse *bool
}

func (r *MultisigVotingStatus) Destroy() {
	FfiDestroyerSequenceString{}.Destroy(r.AckedBy)
	FfiDestroyerSequenceString{}.Destroy(r.NackedBy)
	FfiDestroyerUint8{}.Destroy(r.Threshold)
	FfiDestroyerOptionalBool{}.Destroy(r.MyResponse)
}

type FfiConverterMultisigVotingStatus struct{}

var FfiConverterMultisigVotingStatusINSTANCE = FfiConverterMultisigVotingStatus{}

func (c FfiConverterMultisigVotingStatus) Lift(rb RustBufferI) MultisigVotingStatus {
	return LiftFromRustBuffer[MultisigVotingStatus](c, rb)
}

func (c FfiConverterMultisigVotingStatus) Read(reader io.Reader) MultisigVotingStatus {
	return MultisigVotingStatus{
		FfiConverterSequenceStringINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterOptionalBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterMultisigVotingStatus) Lower(value MultisigVotingStatus) C.RustBuffer {
	return LowerIntoRustBuffer[MultisigVotingStatus](c, value)
}

func (c FfiConverterMultisigVotingStatus) LowerExternal(value MultisigVotingStatus) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[MultisigVotingStatus](c, value))
}

func (c FfiConverterMultisigVotingStatus) Write(writer io.Writer, value MultisigVotingStatus) {
	FfiConverterSequenceStringINSTANCE.Write(writer, value.AckedBy)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.NackedBy)
	FfiConverterUint8INSTANCE.Write(writer, value.Threshold)
	FfiConverterOptionalBoolINSTANCE.Write(writer, value.MyResponse)
}

type FfiDestroyerMultisigVotingStatus struct{}

func (_ FfiDestroyerMultisigVotingStatus) Destroy(value MultisigVotingStatus) {
	value.Destroy()
}

type Online struct {
	Id uint64
}

func (r *Online) Destroy() {
	FfiDestroyerUint64{}.Destroy(r.Id)
}

type FfiConverterOnline struct{}

var FfiConverterOnlineINSTANCE = FfiConverterOnline{}

func (c FfiConverterOnline) Lift(rb RustBufferI) Online {
	return LiftFromRustBuffer[Online](c, rb)
}

func (c FfiConverterOnline) Read(reader io.Reader) Online {
	return Online{
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterOnline) Lower(value Online) C.RustBuffer {
	return LowerIntoRustBuffer[Online](c, value)
}

func (c FfiConverterOnline) LowerExternal(value Online) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Online](c, value))
}

func (c FfiConverterOnline) Write(writer io.Writer, value Online) {
	FfiConverterUint64INSTANCE.Write(writer, value.Id)
}

type FfiDestroyerOnline struct{}

func (_ FfiDestroyerOnline) Destroy(value Online) {
	value.Destroy()
}

type OnlineOptions struct {
	IndexerUrl           string
	SkipConsistencyCheck bool
	VanillaSyncLookback  uint32
}

func (r *OnlineOptions) Destroy() {
	FfiDestroyerString{}.Destroy(r.IndexerUrl)
	FfiDestroyerBool{}.Destroy(r.SkipConsistencyCheck)
	FfiDestroyerUint32{}.Destroy(r.VanillaSyncLookback)
}

type FfiConverterOnlineOptions struct{}

var FfiConverterOnlineOptionsINSTANCE = FfiConverterOnlineOptions{}

func (c FfiConverterOnlineOptions) Lift(rb RustBufferI) OnlineOptions {
	return LiftFromRustBuffer[OnlineOptions](c, rb)
}

func (c FfiConverterOnlineOptions) Read(reader io.Reader) OnlineOptions {
	return OnlineOptions{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
	}
}

func (c FfiConverterOnlineOptions) Lower(value OnlineOptions) C.RustBuffer {
	return LowerIntoRustBuffer[OnlineOptions](c, value)
}

func (c FfiConverterOnlineOptions) LowerExternal(value OnlineOptions) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[OnlineOptions](c, value))
}

func (c FfiConverterOnlineOptions) Write(writer io.Writer, value OnlineOptions) {
	FfiConverterStringINSTANCE.Write(writer, value.IndexerUrl)
	FfiConverterBoolINSTANCE.Write(writer, value.SkipConsistencyCheck)
	FfiConverterUint32INSTANCE.Write(writer, value.VanillaSyncLookback)
}

type FfiDestroyerOnlineOptions struct{}

func (_ FfiDestroyerOnlineOptions) Destroy(value OnlineOptions) {
	value.Destroy()
}

type OperationInfo struct {
	OperationIdx  int32
	InitiatorXpub string
	Operation     Operation
}

func (r *OperationInfo) Destroy() {
	FfiDestroyerInt32{}.Destroy(r.OperationIdx)
	FfiDestroyerString{}.Destroy(r.InitiatorXpub)
	FfiDestroyerOperation{}.Destroy(r.Operation)
}

type FfiConverterOperationInfo struct{}

var FfiConverterOperationInfoINSTANCE = FfiConverterOperationInfo{}

func (c FfiConverterOperationInfo) Lift(rb RustBufferI) OperationInfo {
	return LiftFromRustBuffer[OperationInfo](c, rb)
}

func (c FfiConverterOperationInfo) Read(reader io.Reader) OperationInfo {
	return OperationInfo{
		FfiConverterInt32INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOperationINSTANCE.Read(reader),
	}
}

func (c FfiConverterOperationInfo) Lower(value OperationInfo) C.RustBuffer {
	return LowerIntoRustBuffer[OperationInfo](c, value)
}

func (c FfiConverterOperationInfo) LowerExternal(value OperationInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[OperationInfo](c, value))
}

func (c FfiConverterOperationInfo) Write(writer io.Writer, value OperationInfo) {
	FfiConverterInt32INSTANCE.Write(writer, value.OperationIdx)
	FfiConverterStringINSTANCE.Write(writer, value.InitiatorXpub)
	FfiConverterOperationINSTANCE.Write(writer, value.Operation)
}

type FfiDestroyerOperationInfo struct{}

func (_ FfiDestroyerOperationInfo) Destroy(value OperationInfo) {
	value.Destroy()
}

type OperationResult struct {
	Txid             string
	BatchTransferIdx int32
	Entropy          uint64
}

func (r *OperationResult) Destroy() {
	FfiDestroyerString{}.Destroy(r.Txid)
	FfiDestroyerInt32{}.Destroy(r.BatchTransferIdx)
	FfiDestroyerUint64{}.Destroy(r.Entropy)
}

type FfiConverterOperationResult struct{}

var FfiConverterOperationResultINSTANCE = FfiConverterOperationResult{}

func (c FfiConverterOperationResult) Lift(rb RustBufferI) OperationResult {
	return LiftFromRustBuffer[OperationResult](c, rb)
}

func (c FfiConverterOperationResult) Read(reader io.Reader) OperationResult {
	return OperationResult{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterInt32INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterOperationResult) Lower(value OperationResult) C.RustBuffer {
	return LowerIntoRustBuffer[OperationResult](c, value)
}

func (c FfiConverterOperationResult) LowerExternal(value OperationResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[OperationResult](c, value))
}

func (c FfiConverterOperationResult) Write(writer io.Writer, value OperationResult) {
	FfiConverterStringINSTANCE.Write(writer, value.Txid)
	FfiConverterInt32INSTANCE.Write(writer, value.BatchTransferIdx)
	FfiConverterUint64INSTANCE.Write(writer, value.Entropy)
}

type FfiDestroyerOperationResult struct{}

func (_ FfiDestroyerOperationResult) Destroy(value OperationResult) {
	value.Destroy()
}

type Outpoint struct {
	Txid string
	Vout uint32
}

func (r *Outpoint) Destroy() {
	FfiDestroyerString{}.Destroy(r.Txid)
	FfiDestroyerUint32{}.Destroy(r.Vout)
}

type FfiConverterOutpoint struct{}

var FfiConverterOutpointINSTANCE = FfiConverterOutpoint{}

func (c FfiConverterOutpoint) Lift(rb RustBufferI) Outpoint {
	return LiftFromRustBuffer[Outpoint](c, rb)
}

func (c FfiConverterOutpoint) Read(reader io.Reader) Outpoint {
	return Outpoint{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
	}
}

func (c FfiConverterOutpoint) Lower(value Outpoint) C.RustBuffer {
	return LowerIntoRustBuffer[Outpoint](c, value)
}

func (c FfiConverterOutpoint) LowerExternal(value Outpoint) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Outpoint](c, value))
}

func (c FfiConverterOutpoint) Write(writer io.Writer, value Outpoint) {
	FfiConverterStringINSTANCE.Write(writer, value.Txid)
	FfiConverterUint32INSTANCE.Write(writer, value.Vout)
}

type FfiDestroyerOutpoint struct{}

func (_ FfiDestroyerOutpoint) Destroy(value Outpoint) {
	value.Destroy()
}

type OutpointAssignments struct {
	Outpoint    Outpoint
	Assignments []Assignment
}

func (r *OutpointAssignments) Destroy() {
	FfiDestroyerOutpoint{}.Destroy(r.Outpoint)
	FfiDestroyerSequenceAssignment{}.Destroy(r.Assignments)
}

type FfiConverterOutpointAssignments struct{}

var FfiConverterOutpointAssignmentsINSTANCE = FfiConverterOutpointAssignments{}

func (c FfiConverterOutpointAssignments) Lift(rb RustBufferI) OutpointAssignments {
	return LiftFromRustBuffer[OutpointAssignments](c, rb)
}

func (c FfiConverterOutpointAssignments) Read(reader io.Reader) OutpointAssignments {
	return OutpointAssignments{
		FfiConverterOutpointINSTANCE.Read(reader),
		FfiConverterSequenceAssignmentINSTANCE.Read(reader),
	}
}

func (c FfiConverterOutpointAssignments) Lower(value OutpointAssignments) C.RustBuffer {
	return LowerIntoRustBuffer[OutpointAssignments](c, value)
}

func (c FfiConverterOutpointAssignments) LowerExternal(value OutpointAssignments) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[OutpointAssignments](c, value))
}

func (c FfiConverterOutpointAssignments) Write(writer io.Writer, value OutpointAssignments) {
	FfiConverterOutpointINSTANCE.Write(writer, value.Outpoint)
	FfiConverterSequenceAssignmentINSTANCE.Write(writer, value.Assignments)
}

type FfiDestroyerOutpointAssignments struct{}

func (_ FfiDestroyerOutpointAssignments) Destroy(value OutpointAssignments) {
	value.Destroy()
}

type PendingVanillaTx struct {
	Txid string
	Type WalletTransactionType
}

func (r *PendingVanillaTx) Destroy() {
	FfiDestroyerString{}.Destroy(r.Txid)
	FfiDestroyerWalletTransactionType{}.Destroy(r.Type)
}

type FfiConverterPendingVanillaTx struct{}

var FfiConverterPendingVanillaTxINSTANCE = FfiConverterPendingVanillaTx{}

func (c FfiConverterPendingVanillaTx) Lift(rb RustBufferI) PendingVanillaTx {
	return LiftFromRustBuffer[PendingVanillaTx](c, rb)
}

func (c FfiConverterPendingVanillaTx) Read(reader io.Reader) PendingVanillaTx {
	return PendingVanillaTx{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterWalletTransactionTypeINSTANCE.Read(reader),
	}
}

func (c FfiConverterPendingVanillaTx) Lower(value PendingVanillaTx) C.RustBuffer {
	return LowerIntoRustBuffer[PendingVanillaTx](c, value)
}

func (c FfiConverterPendingVanillaTx) LowerExternal(value PendingVanillaTx) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[PendingVanillaTx](c, value))
}

func (c FfiConverterPendingVanillaTx) Write(writer io.Writer, value PendingVanillaTx) {
	FfiConverterStringINSTANCE.Write(writer, value.Txid)
	FfiConverterWalletTransactionTypeINSTANCE.Write(writer, value.Type)
}

type FfiDestroyerPendingVanillaTx struct{}

func (_ FfiDestroyerPendingVanillaTx) Destroy(value PendingVanillaTx) {
	value.Destroy()
}

type ProofOfReserves struct {
	Utxo  Outpoint
	Proof []uint8
}

func (r *ProofOfReserves) Destroy() {
	FfiDestroyerOutpoint{}.Destroy(r.Utxo)
	FfiDestroyerSequenceUint8{}.Destroy(r.Proof)
}

type FfiConverterProofOfReserves struct{}

var FfiConverterProofOfReservesINSTANCE = FfiConverterProofOfReserves{}

func (c FfiConverterProofOfReserves) Lift(rb RustBufferI) ProofOfReserves {
	return LiftFromRustBuffer[ProofOfReserves](c, rb)
}

func (c FfiConverterProofOfReserves) Read(reader io.Reader) ProofOfReserves {
	return ProofOfReserves{
		FfiConverterOutpointINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
	}
}

func (c FfiConverterProofOfReserves) Lower(value ProofOfReserves) C.RustBuffer {
	return LowerIntoRustBuffer[ProofOfReserves](c, value)
}

func (c FfiConverterProofOfReserves) LowerExternal(value ProofOfReserves) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[ProofOfReserves](c, value))
}

func (c FfiConverterProofOfReserves) Write(writer io.Writer, value ProofOfReserves) {
	FfiConverterOutpointINSTANCE.Write(writer, value.Utxo)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.Proof)
}

type FfiDestroyerProofOfReserves struct{}

func (_ FfiDestroyerProofOfReserves) Destroy(value ProofOfReserves) {
	value.Destroy()
}

type PsbtInputInfo struct {
	Outpoint  Outpoint
	AmountSat uint64
	IsMine    bool
}

func (r *PsbtInputInfo) Destroy() {
	FfiDestroyerOutpoint{}.Destroy(r.Outpoint)
	FfiDestroyerUint64{}.Destroy(r.AmountSat)
	FfiDestroyerBool{}.Destroy(r.IsMine)
}

type FfiConverterPsbtInputInfo struct{}

var FfiConverterPsbtInputInfoINSTANCE = FfiConverterPsbtInputInfo{}

func (c FfiConverterPsbtInputInfo) Lift(rb RustBufferI) PsbtInputInfo {
	return LiftFromRustBuffer[PsbtInputInfo](c, rb)
}

func (c FfiConverterPsbtInputInfo) Read(reader io.Reader) PsbtInputInfo {
	return PsbtInputInfo{
		FfiConverterOutpointINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterPsbtInputInfo) Lower(value PsbtInputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[PsbtInputInfo](c, value)
}

func (c FfiConverterPsbtInputInfo) LowerExternal(value PsbtInputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[PsbtInputInfo](c, value))
}

func (c FfiConverterPsbtInputInfo) Write(writer io.Writer, value PsbtInputInfo) {
	FfiConverterOutpointINSTANCE.Write(writer, value.Outpoint)
	FfiConverterUint64INSTANCE.Write(writer, value.AmountSat)
	FfiConverterBoolINSTANCE.Write(writer, value.IsMine)
}

type FfiDestroyerPsbtInputInfo struct{}

func (_ FfiDestroyerPsbtInputInfo) Destroy(value PsbtInputInfo) {
	value.Destroy()
}

type PsbtInspection struct {
	Txid           string
	Inputs         []PsbtInputInfo
	Outputs        []PsbtOutputInfo
	TotalInputSat  uint64
	TotalOutputSat uint64
	FeeSat         uint64
	SignatureCount uint16
	SizeVbytes     uint64
}

func (r *PsbtInspection) Destroy() {
	FfiDestroyerString{}.Destroy(r.Txid)
	FfiDestroyerSequencePsbtInputInfo{}.Destroy(r.Inputs)
	FfiDestroyerSequencePsbtOutputInfo{}.Destroy(r.Outputs)
	FfiDestroyerUint64{}.Destroy(r.TotalInputSat)
	FfiDestroyerUint64{}.Destroy(r.TotalOutputSat)
	FfiDestroyerUint64{}.Destroy(r.FeeSat)
	FfiDestroyerUint16{}.Destroy(r.SignatureCount)
	FfiDestroyerUint64{}.Destroy(r.SizeVbytes)
}

type FfiConverterPsbtInspection struct{}

var FfiConverterPsbtInspectionINSTANCE = FfiConverterPsbtInspection{}

func (c FfiConverterPsbtInspection) Lift(rb RustBufferI) PsbtInspection {
	return LiftFromRustBuffer[PsbtInspection](c, rb)
}

func (c FfiConverterPsbtInspection) Read(reader io.Reader) PsbtInspection {
	return PsbtInspection{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequencePsbtInputInfoINSTANCE.Read(reader),
		FfiConverterSequencePsbtOutputInfoINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint16INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterPsbtInspection) Lower(value PsbtInspection) C.RustBuffer {
	return LowerIntoRustBuffer[PsbtInspection](c, value)
}

func (c FfiConverterPsbtInspection) LowerExternal(value PsbtInspection) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[PsbtInspection](c, value))
}

func (c FfiConverterPsbtInspection) Write(writer io.Writer, value PsbtInspection) {
	FfiConverterStringINSTANCE.Write(writer, value.Txid)
	FfiConverterSequencePsbtInputInfoINSTANCE.Write(writer, value.Inputs)
	FfiConverterSequencePsbtOutputInfoINSTANCE.Write(writer, value.Outputs)
	FfiConverterUint64INSTANCE.Write(writer, value.TotalInputSat)
	FfiConverterUint64INSTANCE.Write(writer, value.TotalOutputSat)
	FfiConverterUint64INSTANCE.Write(writer, value.FeeSat)
	FfiConverterUint16INSTANCE.Write(writer, value.SignatureCount)
	FfiConverterUint64INSTANCE.Write(writer, value.SizeVbytes)
}

type FfiDestroyerPsbtInspection struct{}

func (_ FfiDestroyerPsbtInspection) Destroy(value PsbtInspection) {
	value.Destroy()
}

type PsbtOutputInfo struct {
	Address         *string
	ScriptPubkeyHex string
	AmountSat       uint64
	IsOpReturn      bool
	IsMine          bool
}

func (r *PsbtOutputInfo) Destroy() {
	FfiDestroyerOptionalString{}.Destroy(r.Address)
	FfiDestroyerString{}.Destroy(r.ScriptPubkeyHex)
	FfiDestroyerUint64{}.Destroy(r.AmountSat)
	FfiDestroyerBool{}.Destroy(r.IsOpReturn)
	FfiDestroyerBool{}.Destroy(r.IsMine)
}

type FfiConverterPsbtOutputInfo struct{}

var FfiConverterPsbtOutputInfoINSTANCE = FfiConverterPsbtOutputInfo{}

func (c FfiConverterPsbtOutputInfo) Lift(rb RustBufferI) PsbtOutputInfo {
	return LiftFromRustBuffer[PsbtOutputInfo](c, rb)
}

func (c FfiConverterPsbtOutputInfo) Read(reader io.Reader) PsbtOutputInfo {
	return PsbtOutputInfo{
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterPsbtOutputInfo) Lower(value PsbtOutputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[PsbtOutputInfo](c, value)
}

func (c FfiConverterPsbtOutputInfo) LowerExternal(value PsbtOutputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[PsbtOutputInfo](c, value))
}

func (c FfiConverterPsbtOutputInfo) Write(writer io.Writer, value PsbtOutputInfo) {
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Address)
	FfiConverterStringINSTANCE.Write(writer, value.ScriptPubkeyHex)
	FfiConverterUint64INSTANCE.Write(writer, value.AmountSat)
	FfiConverterBoolINSTANCE.Write(writer, value.IsOpReturn)
	FfiConverterBoolINSTANCE.Write(writer, value.IsMine)
}

type FfiDestroyerPsbtOutputInfo struct{}

func (_ FfiDestroyerPsbtOutputInfo) Destroy(value PsbtOutputInfo) {
	value.Destroy()
}

type ReceiveData struct {
	Invoice             string
	RecipientId         string
	ExpirationTimestamp *uint64
	BatchTransferIdx    int32
}

func (r *ReceiveData) Destroy() {
	FfiDestroyerString{}.Destroy(r.Invoice)
	FfiDestroyerString{}.Destroy(r.RecipientId)
	FfiDestroyerOptionalUint64{}.Destroy(r.ExpirationTimestamp)
	FfiDestroyerInt32{}.Destroy(r.BatchTransferIdx)
}

type FfiConverterReceiveData struct{}

var FfiConverterReceiveDataINSTANCE = FfiConverterReceiveData{}

func (c FfiConverterReceiveData) Lift(rb RustBufferI) ReceiveData {
	return LiftFromRustBuffer[ReceiveData](c, rb)
}

func (c FfiConverterReceiveData) Read(reader io.Reader) ReceiveData {
	return ReceiveData{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterInt32INSTANCE.Read(reader),
	}
}

func (c FfiConverterReceiveData) Lower(value ReceiveData) C.RustBuffer {
	return LowerIntoRustBuffer[ReceiveData](c, value)
}

func (c FfiConverterReceiveData) LowerExternal(value ReceiveData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[ReceiveData](c, value))
}

func (c FfiConverterReceiveData) Write(writer io.Writer, value ReceiveData) {
	FfiConverterStringINSTANCE.Write(writer, value.Invoice)
	FfiConverterStringINSTANCE.Write(writer, value.RecipientId)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.ExpirationTimestamp)
	FfiConverterInt32INSTANCE.Write(writer, value.BatchTransferIdx)
}

type FfiDestroyerReceiveData struct{}

func (_ FfiDestroyerReceiveData) Destroy(value ReceiveData) {
	value.Destroy()
}

type Recipient struct {
	RecipientId        string
	WitnessData        *WitnessData
	Assignment         Assignment
	TransportEndpoints []string
}

func (r *Recipient) Destroy() {
	FfiDestroyerString{}.Destroy(r.RecipientId)
	FfiDestroyerOptionalWitnessData{}.Destroy(r.WitnessData)
	FfiDestroyerAssignment{}.Destroy(r.Assignment)
	FfiDestroyerSequenceString{}.Destroy(r.TransportEndpoints)
}

type FfiConverterRecipient struct{}

var FfiConverterRecipientINSTANCE = FfiConverterRecipient{}

func (c FfiConverterRecipient) Lift(rb RustBufferI) Recipient {
	return LiftFromRustBuffer[Recipient](c, rb)
}

func (c FfiConverterRecipient) Read(reader io.Reader) Recipient {
	return Recipient{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalWitnessDataINSTANCE.Read(reader),
		FfiConverterAssignmentINSTANCE.Read(reader),
		FfiConverterSequenceStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterRecipient) Lower(value Recipient) C.RustBuffer {
	return LowerIntoRustBuffer[Recipient](c, value)
}

func (c FfiConverterRecipient) LowerExternal(value Recipient) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Recipient](c, value))
}

func (c FfiConverterRecipient) Write(writer io.Writer, value Recipient) {
	FfiConverterStringINSTANCE.Write(writer, value.RecipientId)
	FfiConverterOptionalWitnessDataINSTANCE.Write(writer, value.WitnessData)
	FfiConverterAssignmentINSTANCE.Write(writer, value.Assignment)
	FfiConverterSequenceStringINSTANCE.Write(writer, value.TransportEndpoints)
}

type FfiDestroyerRecipient struct{}

func (_ FfiDestroyerRecipient) Destroy(value Recipient) {
	value.Destroy()
}

type RefreshFilter struct {
	Status   RefreshTransferStatus
	Incoming bool
}

func (r *RefreshFilter) Destroy() {
	FfiDestroyerRefreshTransferStatus{}.Destroy(r.Status)
	FfiDestroyerBool{}.Destroy(r.Incoming)
}

type FfiConverterRefreshFilter struct{}

var FfiConverterRefreshFilterINSTANCE = FfiConverterRefreshFilter{}

func (c FfiConverterRefreshFilter) Lift(rb RustBufferI) RefreshFilter {
	return LiftFromRustBuffer[RefreshFilter](c, rb)
}

func (c FfiConverterRefreshFilter) Read(reader io.Reader) RefreshFilter {
	return RefreshFilter{
		FfiConverterRefreshTransferStatusINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterRefreshFilter) Lower(value RefreshFilter) C.RustBuffer {
	return LowerIntoRustBuffer[RefreshFilter](c, value)
}

func (c FfiConverterRefreshFilter) LowerExternal(value RefreshFilter) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RefreshFilter](c, value))
}

func (c FfiConverterRefreshFilter) Write(writer io.Writer, value RefreshFilter) {
	FfiConverterRefreshTransferStatusINSTANCE.Write(writer, value.Status)
	FfiConverterBoolINSTANCE.Write(writer, value.Incoming)
}

type FfiDestroyerRefreshFilter struct{}

func (_ FfiDestroyerRefreshFilter) Destroy(value RefreshFilter) {
	value.Destroy()
}

type RefreshedTransfer struct {
	UpdatedStatus *TransferStatus
	Failure       **RgbLibError
}

func (r *RefreshedTransfer) Destroy() {
	FfiDestroyerOptionalTransferStatus{}.Destroy(r.UpdatedStatus)
	FfiDestroyerOptionalRgbLibError{}.Destroy(r.Failure)
}

type FfiConverterRefreshedTransfer struct{}

var FfiConverterRefreshedTransferINSTANCE = FfiConverterRefreshedTransfer{}

func (c FfiConverterRefreshedTransfer) Lift(rb RustBufferI) RefreshedTransfer {
	return LiftFromRustBuffer[RefreshedTransfer](c, rb)
}

func (c FfiConverterRefreshedTransfer) Read(reader io.Reader) RefreshedTransfer {
	return RefreshedTransfer{
		FfiConverterOptionalTransferStatusINSTANCE.Read(reader),
		FfiConverterOptionalRgbLibErrorINSTANCE.Read(reader),
	}
}

func (c FfiConverterRefreshedTransfer) Lower(value RefreshedTransfer) C.RustBuffer {
	return LowerIntoRustBuffer[RefreshedTransfer](c, value)
}

func (c FfiConverterRefreshedTransfer) LowerExternal(value RefreshedTransfer) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RefreshedTransfer](c, value))
}

func (c FfiConverterRefreshedTransfer) Write(writer io.Writer, value RefreshedTransfer) {
	FfiConverterOptionalTransferStatusINSTANCE.Write(writer, value.UpdatedStatus)
	FfiConverterOptionalRgbLibErrorINSTANCE.Write(writer, value.Failure)
}

type FfiDestroyerRefreshedTransfer struct{}

func (_ FfiDestroyerRefreshedTransfer) Destroy(value RefreshedTransfer) {
	value.Destroy()
}

type RgbAllocation struct {
	AssetId    *string
	Assignment Assignment
	Settled    bool
}

func (r *RgbAllocation) Destroy() {
	FfiDestroyerOptionalString{}.Destroy(r.AssetId)
	FfiDestroyerAssignment{}.Destroy(r.Assignment)
	FfiDestroyerBool{}.Destroy(r.Settled)
}

type FfiConverterRgbAllocation struct{}

var FfiConverterRgbAllocationINSTANCE = FfiConverterRgbAllocation{}

func (c FfiConverterRgbAllocation) Lift(rb RustBufferI) RgbAllocation {
	return LiftFromRustBuffer[RgbAllocation](c, rb)
}

func (c FfiConverterRgbAllocation) Read(reader io.Reader) RgbAllocation {
	return RgbAllocation{
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterAssignmentINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterRgbAllocation) Lower(value RgbAllocation) C.RustBuffer {
	return LowerIntoRustBuffer[RgbAllocation](c, value)
}

func (c FfiConverterRgbAllocation) LowerExternal(value RgbAllocation) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RgbAllocation](c, value))
}

func (c FfiConverterRgbAllocation) Write(writer io.Writer, value RgbAllocation) {
	FfiConverterOptionalStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterAssignmentINSTANCE.Write(writer, value.Assignment)
	FfiConverterBoolINSTANCE.Write(writer, value.Settled)
}

type FfiDestroyerRgbAllocation struct{}

func (_ FfiDestroyerRgbAllocation) Destroy(value RgbAllocation) {
	value.Destroy()
}

type RgbInputInfo struct {
	Vin        uint32
	Assignment Assignment
}

func (r *RgbInputInfo) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.Vin)
	FfiDestroyerAssignment{}.Destroy(r.Assignment)
}

type FfiConverterRgbInputInfo struct{}

var FfiConverterRgbInputInfoINSTANCE = FfiConverterRgbInputInfo{}

func (c FfiConverterRgbInputInfo) Lift(rb RustBufferI) RgbInputInfo {
	return LiftFromRustBuffer[RgbInputInfo](c, rb)
}

func (c FfiConverterRgbInputInfo) Read(reader io.Reader) RgbInputInfo {
	return RgbInputInfo{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterAssignmentINSTANCE.Read(reader),
	}
}

func (c FfiConverterRgbInputInfo) Lower(value RgbInputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[RgbInputInfo](c, value)
}

func (c FfiConverterRgbInputInfo) LowerExternal(value RgbInputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RgbInputInfo](c, value))
}

func (c FfiConverterRgbInputInfo) Write(writer io.Writer, value RgbInputInfo) {
	FfiConverterUint32INSTANCE.Write(writer, value.Vin)
	FfiConverterAssignmentINSTANCE.Write(writer, value.Assignment)
}

type FfiDestroyerRgbInputInfo struct{}

func (_ FfiDestroyerRgbInputInfo) Destroy(value RgbInputInfo) {
	value.Destroy()
}

type RgbInspection struct {
	CloseMethod   CloseMethod
	CommitmentHex string
	Operations    []RgbOperationInfo
}

func (r *RgbInspection) Destroy() {
	FfiDestroyerCloseMethod{}.Destroy(r.CloseMethod)
	FfiDestroyerString{}.Destroy(r.CommitmentHex)
	FfiDestroyerSequenceRgbOperationInfo{}.Destroy(r.Operations)
}

type FfiConverterRgbInspection struct{}

var FfiConverterRgbInspectionINSTANCE = FfiConverterRgbInspection{}

func (c FfiConverterRgbInspection) Lift(rb RustBufferI) RgbInspection {
	return LiftFromRustBuffer[RgbInspection](c, rb)
}

func (c FfiConverterRgbInspection) Read(reader io.Reader) RgbInspection {
	return RgbInspection{
		FfiConverterCloseMethodINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceRgbOperationInfoINSTANCE.Read(reader),
	}
}

func (c FfiConverterRgbInspection) Lower(value RgbInspection) C.RustBuffer {
	return LowerIntoRustBuffer[RgbInspection](c, value)
}

func (c FfiConverterRgbInspection) LowerExternal(value RgbInspection) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RgbInspection](c, value))
}

func (c FfiConverterRgbInspection) Write(writer io.Writer, value RgbInspection) {
	FfiConverterCloseMethodINSTANCE.Write(writer, value.CloseMethod)
	FfiConverterStringINSTANCE.Write(writer, value.CommitmentHex)
	FfiConverterSequenceRgbOperationInfoINSTANCE.Write(writer, value.Operations)
}

type FfiDestroyerRgbInspection struct{}

func (_ FfiDestroyerRgbInspection) Destroy(value RgbInspection) {
	value.Destroy()
}

type RgbOperationInfo struct {
	AssetId     string
	Transitions []RgbTransitionInfo
}

func (r *RgbOperationInfo) Destroy() {
	FfiDestroyerString{}.Destroy(r.AssetId)
	FfiDestroyerSequenceRgbTransitionInfo{}.Destroy(r.Transitions)
}

type FfiConverterRgbOperationInfo struct{}

var FfiConverterRgbOperationInfoINSTANCE = FfiConverterRgbOperationInfo{}

func (c FfiConverterRgbOperationInfo) Lift(rb RustBufferI) RgbOperationInfo {
	return LiftFromRustBuffer[RgbOperationInfo](c, rb)
}

func (c FfiConverterRgbOperationInfo) Read(reader io.Reader) RgbOperationInfo {
	return RgbOperationInfo{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceRgbTransitionInfoINSTANCE.Read(reader),
	}
}

func (c FfiConverterRgbOperationInfo) Lower(value RgbOperationInfo) C.RustBuffer {
	return LowerIntoRustBuffer[RgbOperationInfo](c, value)
}

func (c FfiConverterRgbOperationInfo) LowerExternal(value RgbOperationInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RgbOperationInfo](c, value))
}

func (c FfiConverterRgbOperationInfo) Write(writer io.Writer, value RgbOperationInfo) {
	FfiConverterStringINSTANCE.Write(writer, value.AssetId)
	FfiConverterSequenceRgbTransitionInfoINSTANCE.Write(writer, value.Transitions)
}

type FfiDestroyerRgbOperationInfo struct{}

func (_ FfiDestroyerRgbOperationInfo) Destroy(value RgbOperationInfo) {
	value.Destroy()
}

type RgbOutputInfo struct {
	Vout        *uint32
	Assignment  Assignment
	IsConcealed bool
	IsOurs      bool
}

func (r *RgbOutputInfo) Destroy() {
	FfiDestroyerOptionalUint32{}.Destroy(r.Vout)
	FfiDestroyerAssignment{}.Destroy(r.Assignment)
	FfiDestroyerBool{}.Destroy(r.IsConcealed)
	FfiDestroyerBool{}.Destroy(r.IsOurs)
}

type FfiConverterRgbOutputInfo struct{}

var FfiConverterRgbOutputInfoINSTANCE = FfiConverterRgbOutputInfo{}

func (c FfiConverterRgbOutputInfo) Lift(rb RustBufferI) RgbOutputInfo {
	return LiftFromRustBuffer[RgbOutputInfo](c, rb)
}

func (c FfiConverterRgbOutputInfo) Read(reader io.Reader) RgbOutputInfo {
	return RgbOutputInfo{
		FfiConverterOptionalUint32INSTANCE.Read(reader),
		FfiConverterAssignmentINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterRgbOutputInfo) Lower(value RgbOutputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[RgbOutputInfo](c, value)
}

func (c FfiConverterRgbOutputInfo) LowerExternal(value RgbOutputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RgbOutputInfo](c, value))
}

func (c FfiConverterRgbOutputInfo) Write(writer io.Writer, value RgbOutputInfo) {
	FfiConverterOptionalUint32INSTANCE.Write(writer, value.Vout)
	FfiConverterAssignmentINSTANCE.Write(writer, value.Assignment)
	FfiConverterBoolINSTANCE.Write(writer, value.IsConcealed)
	FfiConverterBoolINSTANCE.Write(writer, value.IsOurs)
}

type FfiDestroyerRgbOutputInfo struct{}

func (_ FfiDestroyerRgbOutputInfo) Destroy(value RgbOutputInfo) {
	value.Destroy()
}

type RgbTransitionInfo struct {
	Type    TypeOfTransition
	Inputs  []RgbInputInfo
	Outputs []RgbOutputInfo
}

func (r *RgbTransitionInfo) Destroy() {
	FfiDestroyerTypeOfTransition{}.Destroy(r.Type)
	FfiDestroyerSequenceRgbInputInfo{}.Destroy(r.Inputs)
	FfiDestroyerSequenceRgbOutputInfo{}.Destroy(r.Outputs)
}

type FfiConverterRgbTransitionInfo struct{}

var FfiConverterRgbTransitionInfoINSTANCE = FfiConverterRgbTransitionInfo{}

func (c FfiConverterRgbTransitionInfo) Lift(rb RustBufferI) RgbTransitionInfo {
	return LiftFromRustBuffer[RgbTransitionInfo](c, rb)
}

func (c FfiConverterRgbTransitionInfo) Read(reader io.Reader) RgbTransitionInfo {
	return RgbTransitionInfo{
		FfiConverterTypeOfTransitionINSTANCE.Read(reader),
		FfiConverterSequenceRgbInputInfoINSTANCE.Read(reader),
		FfiConverterSequenceRgbOutputInfoINSTANCE.Read(reader),
	}
}

func (c FfiConverterRgbTransitionInfo) Lower(value RgbTransitionInfo) C.RustBuffer {
	return LowerIntoRustBuffer[RgbTransitionInfo](c, value)
}

func (c FfiConverterRgbTransitionInfo) LowerExternal(value RgbTransitionInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RgbTransitionInfo](c, value))
}

func (c FfiConverterRgbTransitionInfo) Write(writer io.Writer, value RgbTransitionInfo) {
	FfiConverterTypeOfTransitionINSTANCE.Write(writer, value.Type)
	FfiConverterSequenceRgbInputInfoINSTANCE.Write(writer, value.Inputs)
	FfiConverterSequenceRgbOutputInfoINSTANCE.Write(writer, value.Outputs)
}

type FfiDestroyerRgbTransitionInfo struct{}

func (_ FfiDestroyerRgbTransitionInfo) Destroy(value RgbTransitionInfo) {
	value.Destroy()
}

type SendBeginResult struct {
	Psbt             string
	BatchTransferIdx *int32
	Details          SendDetails
}

func (r *SendBeginResult) Destroy() {
	FfiDestroyerString{}.Destroy(r.Psbt)
	FfiDestroyerOptionalInt32{}.Destroy(r.BatchTransferIdx)
	FfiDestroyerSendDetails{}.Destroy(r.Details)
}

type FfiConverterSendBeginResult struct{}

var FfiConverterSendBeginResultINSTANCE = FfiConverterSendBeginResult{}

func (c FfiConverterSendBeginResult) Lift(rb RustBufferI) SendBeginResult {
	return LiftFromRustBuffer[SendBeginResult](c, rb)
}

func (c FfiConverterSendBeginResult) Read(reader io.Reader) SendBeginResult {
	return SendBeginResult{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalInt32INSTANCE.Read(reader),
		FfiConverterSendDetailsINSTANCE.Read(reader),
	}
}

func (c FfiConverterSendBeginResult) Lower(value SendBeginResult) C.RustBuffer {
	return LowerIntoRustBuffer[SendBeginResult](c, value)
}

func (c FfiConverterSendBeginResult) LowerExternal(value SendBeginResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[SendBeginResult](c, value))
}

func (c FfiConverterSendBeginResult) Write(writer io.Writer, value SendBeginResult) {
	FfiConverterStringINSTANCE.Write(writer, value.Psbt)
	FfiConverterOptionalInt32INSTANCE.Write(writer, value.BatchTransferIdx)
	FfiConverterSendDetailsINSTANCE.Write(writer, value.Details)
}

type FfiDestroyerSendBeginResult struct{}

func (_ FfiDestroyerSendBeginResult) Destroy(value SendBeginResult) {
	value.Destroy()
}

type SendDetails struct {
	FasciaPath       string
	MinConfirmations uint8
	Entropy          uint64
	IsDonation       bool
}

func (r *SendDetails) Destroy() {
	FfiDestroyerString{}.Destroy(r.FasciaPath)
	FfiDestroyerUint8{}.Destroy(r.MinConfirmations)
	FfiDestroyerUint64{}.Destroy(r.Entropy)
	FfiDestroyerBool{}.Destroy(r.IsDonation)
}

type FfiConverterSendDetails struct{}

var FfiConverterSendDetailsINSTANCE = FfiConverterSendDetails{}

func (c FfiConverterSendDetails) Lift(rb RustBufferI) SendDetails {
	return LiftFromRustBuffer[SendDetails](c, rb)
}

func (c FfiConverterSendDetails) Read(reader io.Reader) SendDetails {
	return SendDetails{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint8INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterSendDetails) Lower(value SendDetails) C.RustBuffer {
	return LowerIntoRustBuffer[SendDetails](c, value)
}

func (c FfiConverterSendDetails) LowerExternal(value SendDetails) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[SendDetails](c, value))
}

func (c FfiConverterSendDetails) Write(writer io.Writer, value SendDetails) {
	FfiConverterStringINSTANCE.Write(writer, value.FasciaPath)
	FfiConverterUint8INSTANCE.Write(writer, value.MinConfirmations)
	FfiConverterUint64INSTANCE.Write(writer, value.Entropy)
	FfiConverterBoolINSTANCE.Write(writer, value.IsDonation)
}

type FfiDestroyerSendDetails struct{}

func (_ FfiDestroyerSendDetails) Destroy(value SendDetails) {
	value.Destroy()
}

type SinglesigKeys struct {
	AccountXpubVanilla string
	AccountXpubColored string
	VanillaKeychain    *uint8
	MasterFingerprint  string
	Mnemonic           *string
	WitnessVersion     WitnessVersion
}

func (r *SinglesigKeys) Destroy() {
	FfiDestroyerString{}.Destroy(r.AccountXpubVanilla)
	FfiDestroyerString{}.Destroy(r.AccountXpubColored)
	FfiDestroyerOptionalUint8{}.Destroy(r.VanillaKeychain)
	FfiDestroyerString{}.Destroy(r.MasterFingerprint)
	FfiDestroyerOptionalString{}.Destroy(r.Mnemonic)
	FfiDestroyerWitnessVersion{}.Destroy(r.WitnessVersion)
}

type FfiConverterSinglesigKeys struct{}

var FfiConverterSinglesigKeysINSTANCE = FfiConverterSinglesigKeys{}

func (c FfiConverterSinglesigKeys) Lift(rb RustBufferI) SinglesigKeys {
	return LiftFromRustBuffer[SinglesigKeys](c, rb)
}

func (c FfiConverterSinglesigKeys) Read(reader io.Reader) SinglesigKeys {
	return SinglesigKeys{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalUint8INSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterWitnessVersionINSTANCE.Read(reader),
	}
}

func (c FfiConverterSinglesigKeys) Lower(value SinglesigKeys) C.RustBuffer {
	return LowerIntoRustBuffer[SinglesigKeys](c, value)
}

func (c FfiConverterSinglesigKeys) LowerExternal(value SinglesigKeys) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[SinglesigKeys](c, value))
}

func (c FfiConverterSinglesigKeys) Write(writer io.Writer, value SinglesigKeys) {
	FfiConverterStringINSTANCE.Write(writer, value.AccountXpubVanilla)
	FfiConverterStringINSTANCE.Write(writer, value.AccountXpubColored)
	FfiConverterOptionalUint8INSTANCE.Write(writer, value.VanillaKeychain)
	FfiConverterStringINSTANCE.Write(writer, value.MasterFingerprint)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Mnemonic)
	FfiConverterWitnessVersionINSTANCE.Write(writer, value.WitnessVersion)
}

type FfiDestroyerSinglesigKeys struct{}

func (_ FfiDestroyerSinglesigKeys) Destroy(value SinglesigKeys) {
	value.Destroy()
}

type SyncOptions struct {
	Keychain SyncKeychain
	Strategy SyncStrategy
}

func (r *SyncOptions) Destroy() {
	FfiDestroyerSyncKeychain{}.Destroy(r.Keychain)
	FfiDestroyerSyncStrategy{}.Destroy(r.Strategy)
}

type FfiConverterSyncOptions struct{}

var FfiConverterSyncOptionsINSTANCE = FfiConverterSyncOptions{}

func (c FfiConverterSyncOptions) Lift(rb RustBufferI) SyncOptions {
	return LiftFromRustBuffer[SyncOptions](c, rb)
}

func (c FfiConverterSyncOptions) Read(reader io.Reader) SyncOptions {
	return SyncOptions{
		FfiConverterSyncKeychainINSTANCE.Read(reader),
		FfiConverterSyncStrategyINSTANCE.Read(reader),
	}
}

func (c FfiConverterSyncOptions) Lower(value SyncOptions) C.RustBuffer {
	return LowerIntoRustBuffer[SyncOptions](c, value)
}

func (c FfiConverterSyncOptions) LowerExternal(value SyncOptions) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[SyncOptions](c, value))
}

func (c FfiConverterSyncOptions) Write(writer io.Writer, value SyncOptions) {
	FfiConverterSyncKeychainINSTANCE.Write(writer, value.Keychain)
	FfiConverterSyncStrategyINSTANCE.Write(writer, value.Strategy)
}

type FfiDestroyerSyncOptions struct{}

func (_ FfiDestroyerSyncOptions) Destroy(value SyncOptions) {
	value.Destroy()
}

type Token struct {
	Index         uint32
	Ticker        *string
	Name          *string
	Details       *string
	EmbeddedMedia *EmbeddedMedia
	Media         *Media
	Attachments   map[uint8]Media
	Reserves      *ProofOfReserves
}

func (r *Token) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.Index)
	FfiDestroyerOptionalString{}.Destroy(r.Ticker)
	FfiDestroyerOptionalString{}.Destroy(r.Name)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
	FfiDestroyerOptionalEmbeddedMedia{}.Destroy(r.EmbeddedMedia)
	FfiDestroyerOptionalMedia{}.Destroy(r.Media)
	FfiDestroyerMapUint8Media{}.Destroy(r.Attachments)
	FfiDestroyerOptionalProofOfReserves{}.Destroy(r.Reserves)
}

type FfiConverterToken struct{}

var FfiConverterTokenINSTANCE = FfiConverterToken{}

func (c FfiConverterToken) Lift(rb RustBufferI) Token {
	return LiftFromRustBuffer[Token](c, rb)
}

func (c FfiConverterToken) Read(reader io.Reader) Token {
	return Token{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalEmbeddedMediaINSTANCE.Read(reader),
		FfiConverterOptionalMediaINSTANCE.Read(reader),
		FfiConverterMapUint8MediaINSTANCE.Read(reader),
		FfiConverterOptionalProofOfReservesINSTANCE.Read(reader),
	}
}

func (c FfiConverterToken) Lower(value Token) C.RustBuffer {
	return LowerIntoRustBuffer[Token](c, value)
}

func (c FfiConverterToken) LowerExternal(value Token) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Token](c, value))
}

func (c FfiConverterToken) Write(writer io.Writer, value Token) {
	FfiConverterUint32INSTANCE.Write(writer, value.Index)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Ticker)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Name)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
	FfiConverterOptionalEmbeddedMediaINSTANCE.Write(writer, value.EmbeddedMedia)
	FfiConverterOptionalMediaINSTANCE.Write(writer, value.Media)
	FfiConverterMapUint8MediaINSTANCE.Write(writer, value.Attachments)
	FfiConverterOptionalProofOfReservesINSTANCE.Write(writer, value.Reserves)
}

type FfiDestroyerToken struct{}

func (_ FfiDestroyerToken) Destroy(value Token) {
	value.Destroy()
}

type TokenLight struct {
	Index         uint32
	Ticker        *string
	Name          *string
	Details       *string
	EmbeddedMedia bool
	Media         *Media
	Attachments   map[uint8]Media
	Reserves      bool
}

func (r *TokenLight) Destroy() {
	FfiDestroyerUint32{}.Destroy(r.Index)
	FfiDestroyerOptionalString{}.Destroy(r.Ticker)
	FfiDestroyerOptionalString{}.Destroy(r.Name)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
	FfiDestroyerBool{}.Destroy(r.EmbeddedMedia)
	FfiDestroyerOptionalMedia{}.Destroy(r.Media)
	FfiDestroyerMapUint8Media{}.Destroy(r.Attachments)
	FfiDestroyerBool{}.Destroy(r.Reserves)
}

type FfiConverterTokenLight struct{}

var FfiConverterTokenLightINSTANCE = FfiConverterTokenLight{}

func (c FfiConverterTokenLight) Lift(rb RustBufferI) TokenLight {
	return LiftFromRustBuffer[TokenLight](c, rb)
}

func (c FfiConverterTokenLight) Read(reader io.Reader) TokenLight {
	return TokenLight{
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalMediaINSTANCE.Read(reader),
		FfiConverterMapUint8MediaINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterTokenLight) Lower(value TokenLight) C.RustBuffer {
	return LowerIntoRustBuffer[TokenLight](c, value)
}

func (c FfiConverterTokenLight) LowerExternal(value TokenLight) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[TokenLight](c, value))
}

func (c FfiConverterTokenLight) Write(writer io.Writer, value TokenLight) {
	FfiConverterUint32INSTANCE.Write(writer, value.Index)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Ticker)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Name)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
	FfiConverterBoolINSTANCE.Write(writer, value.EmbeddedMedia)
	FfiConverterOptionalMediaINSTANCE.Write(writer, value.Media)
	FfiConverterMapUint8MediaINSTANCE.Write(writer, value.Attachments)
	FfiConverterBoolINSTANCE.Write(writer, value.Reserves)
}

type FfiDestroyerTokenLight struct{}

func (_ FfiDestroyerTokenLight) Destroy(value TokenLight) {
	value.Destroy()
}

type Transaction struct {
	TransactionType  TransactionType
	Txid             string
	Received         uint64
	Sent             uint64
	Fee              uint64
	ConfirmationTime *BlockTime
}

func (r *Transaction) Destroy() {
	FfiDestroyerTransactionType{}.Destroy(r.TransactionType)
	FfiDestroyerString{}.Destroy(r.Txid)
	FfiDestroyerUint64{}.Destroy(r.Received)
	FfiDestroyerUint64{}.Destroy(r.Sent)
	FfiDestroyerUint64{}.Destroy(r.Fee)
	FfiDestroyerOptionalBlockTime{}.Destroy(r.ConfirmationTime)
}

type FfiConverterTransaction struct{}

var FfiConverterTransactionINSTANCE = FfiConverterTransaction{}

func (c FfiConverterTransaction) Lift(rb RustBufferI) Transaction {
	return LiftFromRustBuffer[Transaction](c, rb)
}

func (c FfiConverterTransaction) Read(reader io.Reader) Transaction {
	return Transaction{
		FfiConverterTransactionTypeINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterOptionalBlockTimeINSTANCE.Read(reader),
	}
}

func (c FfiConverterTransaction) Lower(value Transaction) C.RustBuffer {
	return LowerIntoRustBuffer[Transaction](c, value)
}

func (c FfiConverterTransaction) LowerExternal(value Transaction) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Transaction](c, value))
}

func (c FfiConverterTransaction) Write(writer io.Writer, value Transaction) {
	FfiConverterTransactionTypeINSTANCE.Write(writer, value.TransactionType)
	FfiConverterStringINSTANCE.Write(writer, value.Txid)
	FfiConverterUint64INSTANCE.Write(writer, value.Received)
	FfiConverterUint64INSTANCE.Write(writer, value.Sent)
	FfiConverterUint64INSTANCE.Write(writer, value.Fee)
	FfiConverterOptionalBlockTimeINSTANCE.Write(writer, value.ConfirmationTime)
}

type FfiDestroyerTransaction struct{}

func (_ FfiDestroyerTransaction) Destroy(value Transaction) {
	value.Destroy()
}

type Transfer struct {
	Idx                 int32
	BatchTransferIdx    int32
	CreatedAt           int64
	UpdatedAt           int64
	Status              TransferStatus
	RequestedAssignment *Assignment
	Assignments         []Assignment
	Kind                TransferKind
	Txid                *string
	RecipientId         *string
	ProxyRecipientId    *string
	ReceiveUtxo         *Outpoint
	ChangeUtxo          *Outpoint
	ExpirationTimestamp *uint64
	TransportEndpoints  []TransferTransportEndpoint
	InvoiceString       *string
	ConsignmentPath     *string
	PsbtPath            *string
}

func (r *Transfer) Destroy() {
	FfiDestroyerInt32{}.Destroy(r.Idx)
	FfiDestroyerInt32{}.Destroy(r.BatchTransferIdx)
	FfiDestroyerInt64{}.Destroy(r.CreatedAt)
	FfiDestroyerInt64{}.Destroy(r.UpdatedAt)
	FfiDestroyerTransferStatus{}.Destroy(r.Status)
	FfiDestroyerOptionalAssignment{}.Destroy(r.RequestedAssignment)
	FfiDestroyerSequenceAssignment{}.Destroy(r.Assignments)
	FfiDestroyerTransferKind{}.Destroy(r.Kind)
	FfiDestroyerOptionalString{}.Destroy(r.Txid)
	FfiDestroyerOptionalString{}.Destroy(r.RecipientId)
	FfiDestroyerOptionalString{}.Destroy(r.ProxyRecipientId)
	FfiDestroyerOptionalOutpoint{}.Destroy(r.ReceiveUtxo)
	FfiDestroyerOptionalOutpoint{}.Destroy(r.ChangeUtxo)
	FfiDestroyerOptionalUint64{}.Destroy(r.ExpirationTimestamp)
	FfiDestroyerSequenceTransferTransportEndpoint{}.Destroy(r.TransportEndpoints)
	FfiDestroyerOptionalString{}.Destroy(r.InvoiceString)
	FfiDestroyerOptionalString{}.Destroy(r.ConsignmentPath)
	FfiDestroyerOptionalString{}.Destroy(r.PsbtPath)
}

type FfiConverterTransfer struct{}

var FfiConverterTransferINSTANCE = FfiConverterTransfer{}

func (c FfiConverterTransfer) Lift(rb RustBufferI) Transfer {
	return LiftFromRustBuffer[Transfer](c, rb)
}

func (c FfiConverterTransfer) Read(reader io.Reader) Transfer {
	return Transfer{
		FfiConverterInt32INSTANCE.Read(reader),
		FfiConverterInt32INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterInt64INSTANCE.Read(reader),
		FfiConverterTransferStatusINSTANCE.Read(reader),
		FfiConverterOptionalAssignmentINSTANCE.Read(reader),
		FfiConverterSequenceAssignmentINSTANCE.Read(reader),
		FfiConverterTransferKindINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalOutpointINSTANCE.Read(reader),
		FfiConverterOptionalOutpointINSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
		FfiConverterSequenceTransferTransportEndpointINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTransfer) Lower(value Transfer) C.RustBuffer {
	return LowerIntoRustBuffer[Transfer](c, value)
}

func (c FfiConverterTransfer) LowerExternal(value Transfer) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Transfer](c, value))
}

func (c FfiConverterTransfer) Write(writer io.Writer, value Transfer) {
	FfiConverterInt32INSTANCE.Write(writer, value.Idx)
	FfiConverterInt32INSTANCE.Write(writer, value.BatchTransferIdx)
	FfiConverterInt64INSTANCE.Write(writer, value.CreatedAt)
	FfiConverterInt64INSTANCE.Write(writer, value.UpdatedAt)
	FfiConverterTransferStatusINSTANCE.Write(writer, value.Status)
	FfiConverterOptionalAssignmentINSTANCE.Write(writer, value.RequestedAssignment)
	FfiConverterSequenceAssignmentINSTANCE.Write(writer, value.Assignments)
	FfiConverterTransferKindINSTANCE.Write(writer, value.Kind)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Txid)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.RecipientId)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ProxyRecipientId)
	FfiConverterOptionalOutpointINSTANCE.Write(writer, value.ReceiveUtxo)
	FfiConverterOptionalOutpointINSTANCE.Write(writer, value.ChangeUtxo)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.ExpirationTimestamp)
	FfiConverterSequenceTransferTransportEndpointINSTANCE.Write(writer, value.TransportEndpoints)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.InvoiceString)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.ConsignmentPath)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.PsbtPath)
}

type FfiDestroyerTransfer struct{}

func (_ FfiDestroyerTransfer) Destroy(value Transfer) {
	value.Destroy()
}

type TransferTransportEndpoint struct {
	Endpoint      string
	TransportType TransportType
	Used          bool
}

func (r *TransferTransportEndpoint) Destroy() {
	FfiDestroyerString{}.Destroy(r.Endpoint)
	FfiDestroyerTransportType{}.Destroy(r.TransportType)
	FfiDestroyerBool{}.Destroy(r.Used)
}

type FfiConverterTransferTransportEndpoint struct{}

var FfiConverterTransferTransportEndpointINSTANCE = FfiConverterTransferTransportEndpoint{}

func (c FfiConverterTransferTransportEndpoint) Lift(rb RustBufferI) TransferTransportEndpoint {
	return LiftFromRustBuffer[TransferTransportEndpoint](c, rb)
}

func (c FfiConverterTransferTransportEndpoint) Read(reader io.Reader) TransferTransportEndpoint {
	return TransferTransportEndpoint{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterTransportTypeINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterTransferTransportEndpoint) Lower(value TransferTransportEndpoint) C.RustBuffer {
	return LowerIntoRustBuffer[TransferTransportEndpoint](c, value)
}

func (c FfiConverterTransferTransportEndpoint) LowerExternal(value TransferTransportEndpoint) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[TransferTransportEndpoint](c, value))
}

func (c FfiConverterTransferTransportEndpoint) Write(writer io.Writer, value TransferTransportEndpoint) {
	FfiConverterStringINSTANCE.Write(writer, value.Endpoint)
	FfiConverterTransportTypeINSTANCE.Write(writer, value.TransportType)
	FfiConverterBoolINSTANCE.Write(writer, value.Used)
}

type FfiDestroyerTransferTransportEndpoint struct{}

func (_ FfiDestroyerTransferTransportEndpoint) Destroy(value TransferTransportEndpoint) {
	value.Destroy()
}

type Unspent struct {
	Utxo           Utxo
	RgbAllocations []RgbAllocation
	PendingBlinded uint32
}

func (r *Unspent) Destroy() {
	FfiDestroyerUtxo{}.Destroy(r.Utxo)
	FfiDestroyerSequenceRgbAllocation{}.Destroy(r.RgbAllocations)
	FfiDestroyerUint32{}.Destroy(r.PendingBlinded)
}

type FfiConverterUnspent struct{}

var FfiConverterUnspentINSTANCE = FfiConverterUnspent{}

func (c FfiConverterUnspent) Lift(rb RustBufferI) Unspent {
	return LiftFromRustBuffer[Unspent](c, rb)
}

func (c FfiConverterUnspent) Read(reader io.Reader) Unspent {
	return Unspent{
		FfiConverterUtxoINSTANCE.Read(reader),
		FfiConverterSequenceRgbAllocationINSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
	}
}

func (c FfiConverterUnspent) Lower(value Unspent) C.RustBuffer {
	return LowerIntoRustBuffer[Unspent](c, value)
}

func (c FfiConverterUnspent) LowerExternal(value Unspent) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Unspent](c, value))
}

func (c FfiConverterUnspent) Write(writer io.Writer, value Unspent) {
	FfiConverterUtxoINSTANCE.Write(writer, value.Utxo)
	FfiConverterSequenceRgbAllocationINSTANCE.Write(writer, value.RgbAllocations)
	FfiConverterUint32INSTANCE.Write(writer, value.PendingBlinded)
}

type FfiDestroyerUnspent struct{}

func (_ FfiDestroyerUnspent) Destroy(value Unspent) {
	value.Destroy()
}

type Utxo struct {
	Outpoint  Outpoint
	BtcAmount uint64
	Colorable bool
	Exists    bool
}

func (r *Utxo) Destroy() {
	FfiDestroyerOutpoint{}.Destroy(r.Outpoint)
	FfiDestroyerUint64{}.Destroy(r.BtcAmount)
	FfiDestroyerBool{}.Destroy(r.Colorable)
	FfiDestroyerBool{}.Destroy(r.Exists)
}

type FfiConverterUtxo struct{}

var FfiConverterUtxoINSTANCE = FfiConverterUtxo{}

func (c FfiConverterUtxo) Lift(rb RustBufferI) Utxo {
	return LiftFromRustBuffer[Utxo](c, rb)
}

func (c FfiConverterUtxo) Read(reader io.Reader) Utxo {
	return Utxo{
		FfiConverterOutpointINSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterUtxo) Lower(value Utxo) C.RustBuffer {
	return LowerIntoRustBuffer[Utxo](c, value)
}

func (c FfiConverterUtxo) LowerExternal(value Utxo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Utxo](c, value))
}

func (c FfiConverterUtxo) Write(writer io.Writer, value Utxo) {
	FfiConverterOutpointINSTANCE.Write(writer, value.Outpoint)
	FfiConverterUint64INSTANCE.Write(writer, value.BtcAmount)
	FfiConverterBoolINSTANCE.Write(writer, value.Colorable)
	FfiConverterBoolINSTANCE.Write(writer, value.Exists)
}

type FfiDestroyerUtxo struct{}

func (_ FfiDestroyerUtxo) Destroy(value Utxo) {
	value.Destroy()
}

type ValidateConsignmentResult struct {
	Valid    bool
	Warnings *[]string
	Error    *string
	Details  *string
}

func (r *ValidateConsignmentResult) Destroy() {
	FfiDestroyerBool{}.Destroy(r.Valid)
	FfiDestroyerOptionalSequenceString{}.Destroy(r.Warnings)
	FfiDestroyerOptionalString{}.Destroy(r.Error)
	FfiDestroyerOptionalString{}.Destroy(r.Details)
}

type FfiConverterValidateConsignmentResult struct{}

var FfiConverterValidateConsignmentResultINSTANCE = FfiConverterValidateConsignmentResult{}

func (c FfiConverterValidateConsignmentResult) Lift(rb RustBufferI) ValidateConsignmentResult {
	return LiftFromRustBuffer[ValidateConsignmentResult](c, rb)
}

func (c FfiConverterValidateConsignmentResult) Read(reader io.Reader) ValidateConsignmentResult {
	return ValidateConsignmentResult{
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalSequenceStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterValidateConsignmentResult) Lower(value ValidateConsignmentResult) C.RustBuffer {
	return LowerIntoRustBuffer[ValidateConsignmentResult](c, value)
}

func (c FfiConverterValidateConsignmentResult) LowerExternal(value ValidateConsignmentResult) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[ValidateConsignmentResult](c, value))
}

func (c FfiConverterValidateConsignmentResult) Write(writer io.Writer, value ValidateConsignmentResult) {
	FfiConverterBoolINSTANCE.Write(writer, value.Valid)
	FfiConverterOptionalSequenceStringINSTANCE.Write(writer, value.Warnings)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Error)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.Details)
}

type FfiDestroyerValidateConsignmentResult struct{}

func (_ FfiDestroyerValidateConsignmentResult) Destroy(value ValidateConsignmentResult) {
	value.Destroy()
}

type VssBackupConfig struct {
	ServerUrl         string
	StoreId           string
	SigningKey        []uint8
	EncryptionEnabled bool
	AutoBackup        bool
	BackupMode        VssBackupMode
}

func (r *VssBackupConfig) Destroy() {
	FfiDestroyerString{}.Destroy(r.ServerUrl)
	FfiDestroyerString{}.Destroy(r.StoreId)
	FfiDestroyerSequenceUint8{}.Destroy(r.SigningKey)
	FfiDestroyerBool{}.Destroy(r.EncryptionEnabled)
	FfiDestroyerBool{}.Destroy(r.AutoBackup)
	FfiDestroyerVssBackupMode{}.Destroy(r.BackupMode)
}

type FfiConverterVssBackupConfig struct{}

var FfiConverterVssBackupConfigINSTANCE = FfiConverterVssBackupConfig{}

func (c FfiConverterVssBackupConfig) Lift(rb RustBufferI) VssBackupConfig {
	return LiftFromRustBuffer[VssBackupConfig](c, rb)
}

func (c FfiConverterVssBackupConfig) Read(reader io.Reader) VssBackupConfig {
	return VssBackupConfig{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterSequenceUint8INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterVssBackupModeINSTANCE.Read(reader),
	}
}

func (c FfiConverterVssBackupConfig) Lower(value VssBackupConfig) C.RustBuffer {
	return LowerIntoRustBuffer[VssBackupConfig](c, value)
}

func (c FfiConverterVssBackupConfig) LowerExternal(value VssBackupConfig) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[VssBackupConfig](c, value))
}

func (c FfiConverterVssBackupConfig) Write(writer io.Writer, value VssBackupConfig) {
	FfiConverterStringINSTANCE.Write(writer, value.ServerUrl)
	FfiConverterStringINSTANCE.Write(writer, value.StoreId)
	FfiConverterSequenceUint8INSTANCE.Write(writer, value.SigningKey)
	FfiConverterBoolINSTANCE.Write(writer, value.EncryptionEnabled)
	FfiConverterBoolINSTANCE.Write(writer, value.AutoBackup)
	FfiConverterVssBackupModeINSTANCE.Write(writer, value.BackupMode)
}

type FfiDestroyerVssBackupConfig struct{}

func (_ FfiDestroyerVssBackupConfig) Destroy(value VssBackupConfig) {
	value.Destroy()
}

type VssBackupInfo struct {
	BackupExists        bool
	ServerVersion       *int64
	BackupRequired      bool
	LastAutoBackupError *string
}

func (r *VssBackupInfo) Destroy() {
	FfiDestroyerBool{}.Destroy(r.BackupExists)
	FfiDestroyerOptionalInt64{}.Destroy(r.ServerVersion)
	FfiDestroyerBool{}.Destroy(r.BackupRequired)
	FfiDestroyerOptionalString{}.Destroy(r.LastAutoBackupError)
}

type FfiConverterVssBackupInfo struct{}

var FfiConverterVssBackupInfoINSTANCE = FfiConverterVssBackupInfo{}

func (c FfiConverterVssBackupInfo) Lift(rb RustBufferI) VssBackupInfo {
	return LiftFromRustBuffer[VssBackupInfo](c, rb)
}

func (c FfiConverterVssBackupInfo) Read(reader io.Reader) VssBackupInfo {
	return VssBackupInfo{
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalInt64INSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
		FfiConverterOptionalStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterVssBackupInfo) Lower(value VssBackupInfo) C.RustBuffer {
	return LowerIntoRustBuffer[VssBackupInfo](c, value)
}

func (c FfiConverterVssBackupInfo) LowerExternal(value VssBackupInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[VssBackupInfo](c, value))
}

func (c FfiConverterVssBackupInfo) Write(writer io.Writer, value VssBackupInfo) {
	FfiConverterBoolINSTANCE.Write(writer, value.BackupExists)
	FfiConverterOptionalInt64INSTANCE.Write(writer, value.ServerVersion)
	FfiConverterBoolINSTANCE.Write(writer, value.BackupRequired)
	FfiConverterOptionalStringINSTANCE.Write(writer, value.LastAutoBackupError)
}

type FfiDestroyerVssBackupInfo struct{}

func (_ FfiDestroyerVssBackupInfo) Destroy(value VssBackupInfo) {
	value.Destroy()
}

type WalletData struct {
	DataDir               string
	BitcoinNetwork        BitcoinNetwork
	DatabaseType          DatabaseType
	MaxAllocationsPerUtxo uint32
	SupportedSchemas      []AssetSchema
	ReuseAddresses        bool
}

func (r *WalletData) Destroy() {
	FfiDestroyerString{}.Destroy(r.DataDir)
	FfiDestroyerBitcoinNetwork{}.Destroy(r.BitcoinNetwork)
	FfiDestroyerDatabaseType{}.Destroy(r.DatabaseType)
	FfiDestroyerUint32{}.Destroy(r.MaxAllocationsPerUtxo)
	FfiDestroyerSequenceAssetSchema{}.Destroy(r.SupportedSchemas)
	FfiDestroyerBool{}.Destroy(r.ReuseAddresses)
}

type FfiConverterWalletData struct{}

var FfiConverterWalletDataINSTANCE = FfiConverterWalletData{}

func (c FfiConverterWalletData) Lift(rb RustBufferI) WalletData {
	return LiftFromRustBuffer[WalletData](c, rb)
}

func (c FfiConverterWalletData) Read(reader io.Reader) WalletData {
	return WalletData{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterBitcoinNetworkINSTANCE.Read(reader),
		FfiConverterDatabaseTypeINSTANCE.Read(reader),
		FfiConverterUint32INSTANCE.Read(reader),
		FfiConverterSequenceAssetSchemaINSTANCE.Read(reader),
		FfiConverterBoolINSTANCE.Read(reader),
	}
}

func (c FfiConverterWalletData) Lower(value WalletData) C.RustBuffer {
	return LowerIntoRustBuffer[WalletData](c, value)
}

func (c FfiConverterWalletData) LowerExternal(value WalletData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[WalletData](c, value))
}

func (c FfiConverterWalletData) Write(writer io.Writer, value WalletData) {
	FfiConverterStringINSTANCE.Write(writer, value.DataDir)
	FfiConverterBitcoinNetworkINSTANCE.Write(writer, value.BitcoinNetwork)
	FfiConverterDatabaseTypeINSTANCE.Write(writer, value.DatabaseType)
	FfiConverterUint32INSTANCE.Write(writer, value.MaxAllocationsPerUtxo)
	FfiConverterSequenceAssetSchemaINSTANCE.Write(writer, value.SupportedSchemas)
	FfiConverterBoolINSTANCE.Write(writer, value.ReuseAddresses)
}

type FfiDestroyerWalletData struct{}

func (_ FfiDestroyerWalletData) Destroy(value WalletData) {
	value.Destroy()
}

type WalletDescriptors struct {
	Colored string
	Vanilla string
}

func (r *WalletDescriptors) Destroy() {
	FfiDestroyerString{}.Destroy(r.Colored)
	FfiDestroyerString{}.Destroy(r.Vanilla)
}

type FfiConverterWalletDescriptors struct{}

var FfiConverterWalletDescriptorsINSTANCE = FfiConverterWalletDescriptors{}

func (c FfiConverterWalletDescriptors) Lift(rb RustBufferI) WalletDescriptors {
	return LiftFromRustBuffer[WalletDescriptors](c, rb)
}

func (c FfiConverterWalletDescriptors) Read(reader io.Reader) WalletDescriptors {
	return WalletDescriptors{
		FfiConverterStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterWalletDescriptors) Lower(value WalletDescriptors) C.RustBuffer {
	return LowerIntoRustBuffer[WalletDescriptors](c, value)
}

func (c FfiConverterWalletDescriptors) LowerExternal(value WalletDescriptors) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[WalletDescriptors](c, value))
}

func (c FfiConverterWalletDescriptors) Write(writer io.Writer, value WalletDescriptors) {
	FfiConverterStringINSTANCE.Write(writer, value.Colored)
	FfiConverterStringINSTANCE.Write(writer, value.Vanilla)
}

type FfiDestroyerWalletDescriptors struct{}

func (_ FfiDestroyerWalletDescriptors) Destroy(value WalletDescriptors) {
	value.Destroy()
}

type WitnessData struct {
	AmountSat uint64
	Blinding  *uint64
}

func (r *WitnessData) Destroy() {
	FfiDestroyerUint64{}.Destroy(r.AmountSat)
	FfiDestroyerOptionalUint64{}.Destroy(r.Blinding)
}

type FfiConverterWitnessData struct{}

var FfiConverterWitnessDataINSTANCE = FfiConverterWitnessData{}

func (c FfiConverterWitnessData) Lift(rb RustBufferI) WitnessData {
	return LiftFromRustBuffer[WitnessData](c, rb)
}

func (c FfiConverterWitnessData) Read(reader io.Reader) WitnessData {
	return WitnessData{
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterOptionalUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterWitnessData) Lower(value WitnessData) C.RustBuffer {
	return LowerIntoRustBuffer[WitnessData](c, value)
}

func (c FfiConverterWitnessData) LowerExternal(value WitnessData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[WitnessData](c, value))
}

func (c FfiConverterWitnessData) Write(writer io.Writer, value WitnessData) {
	FfiConverterUint64INSTANCE.Write(writer, value.AmountSat)
	FfiConverterOptionalUint64INSTANCE.Write(writer, value.Blinding)
}

type FfiDestroyerWitnessData struct{}

func (_ FfiDestroyerWitnessData) Destroy(value WitnessData) {
	value.Destroy()
}

type AssetFilter interface {
	Destroy()
}
type AssetFilterAnyOrNone struct {
}

func (e AssetFilterAnyOrNone) Destroy() {
}

type AssetFilterNone struct {
}

func (e AssetFilterNone) Destroy() {
}

type AssetFilterId struct {
	AssetId string
}

func (e AssetFilterId) Destroy() {
	FfiDestroyerString{}.Destroy(e.AssetId)
}

type FfiConverterAssetFilter struct{}

var FfiConverterAssetFilterINSTANCE = FfiConverterAssetFilter{}

func (c FfiConverterAssetFilter) Lift(rb RustBufferI) AssetFilter {
	return LiftFromRustBuffer[AssetFilter](c, rb)
}

func (c FfiConverterAssetFilter) Lower(value AssetFilter) C.RustBuffer {
	return LowerIntoRustBuffer[AssetFilter](c, value)
}

func (c FfiConverterAssetFilter) LowerExternal(value AssetFilter) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetFilter](c, value))
}
func (FfiConverterAssetFilter) Read(reader io.Reader) AssetFilter {
	id := readInt32(reader)
	switch id {
	case 1:
		return AssetFilterAnyOrNone{}
	case 2:
		return AssetFilterNone{}
	case 3:
		return AssetFilterId{
			FfiConverterStringINSTANCE.Read(reader),
		}
	default:
		panic(fmt.Sprintf("invalid enum value %v in FfiConverterAssetFilter.Read()", id))
	}
}

func (FfiConverterAssetFilter) Write(writer io.Writer, value AssetFilter) {
	switch variant_value := value.(type) {
	case AssetFilterAnyOrNone:
		writeInt32(writer, 1)
	case AssetFilterNone:
		writeInt32(writer, 2)
	case AssetFilterId:
		writeInt32(writer, 3)
		FfiConverterStringINSTANCE.Write(writer, variant_value.AssetId)
	default:
		_ = variant_value
		panic(fmt.Sprintf("invalid enum value `%v` in FfiConverterAssetFilter.Write", value))
	}
}

type FfiDestroyerAssetFilter struct{}

func (_ FfiDestroyerAssetFilter) Destroy(value AssetFilter) {
	value.Destroy()
}

type AssetSchema uint

const (
	AssetSchemaNia AssetSchema = 1
	AssetSchemaUda AssetSchema = 2
	AssetSchemaCfa AssetSchema = 3
	AssetSchemaIfa AssetSchema = 4
)

type FfiConverterAssetSchema struct{}

var FfiConverterAssetSchemaINSTANCE = FfiConverterAssetSchema{}

func (c FfiConverterAssetSchema) Lift(rb RustBufferI) AssetSchema {
	return LiftFromRustBuffer[AssetSchema](c, rb)
}

func (c FfiConverterAssetSchema) Lower(value AssetSchema) C.RustBuffer {
	return LowerIntoRustBuffer[AssetSchema](c, value)
}

func (c FfiConverterAssetSchema) LowerExternal(value AssetSchema) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[AssetSchema](c, value))
}
func (FfiConverterAssetSchema) Read(reader io.Reader) AssetSchema {
	id := readInt32(reader)
	return AssetSchema(id)
}

func (FfiConverterAssetSchema) Write(writer io.Writer, value AssetSchema) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerAssetSchema struct{}

func (_ FfiDestroyerAssetSchema) Destroy(value AssetSchema) {
}

type Assignment interface {
	Destroy()
}
type AssignmentFungible struct {
	Amount uint64
}

func (e AssignmentFungible) Destroy() {
	FfiDestroyerUint64{}.Destroy(e.Amount)
}

type AssignmentNonFungible struct {
}

func (e AssignmentNonFungible) Destroy() {
}

type AssignmentInflationRight struct {
	Amount uint64
}

func (e AssignmentInflationRight) Destroy() {
	FfiDestroyerUint64{}.Destroy(e.Amount)
}

type AssignmentLinkRight struct {
}

func (e AssignmentLinkRight) Destroy() {
}

type AssignmentAny struct {
}

func (e AssignmentAny) Destroy() {
}

type FfiConverterAssignment struct{}

var FfiConverterAssignmentINSTANCE = FfiConverterAssignment{}

func (c FfiConverterAssignment) Lift(rb RustBufferI) Assignment {
	return LiftFromRustBuffer[Assignment](c, rb)
}

func (c FfiConverterAssignment) Lower(value Assignment) C.RustBuffer {
	return LowerIntoRustBuffer[Assignment](c, value)
}

func (c FfiConverterAssignment) LowerExternal(value Assignment) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Assignment](c, value))
}
func (FfiConverterAssignment) Read(reader io.Reader) Assignment {
	id := readInt32(reader)
	switch id {
	case 1:
		return AssignmentFungible{
			FfiConverterUint64INSTANCE.Read(reader),
		}
	case 2:
		return AssignmentNonFungible{}
	case 3:
		return AssignmentInflationRight{
			FfiConverterUint64INSTANCE.Read(reader),
		}
	case 4:
		return AssignmentLinkRight{}
	case 5:
		return AssignmentAny{}
	default:
		panic(fmt.Sprintf("invalid enum value %v in FfiConverterAssignment.Read()", id))
	}
}

func (FfiConverterAssignment) Write(writer io.Writer, value Assignment) {
	switch variant_value := value.(type) {
	case AssignmentFungible:
		writeInt32(writer, 1)
		FfiConverterUint64INSTANCE.Write(writer, variant_value.Amount)
	case AssignmentNonFungible:
		writeInt32(writer, 2)
	case AssignmentInflationRight:
		writeInt32(writer, 3)
		FfiConverterUint64INSTANCE.Write(writer, variant_value.Amount)
	case AssignmentLinkRight:
		writeInt32(writer, 4)
	case AssignmentAny:
		writeInt32(writer, 5)
	default:
		_ = variant_value
		panic(fmt.Sprintf("invalid enum value `%v` in FfiConverterAssignment.Write", value))
	}
}

type FfiDestroyerAssignment struct{}

func (_ FfiDestroyerAssignment) Destroy(value Assignment) {
	value.Destroy()
}

type BitcoinNetwork uint

const (
	BitcoinNetworkMainnet      BitcoinNetwork = 1
	BitcoinNetworkTestnet      BitcoinNetwork = 2
	BitcoinNetworkTestnet4     BitcoinNetwork = 3
	BitcoinNetworkSignet       BitcoinNetwork = 4
	BitcoinNetworkRegtest      BitcoinNetwork = 5
	BitcoinNetworkSignetCustom BitcoinNetwork = 6
)

type FfiConverterBitcoinNetwork struct{}

var FfiConverterBitcoinNetworkINSTANCE = FfiConverterBitcoinNetwork{}

func (c FfiConverterBitcoinNetwork) Lift(rb RustBufferI) BitcoinNetwork {
	return LiftFromRustBuffer[BitcoinNetwork](c, rb)
}

func (c FfiConverterBitcoinNetwork) Lower(value BitcoinNetwork) C.RustBuffer {
	return LowerIntoRustBuffer[BitcoinNetwork](c, value)
}

func (c FfiConverterBitcoinNetwork) LowerExternal(value BitcoinNetwork) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[BitcoinNetwork](c, value))
}
func (FfiConverterBitcoinNetwork) Read(reader io.Reader) BitcoinNetwork {
	id := readInt32(reader)
	return BitcoinNetwork(id)
}

func (FfiConverterBitcoinNetwork) Write(writer io.Writer, value BitcoinNetwork) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerBitcoinNetwork struct{}

func (_ FfiDestroyerBitcoinNetwork) Destroy(value BitcoinNetwork) {
}

type CloseMethod uint

const (
	CloseMethodOpretFirst  CloseMethod = 1
	CloseMethodTapretFirst CloseMethod = 2
)

type FfiConverterCloseMethod struct{}

var FfiConverterCloseMethodINSTANCE = FfiConverterCloseMethod{}

func (c FfiConverterCloseMethod) Lift(rb RustBufferI) CloseMethod {
	return LiftFromRustBuffer[CloseMethod](c, rb)
}

func (c FfiConverterCloseMethod) Lower(value CloseMethod) C.RustBuffer {
	return LowerIntoRustBuffer[CloseMethod](c, value)
}

func (c FfiConverterCloseMethod) LowerExternal(value CloseMethod) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[CloseMethod](c, value))
}
func (FfiConverterCloseMethod) Read(reader io.Reader) CloseMethod {
	id := readInt32(reader)
	return CloseMethod(id)
}

func (FfiConverterCloseMethod) Write(writer io.Writer, value CloseMethod) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerCloseMethod struct{}

func (_ FfiDestroyerCloseMethod) Destroy(value CloseMethod) {
}

type DatabaseType uint

const (
	DatabaseTypeSqlite DatabaseType = 1
)

type FfiConverterDatabaseType struct{}

var FfiConverterDatabaseTypeINSTANCE = FfiConverterDatabaseType{}

func (c FfiConverterDatabaseType) Lift(rb RustBufferI) DatabaseType {
	return LiftFromRustBuffer[DatabaseType](c, rb)
}

func (c FfiConverterDatabaseType) Lower(value DatabaseType) C.RustBuffer {
	return LowerIntoRustBuffer[DatabaseType](c, value)
}

func (c FfiConverterDatabaseType) LowerExternal(value DatabaseType) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[DatabaseType](c, value))
}
func (FfiConverterDatabaseType) Read(reader io.Reader) DatabaseType {
	id := readInt32(reader)
	return DatabaseType(id)
}

func (FfiConverterDatabaseType) Write(writer io.Writer, value DatabaseType) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerDatabaseType struct{}

func (_ FfiDestroyerDatabaseType) Destroy(value DatabaseType) {
}

type Operation interface {
	Destroy()
}
type OperationCreateUtxosToReview struct {
	Psbt   string
	Status MultisigVotingStatus
}

func (e OperationCreateUtxosToReview) Destroy() {
	FfiDestroyerString{}.Destroy(e.Psbt)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationCreateUtxosPending struct {
	Status MultisigVotingStatus
}

func (e OperationCreateUtxosPending) Destroy() {
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationCreateUtxosCompleted struct {
	Txid   string
	Status MultisigVotingStatus
}

func (e OperationCreateUtxosCompleted) Destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationCreateUtxosDiscarded struct {
	Status MultisigVotingStatus
}

func (e OperationCreateUtxosDiscarded) Destroy() {
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendBtcToReview struct {
	Psbt   string
	Status MultisigVotingStatus
}

func (e OperationSendBtcToReview) Destroy() {
	FfiDestroyerString{}.Destroy(e.Psbt)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendBtcPending struct {
	Status MultisigVotingStatus
}

func (e OperationSendBtcPending) Destroy() {
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendBtcCompleted struct {
	Txid   string
	Status MultisigVotingStatus
}

func (e OperationSendBtcCompleted) Destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendBtcDiscarded struct {
	Status MultisigVotingStatus
}

func (e OperationSendBtcDiscarded) Destroy() {
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendToReview struct {
	Psbt    string
	Details SendDetails
	Status  MultisigVotingStatus
}

func (e OperationSendToReview) Destroy() {
	FfiDestroyerString{}.Destroy(e.Psbt)
	FfiDestroyerSendDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendPending struct {
	Details SendDetails
	Status  MultisigVotingStatus
}

func (e OperationSendPending) Destroy() {
	FfiDestroyerSendDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendCompleted struct {
	Txid    string
	Details SendDetails
	Status  MultisigVotingStatus
}

func (e OperationSendCompleted) Destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
	FfiDestroyerSendDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationSendDiscarded struct {
	Details SendDetails
	Status  MultisigVotingStatus
}

func (e OperationSendDiscarded) Destroy() {
	FfiDestroyerSendDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationInflationToReview struct {
	Psbt    string
	Details InflateDetails
	Status  MultisigVotingStatus
}

func (e OperationInflationToReview) Destroy() {
	FfiDestroyerString{}.Destroy(e.Psbt)
	FfiDestroyerInflateDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationInflationPending struct {
	Details InflateDetails
	Status  MultisigVotingStatus
}

func (e OperationInflationPending) Destroy() {
	FfiDestroyerInflateDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationInflationCompleted struct {
	Txid    string
	Details InflateDetails
	Status  MultisigVotingStatus
}

func (e OperationInflationCompleted) Destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
	FfiDestroyerInflateDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationInflationDiscarded struct {
	Details InflateDetails
	Status  MultisigVotingStatus
}

func (e OperationInflationDiscarded) Destroy() {
	FfiDestroyerInflateDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationBurnToReview struct {
	Psbt    string
	Details BurnDetails
	Status  MultisigVotingStatus
}

func (e OperationBurnToReview) Destroy() {
	FfiDestroyerString{}.Destroy(e.Psbt)
	FfiDestroyerBurnDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationBurnPending struct {
	Details BurnDetails
	Status  MultisigVotingStatus
}

func (e OperationBurnPending) Destroy() {
	FfiDestroyerBurnDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationBurnCompleted struct {
	Txid    string
	Details BurnDetails
	Status  MultisigVotingStatus
}

func (e OperationBurnCompleted) Destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
	FfiDestroyerBurnDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationBurnDiscarded struct {
	Details BurnDetails
	Status  MultisigVotingStatus
}

func (e OperationBurnDiscarded) Destroy() {
	FfiDestroyerBurnDetails{}.Destroy(e.Details)
	FfiDestroyerMultisigVotingStatus{}.Destroy(e.Status)
}

type OperationIssuanceCompleted struct {
	AssetId string
}

func (e OperationIssuanceCompleted) Destroy() {
	FfiDestroyerString{}.Destroy(e.AssetId)
}

type OperationBlindReceiveCompleted struct {
	Details ReceiveData
}

func (e OperationBlindReceiveCompleted) Destroy() {
	FfiDestroyerReceiveData{}.Destroy(e.Details)
}

type OperationWitnessReceiveCompleted struct {
	Details ReceiveData
}

func (e OperationWitnessReceiveCompleted) Destroy() {
	FfiDestroyerReceiveData{}.Destroy(e.Details)
}

type FfiConverterOperation struct{}

var FfiConverterOperationINSTANCE = FfiConverterOperation{}

func (c FfiConverterOperation) Lift(rb RustBufferI) Operation {
	return LiftFromRustBuffer[Operation](c, rb)
}

func (c FfiConverterOperation) Lower(value Operation) C.RustBuffer {
	return LowerIntoRustBuffer[Operation](c, value)
}

func (c FfiConverterOperation) LowerExternal(value Operation) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Operation](c, value))
}
func (FfiConverterOperation) Read(reader io.Reader) Operation {
	id := readInt32(reader)
	switch id {
	case 1:
		return OperationCreateUtxosToReview{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 2:
		return OperationCreateUtxosPending{
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 3:
		return OperationCreateUtxosCompleted{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 4:
		return OperationCreateUtxosDiscarded{
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 5:
		return OperationSendBtcToReview{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 6:
		return OperationSendBtcPending{
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 7:
		return OperationSendBtcCompleted{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 8:
		return OperationSendBtcDiscarded{
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 9:
		return OperationSendToReview{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterSendDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 10:
		return OperationSendPending{
			FfiConverterSendDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 11:
		return OperationSendCompleted{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterSendDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 12:
		return OperationSendDiscarded{
			FfiConverterSendDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 13:
		return OperationInflationToReview{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterInflateDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 14:
		return OperationInflationPending{
			FfiConverterInflateDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 15:
		return OperationInflationCompleted{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterInflateDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 16:
		return OperationInflationDiscarded{
			FfiConverterInflateDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 17:
		return OperationBurnToReview{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterBurnDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 18:
		return OperationBurnPending{
			FfiConverterBurnDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 19:
		return OperationBurnCompleted{
			FfiConverterStringINSTANCE.Read(reader),
			FfiConverterBurnDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 20:
		return OperationBurnDiscarded{
			FfiConverterBurnDetailsINSTANCE.Read(reader),
			FfiConverterMultisigVotingStatusINSTANCE.Read(reader),
		}
	case 21:
		return OperationIssuanceCompleted{
			FfiConverterStringINSTANCE.Read(reader),
		}
	case 22:
		return OperationBlindReceiveCompleted{
			FfiConverterReceiveDataINSTANCE.Read(reader),
		}
	case 23:
		return OperationWitnessReceiveCompleted{
			FfiConverterReceiveDataINSTANCE.Read(reader),
		}
	default:
		panic(fmt.Sprintf("invalid enum value %v in FfiConverterOperation.Read()", id))
	}
}

func (FfiConverterOperation) Write(writer io.Writer, value Operation) {
	switch variant_value := value.(type) {
	case OperationCreateUtxosToReview:
		writeInt32(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Psbt)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationCreateUtxosPending:
		writeInt32(writer, 2)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationCreateUtxosCompleted:
		writeInt32(writer, 3)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Txid)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationCreateUtxosDiscarded:
		writeInt32(writer, 4)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendBtcToReview:
		writeInt32(writer, 5)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Psbt)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendBtcPending:
		writeInt32(writer, 6)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendBtcCompleted:
		writeInt32(writer, 7)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Txid)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendBtcDiscarded:
		writeInt32(writer, 8)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendToReview:
		writeInt32(writer, 9)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Psbt)
		FfiConverterSendDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendPending:
		writeInt32(writer, 10)
		FfiConverterSendDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendCompleted:
		writeInt32(writer, 11)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Txid)
		FfiConverterSendDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationSendDiscarded:
		writeInt32(writer, 12)
		FfiConverterSendDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationInflationToReview:
		writeInt32(writer, 13)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Psbt)
		FfiConverterInflateDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationInflationPending:
		writeInt32(writer, 14)
		FfiConverterInflateDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationInflationCompleted:
		writeInt32(writer, 15)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Txid)
		FfiConverterInflateDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationInflationDiscarded:
		writeInt32(writer, 16)
		FfiConverterInflateDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationBurnToReview:
		writeInt32(writer, 17)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Psbt)
		FfiConverterBurnDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationBurnPending:
		writeInt32(writer, 18)
		FfiConverterBurnDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationBurnCompleted:
		writeInt32(writer, 19)
		FfiConverterStringINSTANCE.Write(writer, variant_value.Txid)
		FfiConverterBurnDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationBurnDiscarded:
		writeInt32(writer, 20)
		FfiConverterBurnDetailsINSTANCE.Write(writer, variant_value.Details)
		FfiConverterMultisigVotingStatusINSTANCE.Write(writer, variant_value.Status)
	case OperationIssuanceCompleted:
		writeInt32(writer, 21)
		FfiConverterStringINSTANCE.Write(writer, variant_value.AssetId)
	case OperationBlindReceiveCompleted:
		writeInt32(writer, 22)
		FfiConverterReceiveDataINSTANCE.Write(writer, variant_value.Details)
	case OperationWitnessReceiveCompleted:
		writeInt32(writer, 23)
		FfiConverterReceiveDataINSTANCE.Write(writer, variant_value.Details)
	default:
		_ = variant_value
		panic(fmt.Sprintf("invalid enum value `%v` in FfiConverterOperation.Write", value))
	}
}

type FfiDestroyerOperation struct{}

func (_ FfiDestroyerOperation) Destroy(value Operation) {
	value.Destroy()
}

type RecipientType uint

const (
	RecipientTypeBlind   RecipientType = 1
	RecipientTypeWitness RecipientType = 2
)

type FfiConverterRecipientType struct{}

var FfiConverterRecipientTypeINSTANCE = FfiConverterRecipientType{}

func (c FfiConverterRecipientType) Lift(rb RustBufferI) RecipientType {
	return LiftFromRustBuffer[RecipientType](c, rb)
}

func (c FfiConverterRecipientType) Lower(value RecipientType) C.RustBuffer {
	return LowerIntoRustBuffer[RecipientType](c, value)
}

func (c FfiConverterRecipientType) LowerExternal(value RecipientType) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RecipientType](c, value))
}
func (FfiConverterRecipientType) Read(reader io.Reader) RecipientType {
	id := readInt32(reader)
	return RecipientType(id)
}

func (FfiConverterRecipientType) Write(writer io.Writer, value RecipientType) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerRecipientType struct{}

func (_ FfiDestroyerRecipientType) Destroy(value RecipientType) {
}

type RefreshTransferStatus uint

const (
	RefreshTransferStatusWaitingCounterparty  RefreshTransferStatus = 1
	RefreshTransferStatusWaitingSafeHeight    RefreshTransferStatus = 2
	RefreshTransferStatusWaitingConfirmations RefreshTransferStatus = 3
)

type FfiConverterRefreshTransferStatus struct{}

var FfiConverterRefreshTransferStatusINSTANCE = FfiConverterRefreshTransferStatus{}

func (c FfiConverterRefreshTransferStatus) Lift(rb RustBufferI) RefreshTransferStatus {
	return LiftFromRustBuffer[RefreshTransferStatus](c, rb)
}

func (c FfiConverterRefreshTransferStatus) Lower(value RefreshTransferStatus) C.RustBuffer {
	return LowerIntoRustBuffer[RefreshTransferStatus](c, value)
}

func (c FfiConverterRefreshTransferStatus) LowerExternal(value RefreshTransferStatus) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RefreshTransferStatus](c, value))
}
func (FfiConverterRefreshTransferStatus) Read(reader io.Reader) RefreshTransferStatus {
	id := readInt32(reader)
	return RefreshTransferStatus(id)
}

func (FfiConverterRefreshTransferStatus) Write(writer io.Writer, value RefreshTransferStatus) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerRefreshTransferStatus struct{}

func (_ FfiDestroyerRefreshTransferStatus) Destroy(value RefreshTransferStatus) {
}

type RespondToOperation interface {
	Destroy()
}
type RespondToOperationAck struct {
	SignedPsbt string
}

func (e RespondToOperationAck) Destroy() {
	FfiDestroyerString{}.Destroy(e.SignedPsbt)
}

type RespondToOperationNack struct {
}

func (e RespondToOperationNack) Destroy() {
}

type FfiConverterRespondToOperation struct{}

var FfiConverterRespondToOperationINSTANCE = FfiConverterRespondToOperation{}

func (c FfiConverterRespondToOperation) Lift(rb RustBufferI) RespondToOperation {
	return LiftFromRustBuffer[RespondToOperation](c, rb)
}

func (c FfiConverterRespondToOperation) Lower(value RespondToOperation) C.RustBuffer {
	return LowerIntoRustBuffer[RespondToOperation](c, value)
}

func (c FfiConverterRespondToOperation) LowerExternal(value RespondToOperation) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[RespondToOperation](c, value))
}
func (FfiConverterRespondToOperation) Read(reader io.Reader) RespondToOperation {
	id := readInt32(reader)
	switch id {
	case 1:
		return RespondToOperationAck{
			FfiConverterStringINSTANCE.Read(reader),
		}
	case 2:
		return RespondToOperationNack{}
	default:
		panic(fmt.Sprintf("invalid enum value %v in FfiConverterRespondToOperation.Read()", id))
	}
}

func (FfiConverterRespondToOperation) Write(writer io.Writer, value RespondToOperation) {
	switch variant_value := value.(type) {
	case RespondToOperationAck:
		writeInt32(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, variant_value.SignedPsbt)
	case RespondToOperationNack:
		writeInt32(writer, 2)
	default:
		_ = variant_value
		panic(fmt.Sprintf("invalid enum value `%v` in FfiConverterRespondToOperation.Write", value))
	}
}

type FfiDestroyerRespondToOperation struct{}

func (_ FfiDestroyerRespondToOperation) Destroy(value RespondToOperation) {
	value.Destroy()
}

type RgbLibError struct {
	err error
}

// Convenience method to turn *RgbLibError into error
// Avoiding treating nil pointer as non nil error interface
func (err *RgbLibError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err RgbLibError) Error() string {
	return fmt.Sprintf("RgbLibError: %s", err.err.Error())
}

func (err RgbLibError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrRgbLibErrorAddressReuseDisabled = fmt.Errorf("RgbLibErrorAddressReuseDisabled")
var ErrRgbLibErrorAllocationsAlreadyAvailable = fmt.Errorf("RgbLibErrorAllocationsAlreadyAvailable")
var ErrRgbLibErrorAssetNotFound = fmt.Errorf("RgbLibErrorAssetNotFound")
var ErrRgbLibErrorBatchTransferNotFound = fmt.Errorf("RgbLibErrorBatchTransferNotFound")
var ErrRgbLibErrorBitcoinNetworkMismatch = fmt.Errorf("RgbLibErrorBitcoinNetworkMismatch")
var ErrRgbLibErrorCannotAbortPendingVanillaTx = fmt.Errorf("RgbLibErrorCannotAbortPendingVanillaTx")
var ErrRgbLibErrorCannotChangeOnline = fmt.Errorf("RgbLibErrorCannotChangeOnline")
var ErrRgbLibErrorCannotCombinePsbts = fmt.Errorf("RgbLibErrorCannotCombinePsbts")
var ErrRgbLibErrorCannotDeleteBatchTransfer = fmt.Errorf("RgbLibErrorCannotDeleteBatchTransfer")
var ErrRgbLibErrorCannotEstimateFees = fmt.Errorf("RgbLibErrorCannotEstimateFees")
var ErrRgbLibErrorCannotFailBatchTransfer = fmt.Errorf("RgbLibErrorCannotFailBatchTransfer")
var ErrRgbLibErrorCannotFinalizePsbt = fmt.Errorf("RgbLibErrorCannotFinalizePsbt")
var ErrRgbLibErrorCannotUseIfaOnMainnet = fmt.Errorf("RgbLibErrorCannotUseIfaOnMainnet")
var ErrRgbLibErrorDatabase = fmt.Errorf("RgbLibErrorDatabase")
var ErrRgbLibErrorEmptyFile = fmt.Errorf("RgbLibErrorEmptyFile")
var ErrRgbLibErrorFailedBdkSync = fmt.Errorf("RgbLibErrorFailedBdkSync")
var ErrRgbLibErrorFailedBroadcast = fmt.Errorf("RgbLibErrorFailedBroadcast")
var ErrRgbLibErrorFailedIssuance = fmt.Errorf("RgbLibErrorFailedIssuance")
var ErrRgbLibErrorFileAlreadyExists = fmt.Errorf("RgbLibErrorFileAlreadyExists")
var ErrRgbLibErrorFingerprintMismatch = fmt.Errorf("RgbLibErrorFingerprintMismatch")
var ErrRgbLibErrorIo = fmt.Errorf("RgbLibErrorIo")
var ErrRgbLibErrorInconsistency = fmt.Errorf("RgbLibErrorInconsistency")
var ErrRgbLibErrorIndexer = fmt.Errorf("RgbLibErrorIndexer")
var ErrRgbLibErrorInexistentDataDir = fmt.Errorf("RgbLibErrorInexistentDataDir")
var ErrRgbLibErrorInsufficientAllocationSlots = fmt.Errorf("RgbLibErrorInsufficientAllocationSlots")
var ErrRgbLibErrorInsufficientAssignments = fmt.Errorf("RgbLibErrorInsufficientAssignments")
var ErrRgbLibErrorInsufficientBitcoins = fmt.Errorf("RgbLibErrorInsufficientBitcoins")
var ErrRgbLibErrorInternal = fmt.Errorf("RgbLibErrorInternal")
var ErrRgbLibErrorInvalidAddress = fmt.Errorf("RgbLibErrorInvalidAddress")
var ErrRgbLibErrorInvalidAmountZero = fmt.Errorf("RgbLibErrorInvalidAmountZero")
var ErrRgbLibErrorInvalidAssignment = fmt.Errorf("RgbLibErrorInvalidAssignment")
var ErrRgbLibErrorInvalidAttachments = fmt.Errorf("RgbLibErrorInvalidAttachments")
var ErrRgbLibErrorInvalidBitcoinKeys = fmt.Errorf("RgbLibErrorInvalidBitcoinKeys")
var ErrRgbLibErrorInvalidBitcoinNetwork = fmt.Errorf("RgbLibErrorInvalidBitcoinNetwork")
var ErrRgbLibErrorInvalidColoringInfo = fmt.Errorf("RgbLibErrorInvalidColoringInfo")
var ErrRgbLibErrorInvalidConsignment = fmt.Errorf("RgbLibErrorInvalidConsignment")
var ErrRgbLibErrorInvalidContractLink = fmt.Errorf("RgbLibErrorInvalidContractLink")
var ErrRgbLibErrorInvalidCosigner = fmt.Errorf("RgbLibErrorInvalidCosigner")
var ErrRgbLibErrorInvalidDetails = fmt.Errorf("RgbLibErrorInvalidDetails")
var ErrRgbLibErrorInvalidElectrum = fmt.Errorf("RgbLibErrorInvalidElectrum")
var ErrRgbLibErrorInvalidEstimationBlocks = fmt.Errorf("RgbLibErrorInvalidEstimationBlocks")
var ErrRgbLibErrorInvalidExpiration = fmt.Errorf("RgbLibErrorInvalidExpiration")
var ErrRgbLibErrorInvalidFeeRate = fmt.Errorf("RgbLibErrorInvalidFeeRate")
var ErrRgbLibErrorInvalidFilePath = fmt.Errorf("RgbLibErrorInvalidFilePath")
var ErrRgbLibErrorInvalidFingerprint = fmt.Errorf("RgbLibErrorInvalidFingerprint")
var ErrRgbLibErrorInvalidIndexer = fmt.Errorf("RgbLibErrorInvalidIndexer")
var ErrRgbLibErrorInvalidInvoice = fmt.Errorf("RgbLibErrorInvalidInvoice")
var ErrRgbLibErrorInvalidMnemonic = fmt.Errorf("RgbLibErrorInvalidMnemonic")
var ErrRgbLibErrorInvalidMultisigThreshold = fmt.Errorf("RgbLibErrorInvalidMultisigThreshold")
var ErrRgbLibErrorInvalidName = fmt.Errorf("RgbLibErrorInvalidName")
var ErrRgbLibErrorInvalidPrecision = fmt.Errorf("RgbLibErrorInvalidPrecision")
var ErrRgbLibErrorInvalidProxyProtocol = fmt.Errorf("RgbLibErrorInvalidProxyProtocol")
var ErrRgbLibErrorInvalidPsbt = fmt.Errorf("RgbLibErrorInvalidPsbt")
var ErrRgbLibErrorInvalidPubkey = fmt.Errorf("RgbLibErrorInvalidPubkey")
var ErrRgbLibErrorInvalidRecipientData = fmt.Errorf("RgbLibErrorInvalidRecipientData")
var ErrRgbLibErrorInvalidRecipientId = fmt.Errorf("RgbLibErrorInvalidRecipientId")
var ErrRgbLibErrorInvalidRecipientMap = fmt.Errorf("RgbLibErrorInvalidRecipientMap")
var ErrRgbLibErrorInvalidRecipientNetwork = fmt.Errorf("RgbLibErrorInvalidRecipientNetwork")
var ErrRgbLibErrorInvalidRejectListUrl = fmt.Errorf("RgbLibErrorInvalidRejectListUrl")
var ErrRgbLibErrorInvalidRightOutpoint = fmt.Errorf("RgbLibErrorInvalidRightOutpoint")
var ErrRgbLibErrorInvalidTicker = fmt.Errorf("RgbLibErrorInvalidTicker")
var ErrRgbLibErrorInvalidTransportEndpoint = fmt.Errorf("RgbLibErrorInvalidTransportEndpoint")
var ErrRgbLibErrorInvalidTransportEndpoints = fmt.Errorf("RgbLibErrorInvalidTransportEndpoints")
var ErrRgbLibErrorInvalidTxid = fmt.Errorf("RgbLibErrorInvalidTxid")
var ErrRgbLibErrorInvalidVanillaKeychain = fmt.Errorf("RgbLibErrorInvalidVanillaKeychain")
var ErrRgbLibErrorInvalidWitnessVersion = fmt.Errorf("RgbLibErrorInvalidWitnessVersion")
var ErrRgbLibErrorMaxFeeExceeded = fmt.Errorf("RgbLibErrorMaxFeeExceeded")
var ErrRgbLibErrorMinFeeNotMet = fmt.Errorf("RgbLibErrorMinFeeNotMet")
var ErrRgbLibErrorMpcProvider = fmt.Errorf("RgbLibErrorMpcProvider")
var ErrRgbLibErrorMultisigHubService = fmt.Errorf("RgbLibErrorMultisigHubService")
var ErrRgbLibErrorMultisigCannotMarkOperationProcessed = fmt.Errorf("RgbLibErrorMultisigCannotMarkOperationProcessed")
var ErrRgbLibErrorMultisigCannotRespondToOperation = fmt.Errorf("RgbLibErrorMultisigCannotRespondToOperation")
var ErrRgbLibErrorMultisigOperationInProgress = fmt.Errorf("RgbLibErrorMultisigOperationInProgress")
var ErrRgbLibErrorMultisigOperationNotFound = fmt.Errorf("RgbLibErrorMultisigOperationNotFound")
var ErrRgbLibErrorMultisigTransferStatusMismatch = fmt.Errorf("RgbLibErrorMultisigTransferStatusMismatch")
var ErrRgbLibErrorMultisigUnexpectedData = fmt.Errorf("RgbLibErrorMultisigUnexpectedData")
var ErrRgbLibErrorMultisigUserNotCosigner = fmt.Errorf("RgbLibErrorMultisigUserNotCosigner")
var ErrRgbLibErrorNetwork = fmt.Errorf("RgbLibErrorNetwork")
var ErrRgbLibErrorNoConsignment = fmt.Errorf("RgbLibErrorNoConsignment")
var ErrRgbLibErrorNoCosignersSupplied = fmt.Errorf("RgbLibErrorNoCosignersSupplied")
var ErrRgbLibErrorNoBurnAmount = fmt.Errorf("RgbLibErrorNoBurnAmount")
var ErrRgbLibErrorNoInflationAmounts = fmt.Errorf("RgbLibErrorNoInflationAmounts")
var ErrRgbLibErrorNoIssuanceAmounts = fmt.Errorf("RgbLibErrorNoIssuanceAmounts")
var ErrRgbLibErrorNoKeysSupplied = fmt.Errorf("RgbLibErrorNoKeysSupplied")
var ErrRgbLibErrorNoSupportedSchemas = fmt.Errorf("RgbLibErrorNoSupportedSchemas")
var ErrRgbLibErrorNoValidTransportEndpoint = fmt.Errorf("RgbLibErrorNoValidTransportEndpoint")
var ErrRgbLibErrorOffline = fmt.Errorf("RgbLibErrorOffline")
var ErrRgbLibErrorOnlineNeeded = fmt.Errorf("RgbLibErrorOnlineNeeded")
var ErrRgbLibErrorOutputBelowDustLimit = fmt.Errorf("RgbLibErrorOutputBelowDustLimit")
var ErrRgbLibErrorProxy = fmt.Errorf("RgbLibErrorProxy")
var ErrRgbLibErrorPsbtInspection = fmt.Errorf("RgbLibErrorPsbtInspection")
var ErrRgbLibErrorRecipientIdAlreadyUsed = fmt.Errorf("RgbLibErrorRecipientIdAlreadyUsed")
var ErrRgbLibErrorRecipientIdDuplicated = fmt.Errorf("RgbLibErrorRecipientIdDuplicated")
var ErrRgbLibErrorRejectListService = fmt.Errorf("RgbLibErrorRejectListService")
var ErrRgbLibErrorRestClientBuild = fmt.Errorf("RgbLibErrorRestClientBuild")
var ErrRgbLibErrorRestoredBackupInconsistent = fmt.Errorf("RgbLibErrorRestoredBackupInconsistent")
var ErrRgbLibErrorRgbInspection = fmt.Errorf("RgbLibErrorRgbInspection")
var ErrRgbLibErrorTooHighInflationAmounts = fmt.Errorf("RgbLibErrorTooHighInflationAmounts")
var ErrRgbLibErrorTooHighIssuanceAmounts = fmt.Errorf("RgbLibErrorTooHighIssuanceAmounts")
var ErrRgbLibErrorTooManyCosigners = fmt.Errorf("RgbLibErrorTooManyCosigners")
var ErrRgbLibErrorTooManySignaturesInPsbt = fmt.Errorf("RgbLibErrorTooManySignaturesInPsbt")
var ErrRgbLibErrorUnknownRgbSchema = fmt.Errorf("RgbLibErrorUnknownRgbSchema")
var ErrRgbLibErrorUnknownTransfer = fmt.Errorf("RgbLibErrorUnknownTransfer")
var ErrRgbLibErrorUnsupportedBackupVersion = fmt.Errorf("RgbLibErrorUnsupportedBackupVersion")
var ErrRgbLibErrorUnsupportedBurn = fmt.Errorf("RgbLibErrorUnsupportedBurn")
var ErrRgbLibErrorUnsupportedInflation = fmt.Errorf("RgbLibErrorUnsupportedInflation")
var ErrRgbLibErrorUnsupportedLayer1 = fmt.Errorf("RgbLibErrorUnsupportedLayer1")
var ErrRgbLibErrorUnsupportedSchema = fmt.Errorf("RgbLibErrorUnsupportedSchema")
var ErrRgbLibErrorUnsupportedTransportType = fmt.Errorf("RgbLibErrorUnsupportedTransportType")
var ErrRgbLibErrorVssAuth = fmt.Errorf("RgbLibErrorVssAuth")
var ErrRgbLibErrorVssBackupNotFound = fmt.Errorf("RgbLibErrorVssBackupNotFound")
var ErrRgbLibErrorVssError = fmt.Errorf("RgbLibErrorVssError")
var ErrRgbLibErrorVssVersionConflict = fmt.Errorf("RgbLibErrorVssVersionConflict")
var ErrRgbLibErrorWalletDirAlreadyExists = fmt.Errorf("RgbLibErrorWalletDirAlreadyExists")
var ErrRgbLibErrorWatchOnly = fmt.Errorf("RgbLibErrorWatchOnly")
var ErrRgbLibErrorWrongPassword = fmt.Errorf("RgbLibErrorWrongPassword")

// Variant structs
type RgbLibErrorAddressReuseDisabled struct {
}

func NewRgbLibErrorAddressReuseDisabled() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorAddressReuseDisabled{}}
}

func (e RgbLibErrorAddressReuseDisabled) destroy() {
}

func (err RgbLibErrorAddressReuseDisabled) Error() string {
	return fmt.Sprint("AddressReuseDisabled")
}

func (self RgbLibErrorAddressReuseDisabled) Is(target error) bool {
	return target == ErrRgbLibErrorAddressReuseDisabled
}

type RgbLibErrorAllocationsAlreadyAvailable struct {
}

func NewRgbLibErrorAllocationsAlreadyAvailable() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorAllocationsAlreadyAvailable{}}
}

func (e RgbLibErrorAllocationsAlreadyAvailable) destroy() {
}

func (err RgbLibErrorAllocationsAlreadyAvailable) Error() string {
	return fmt.Sprint("AllocationsAlreadyAvailable")
}

func (self RgbLibErrorAllocationsAlreadyAvailable) Is(target error) bool {
	return target == ErrRgbLibErrorAllocationsAlreadyAvailable
}

type RgbLibErrorAssetNotFound struct {
	AssetId string
}

func NewRgbLibErrorAssetNotFound(
	assetId string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorAssetNotFound{
		AssetId: assetId}}
}

func (e RgbLibErrorAssetNotFound) destroy() {
	FfiDestroyerString{}.Destroy(e.AssetId)
}

func (err RgbLibErrorAssetNotFound) Error() string {
	return fmt.Sprint("AssetNotFound",
		": ",

		"AssetId=",
		err.AssetId,
	)
}

func (self RgbLibErrorAssetNotFound) Is(target error) bool {
	return target == ErrRgbLibErrorAssetNotFound
}

type RgbLibErrorBatchTransferNotFound struct {
	Idx int32
}

func NewRgbLibErrorBatchTransferNotFound(
	idx int32,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorBatchTransferNotFound{
		Idx: idx}}
}

func (e RgbLibErrorBatchTransferNotFound) destroy() {
	FfiDestroyerInt32{}.Destroy(e.Idx)
}

func (err RgbLibErrorBatchTransferNotFound) Error() string {
	return fmt.Sprint("BatchTransferNotFound",
		": ",

		"Idx=",
		err.Idx,
	)
}

func (self RgbLibErrorBatchTransferNotFound) Is(target error) bool {
	return target == ErrRgbLibErrorBatchTransferNotFound
}

type RgbLibErrorBitcoinNetworkMismatch struct {
}

func NewRgbLibErrorBitcoinNetworkMismatch() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorBitcoinNetworkMismatch{}}
}

func (e RgbLibErrorBitcoinNetworkMismatch) destroy() {
}

func (err RgbLibErrorBitcoinNetworkMismatch) Error() string {
	return fmt.Sprint("BitcoinNetworkMismatch")
}

func (self RgbLibErrorBitcoinNetworkMismatch) Is(target error) bool {
	return target == ErrRgbLibErrorBitcoinNetworkMismatch
}

type RgbLibErrorCannotAbortPendingVanillaTx struct {
}

func NewRgbLibErrorCannotAbortPendingVanillaTx() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotAbortPendingVanillaTx{}}
}

func (e RgbLibErrorCannotAbortPendingVanillaTx) destroy() {
}

func (err RgbLibErrorCannotAbortPendingVanillaTx) Error() string {
	return fmt.Sprint("CannotAbortPendingVanillaTx")
}

func (self RgbLibErrorCannotAbortPendingVanillaTx) Is(target error) bool {
	return target == ErrRgbLibErrorCannotAbortPendingVanillaTx
}

type RgbLibErrorCannotChangeOnline struct {
}

func NewRgbLibErrorCannotChangeOnline() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotChangeOnline{}}
}

func (e RgbLibErrorCannotChangeOnline) destroy() {
}

func (err RgbLibErrorCannotChangeOnline) Error() string {
	return fmt.Sprint("CannotChangeOnline")
}

func (self RgbLibErrorCannotChangeOnline) Is(target error) bool {
	return target == ErrRgbLibErrorCannotChangeOnline
}

type RgbLibErrorCannotCombinePsbts struct {
}

func NewRgbLibErrorCannotCombinePsbts() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotCombinePsbts{}}
}

func (e RgbLibErrorCannotCombinePsbts) destroy() {
}

func (err RgbLibErrorCannotCombinePsbts) Error() string {
	return fmt.Sprint("CannotCombinePsbts")
}

func (self RgbLibErrorCannotCombinePsbts) Is(target error) bool {
	return target == ErrRgbLibErrorCannotCombinePsbts
}

type RgbLibErrorCannotDeleteBatchTransfer struct {
}

func NewRgbLibErrorCannotDeleteBatchTransfer() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotDeleteBatchTransfer{}}
}

func (e RgbLibErrorCannotDeleteBatchTransfer) destroy() {
}

func (err RgbLibErrorCannotDeleteBatchTransfer) Error() string {
	return fmt.Sprint("CannotDeleteBatchTransfer")
}

func (self RgbLibErrorCannotDeleteBatchTransfer) Is(target error) bool {
	return target == ErrRgbLibErrorCannotDeleteBatchTransfer
}

type RgbLibErrorCannotEstimateFees struct {
}

func NewRgbLibErrorCannotEstimateFees() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotEstimateFees{}}
}

func (e RgbLibErrorCannotEstimateFees) destroy() {
}

func (err RgbLibErrorCannotEstimateFees) Error() string {
	return fmt.Sprint("CannotEstimateFees")
}

func (self RgbLibErrorCannotEstimateFees) Is(target error) bool {
	return target == ErrRgbLibErrorCannotEstimateFees
}

type RgbLibErrorCannotFailBatchTransfer struct {
}

func NewRgbLibErrorCannotFailBatchTransfer() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotFailBatchTransfer{}}
}

func (e RgbLibErrorCannotFailBatchTransfer) destroy() {
}

func (err RgbLibErrorCannotFailBatchTransfer) Error() string {
	return fmt.Sprint("CannotFailBatchTransfer")
}

func (self RgbLibErrorCannotFailBatchTransfer) Is(target error) bool {
	return target == ErrRgbLibErrorCannotFailBatchTransfer
}

type RgbLibErrorCannotFinalizePsbt struct {
}

func NewRgbLibErrorCannotFinalizePsbt() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotFinalizePsbt{}}
}

func (e RgbLibErrorCannotFinalizePsbt) destroy() {
}

func (err RgbLibErrorCannotFinalizePsbt) Error() string {
	return fmt.Sprint("CannotFinalizePsbt")
}

func (self RgbLibErrorCannotFinalizePsbt) Is(target error) bool {
	return target == ErrRgbLibErrorCannotFinalizePsbt
}

type RgbLibErrorCannotUseIfaOnMainnet struct {
}

func NewRgbLibErrorCannotUseIfaOnMainnet() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorCannotUseIfaOnMainnet{}}
}

func (e RgbLibErrorCannotUseIfaOnMainnet) destroy() {
}

func (err RgbLibErrorCannotUseIfaOnMainnet) Error() string {
	return fmt.Sprint("CannotUseIfaOnMainnet")
}

func (self RgbLibErrorCannotUseIfaOnMainnet) Is(target error) bool {
	return target == ErrRgbLibErrorCannotUseIfaOnMainnet
}

type RgbLibErrorDatabase struct {
	Details string
}

func NewRgbLibErrorDatabase(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorDatabase{
		Details: details}}
}

func (e RgbLibErrorDatabase) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorDatabase) Error() string {
	return fmt.Sprint("Database",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorDatabase) Is(target error) bool {
	return target == ErrRgbLibErrorDatabase
}

type RgbLibErrorEmptyFile struct {
	FilePath string
}

func NewRgbLibErrorEmptyFile(
	filePath string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorEmptyFile{
		FilePath: filePath}}
}

func (e RgbLibErrorEmptyFile) destroy() {
	FfiDestroyerString{}.Destroy(e.FilePath)
}

func (err RgbLibErrorEmptyFile) Error() string {
	return fmt.Sprint("EmptyFile",
		": ",

		"FilePath=",
		err.FilePath,
	)
}

func (self RgbLibErrorEmptyFile) Is(target error) bool {
	return target == ErrRgbLibErrorEmptyFile
}

type RgbLibErrorFailedBdkSync struct {
	Details string
}

func NewRgbLibErrorFailedBdkSync(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorFailedBdkSync{
		Details: details}}
}

func (e RgbLibErrorFailedBdkSync) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorFailedBdkSync) Error() string {
	return fmt.Sprint("FailedBdkSync",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorFailedBdkSync) Is(target error) bool {
	return target == ErrRgbLibErrorFailedBdkSync
}

type RgbLibErrorFailedBroadcast struct {
	Details string
}

func NewRgbLibErrorFailedBroadcast(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorFailedBroadcast{
		Details: details}}
}

func (e RgbLibErrorFailedBroadcast) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorFailedBroadcast) Error() string {
	return fmt.Sprint("FailedBroadcast",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorFailedBroadcast) Is(target error) bool {
	return target == ErrRgbLibErrorFailedBroadcast
}

type RgbLibErrorFailedIssuance struct {
	Details string
}

func NewRgbLibErrorFailedIssuance(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorFailedIssuance{
		Details: details}}
}

func (e RgbLibErrorFailedIssuance) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorFailedIssuance) Error() string {
	return fmt.Sprint("FailedIssuance",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorFailedIssuance) Is(target error) bool {
	return target == ErrRgbLibErrorFailedIssuance
}

type RgbLibErrorFileAlreadyExists struct {
	Path string
}

func NewRgbLibErrorFileAlreadyExists(
	path string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorFileAlreadyExists{
		Path: path}}
}

func (e RgbLibErrorFileAlreadyExists) destroy() {
	FfiDestroyerString{}.Destroy(e.Path)
}

func (err RgbLibErrorFileAlreadyExists) Error() string {
	return fmt.Sprint("FileAlreadyExists",
		": ",

		"Path=",
		err.Path,
	)
}

func (self RgbLibErrorFileAlreadyExists) Is(target error) bool {
	return target == ErrRgbLibErrorFileAlreadyExists
}

type RgbLibErrorFingerprintMismatch struct {
}

func NewRgbLibErrorFingerprintMismatch() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorFingerprintMismatch{}}
}

func (e RgbLibErrorFingerprintMismatch) destroy() {
}

func (err RgbLibErrorFingerprintMismatch) Error() string {
	return fmt.Sprint("FingerprintMismatch")
}

func (self RgbLibErrorFingerprintMismatch) Is(target error) bool {
	return target == ErrRgbLibErrorFingerprintMismatch
}

type RgbLibErrorIo struct {
	Details string
}

func NewRgbLibErrorIo(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorIo{
		Details: details}}
}

func (e RgbLibErrorIo) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorIo) Error() string {
	return fmt.Sprint("Io",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorIo) Is(target error) bool {
	return target == ErrRgbLibErrorIo
}

type RgbLibErrorInconsistency struct {
	Details string
}

func NewRgbLibErrorInconsistency(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInconsistency{
		Details: details}}
}

func (e RgbLibErrorInconsistency) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInconsistency) Error() string {
	return fmt.Sprint("Inconsistency",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInconsistency) Is(target error) bool {
	return target == ErrRgbLibErrorInconsistency
}

type RgbLibErrorIndexer struct {
	Details string
}

func NewRgbLibErrorIndexer(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorIndexer{
		Details: details}}
}

func (e RgbLibErrorIndexer) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorIndexer) Error() string {
	return fmt.Sprint("Indexer",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorIndexer) Is(target error) bool {
	return target == ErrRgbLibErrorIndexer
}

type RgbLibErrorInexistentDataDir struct {
}

func NewRgbLibErrorInexistentDataDir() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInexistentDataDir{}}
}

func (e RgbLibErrorInexistentDataDir) destroy() {
}

func (err RgbLibErrorInexistentDataDir) Error() string {
	return fmt.Sprint("InexistentDataDir")
}

func (self RgbLibErrorInexistentDataDir) Is(target error) bool {
	return target == ErrRgbLibErrorInexistentDataDir
}

type RgbLibErrorInsufficientAllocationSlots struct {
}

func NewRgbLibErrorInsufficientAllocationSlots() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInsufficientAllocationSlots{}}
}

func (e RgbLibErrorInsufficientAllocationSlots) destroy() {
}

func (err RgbLibErrorInsufficientAllocationSlots) Error() string {
	return fmt.Sprint("InsufficientAllocationSlots")
}

func (self RgbLibErrorInsufficientAllocationSlots) Is(target error) bool {
	return target == ErrRgbLibErrorInsufficientAllocationSlots
}

type RgbLibErrorInsufficientAssignments struct {
	AssetId   string
	Available AssignmentsCollection
}

func NewRgbLibErrorInsufficientAssignments(
	assetId string,
	available AssignmentsCollection,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInsufficientAssignments{
		AssetId:   assetId,
		Available: available}}
}

func (e RgbLibErrorInsufficientAssignments) destroy() {
	FfiDestroyerString{}.Destroy(e.AssetId)
	FfiDestroyerAssignmentsCollection{}.Destroy(e.Available)
}

func (err RgbLibErrorInsufficientAssignments) Error() string {
	return fmt.Sprint("InsufficientAssignments",
		": ",

		"AssetId=",
		err.AssetId,
		", ",
		"Available=",
		err.Available,
	)
}

func (self RgbLibErrorInsufficientAssignments) Is(target error) bool {
	return target == ErrRgbLibErrorInsufficientAssignments
}

type RgbLibErrorInsufficientBitcoins struct {
	Needed    uint64
	Available uint64
}

func NewRgbLibErrorInsufficientBitcoins(
	needed uint64,
	available uint64,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInsufficientBitcoins{
		Needed:    needed,
		Available: available}}
}

func (e RgbLibErrorInsufficientBitcoins) destroy() {
	FfiDestroyerUint64{}.Destroy(e.Needed)
	FfiDestroyerUint64{}.Destroy(e.Available)
}

func (err RgbLibErrorInsufficientBitcoins) Error() string {
	return fmt.Sprint("InsufficientBitcoins",
		": ",

		"Needed=",
		err.Needed,
		", ",
		"Available=",
		err.Available,
	)
}

func (self RgbLibErrorInsufficientBitcoins) Is(target error) bool {
	return target == ErrRgbLibErrorInsufficientBitcoins
}

type RgbLibErrorInternal struct {
	Details string
}

func NewRgbLibErrorInternal(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInternal{
		Details: details}}
}

func (e RgbLibErrorInternal) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInternal) Error() string {
	return fmt.Sprint("Internal",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInternal) Is(target error) bool {
	return target == ErrRgbLibErrorInternal
}

type RgbLibErrorInvalidAddress struct {
	Details string
}

func NewRgbLibErrorInvalidAddress(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidAddress{
		Details: details}}
}

func (e RgbLibErrorInvalidAddress) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidAddress) Error() string {
	return fmt.Sprint("InvalidAddress",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidAddress) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidAddress
}

type RgbLibErrorInvalidAmountZero struct {
}

func NewRgbLibErrorInvalidAmountZero() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidAmountZero{}}
}

func (e RgbLibErrorInvalidAmountZero) destroy() {
}

func (err RgbLibErrorInvalidAmountZero) Error() string {
	return fmt.Sprint("InvalidAmountZero")
}

func (self RgbLibErrorInvalidAmountZero) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidAmountZero
}

type RgbLibErrorInvalidAssignment struct {
}

func NewRgbLibErrorInvalidAssignment() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidAssignment{}}
}

func (e RgbLibErrorInvalidAssignment) destroy() {
}

func (err RgbLibErrorInvalidAssignment) Error() string {
	return fmt.Sprint("InvalidAssignment")
}

func (self RgbLibErrorInvalidAssignment) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidAssignment
}

type RgbLibErrorInvalidAttachments struct {
	Details string
}

func NewRgbLibErrorInvalidAttachments(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidAttachments{
		Details: details}}
}

func (e RgbLibErrorInvalidAttachments) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidAttachments) Error() string {
	return fmt.Sprint("InvalidAttachments",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidAttachments) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidAttachments
}

type RgbLibErrorInvalidBitcoinKeys struct {
}

func NewRgbLibErrorInvalidBitcoinKeys() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidBitcoinKeys{}}
}

func (e RgbLibErrorInvalidBitcoinKeys) destroy() {
}

func (err RgbLibErrorInvalidBitcoinKeys) Error() string {
	return fmt.Sprint("InvalidBitcoinKeys")
}

func (self RgbLibErrorInvalidBitcoinKeys) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidBitcoinKeys
}

type RgbLibErrorInvalidBitcoinNetwork struct {
	Network string
}

func NewRgbLibErrorInvalidBitcoinNetwork(
	network string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidBitcoinNetwork{
		Network: network}}
}

func (e RgbLibErrorInvalidBitcoinNetwork) destroy() {
	FfiDestroyerString{}.Destroy(e.Network)
}

func (err RgbLibErrorInvalidBitcoinNetwork) Error() string {
	return fmt.Sprint("InvalidBitcoinNetwork",
		": ",

		"Network=",
		err.Network,
	)
}

func (self RgbLibErrorInvalidBitcoinNetwork) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidBitcoinNetwork
}

type RgbLibErrorInvalidColoringInfo struct {
	Details string
}

func NewRgbLibErrorInvalidColoringInfo(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidColoringInfo{
		Details: details}}
}

func (e RgbLibErrorInvalidColoringInfo) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidColoringInfo) Error() string {
	return fmt.Sprint("InvalidColoringInfo",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidColoringInfo) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidColoringInfo
}

type RgbLibErrorInvalidConsignment struct {
}

func NewRgbLibErrorInvalidConsignment() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidConsignment{}}
}

func (e RgbLibErrorInvalidConsignment) destroy() {
}

func (err RgbLibErrorInvalidConsignment) Error() string {
	return fmt.Sprint("InvalidConsignment")
}

func (self RgbLibErrorInvalidConsignment) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidConsignment
}

type RgbLibErrorInvalidContractLink struct {
	Details string
}

func NewRgbLibErrorInvalidContractLink(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidContractLink{
		Details: details}}
}

func (e RgbLibErrorInvalidContractLink) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidContractLink) Error() string {
	return fmt.Sprint("InvalidContractLink",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidContractLink) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidContractLink
}

type RgbLibErrorInvalidCosigner struct {
	Details string
}

func NewRgbLibErrorInvalidCosigner(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidCosigner{
		Details: details}}
}

func (e RgbLibErrorInvalidCosigner) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidCosigner) Error() string {
	return fmt.Sprint("InvalidCosigner",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidCosigner) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidCosigner
}

type RgbLibErrorInvalidDetails struct {
	Details string
}

func NewRgbLibErrorInvalidDetails(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidDetails{
		Details: details}}
}

func (e RgbLibErrorInvalidDetails) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidDetails) Error() string {
	return fmt.Sprint("InvalidDetails",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidDetails) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidDetails
}

type RgbLibErrorInvalidElectrum struct {
	Details string
}

func NewRgbLibErrorInvalidElectrum(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidElectrum{
		Details: details}}
}

func (e RgbLibErrorInvalidElectrum) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidElectrum) Error() string {
	return fmt.Sprint("InvalidElectrum",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidElectrum) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidElectrum
}

type RgbLibErrorInvalidEstimationBlocks struct {
}

func NewRgbLibErrorInvalidEstimationBlocks() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidEstimationBlocks{}}
}

func (e RgbLibErrorInvalidEstimationBlocks) destroy() {
}

func (err RgbLibErrorInvalidEstimationBlocks) Error() string {
	return fmt.Sprint("InvalidEstimationBlocks")
}

func (self RgbLibErrorInvalidEstimationBlocks) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidEstimationBlocks
}

type RgbLibErrorInvalidExpiration struct {
}

func NewRgbLibErrorInvalidExpiration() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidExpiration{}}
}

func (e RgbLibErrorInvalidExpiration) destroy() {
}

func (err RgbLibErrorInvalidExpiration) Error() string {
	return fmt.Sprint("InvalidExpiration")
}

func (self RgbLibErrorInvalidExpiration) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidExpiration
}

type RgbLibErrorInvalidFeeRate struct {
	Details string
}

func NewRgbLibErrorInvalidFeeRate(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidFeeRate{
		Details: details}}
}

func (e RgbLibErrorInvalidFeeRate) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidFeeRate) Error() string {
	return fmt.Sprint("InvalidFeeRate",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidFeeRate) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidFeeRate
}

type RgbLibErrorInvalidFilePath struct {
	FilePath string
}

func NewRgbLibErrorInvalidFilePath(
	filePath string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidFilePath{
		FilePath: filePath}}
}

func (e RgbLibErrorInvalidFilePath) destroy() {
	FfiDestroyerString{}.Destroy(e.FilePath)
}

func (err RgbLibErrorInvalidFilePath) Error() string {
	return fmt.Sprint("InvalidFilePath",
		": ",

		"FilePath=",
		err.FilePath,
	)
}

func (self RgbLibErrorInvalidFilePath) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidFilePath
}

type RgbLibErrorInvalidFingerprint struct {
}

func NewRgbLibErrorInvalidFingerprint() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidFingerprint{}}
}

func (e RgbLibErrorInvalidFingerprint) destroy() {
}

func (err RgbLibErrorInvalidFingerprint) Error() string {
	return fmt.Sprint("InvalidFingerprint")
}

func (self RgbLibErrorInvalidFingerprint) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidFingerprint
}

type RgbLibErrorInvalidIndexer struct {
	Details string
}

func NewRgbLibErrorInvalidIndexer(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidIndexer{
		Details: details}}
}

func (e RgbLibErrorInvalidIndexer) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidIndexer) Error() string {
	return fmt.Sprint("InvalidIndexer",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidIndexer) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidIndexer
}

type RgbLibErrorInvalidInvoice struct {
	Details string
}

func NewRgbLibErrorInvalidInvoice(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidInvoice{
		Details: details}}
}

func (e RgbLibErrorInvalidInvoice) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidInvoice) Error() string {
	return fmt.Sprint("InvalidInvoice",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidInvoice) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidInvoice
}

type RgbLibErrorInvalidMnemonic struct {
	Details string
}

func NewRgbLibErrorInvalidMnemonic(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidMnemonic{
		Details: details}}
}

func (e RgbLibErrorInvalidMnemonic) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidMnemonic) Error() string {
	return fmt.Sprint("InvalidMnemonic",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidMnemonic) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidMnemonic
}

type RgbLibErrorInvalidMultisigThreshold struct {
	Required uint8
	Total    uint8
}

func NewRgbLibErrorInvalidMultisigThreshold(
	required uint8,
	total uint8,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidMultisigThreshold{
		Required: required,
		Total:    total}}
}

func (e RgbLibErrorInvalidMultisigThreshold) destroy() {
	FfiDestroyerUint8{}.Destroy(e.Required)
	FfiDestroyerUint8{}.Destroy(e.Total)
}

func (err RgbLibErrorInvalidMultisigThreshold) Error() string {
	return fmt.Sprint("InvalidMultisigThreshold",
		": ",

		"Required=",
		err.Required,
		", ",
		"Total=",
		err.Total,
	)
}

func (self RgbLibErrorInvalidMultisigThreshold) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidMultisigThreshold
}

type RgbLibErrorInvalidName struct {
	Details string
}

func NewRgbLibErrorInvalidName(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidName{
		Details: details}}
}

func (e RgbLibErrorInvalidName) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidName) Error() string {
	return fmt.Sprint("InvalidName",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidName) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidName
}

type RgbLibErrorInvalidPrecision struct {
	Details string
}

func NewRgbLibErrorInvalidPrecision(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidPrecision{
		Details: details}}
}

func (e RgbLibErrorInvalidPrecision) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidPrecision) Error() string {
	return fmt.Sprint("InvalidPrecision",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidPrecision) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidPrecision
}

type RgbLibErrorInvalidProxyProtocol struct {
	Version string
}

func NewRgbLibErrorInvalidProxyProtocol(
	version string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidProxyProtocol{
		Version: version}}
}

func (e RgbLibErrorInvalidProxyProtocol) destroy() {
	FfiDestroyerString{}.Destroy(e.Version)
}

func (err RgbLibErrorInvalidProxyProtocol) Error() string {
	return fmt.Sprint("InvalidProxyProtocol",
		": ",

		"Version=",
		err.Version,
	)
}

func (self RgbLibErrorInvalidProxyProtocol) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidProxyProtocol
}

type RgbLibErrorInvalidPsbt struct {
	Details string
}

func NewRgbLibErrorInvalidPsbt(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidPsbt{
		Details: details}}
}

func (e RgbLibErrorInvalidPsbt) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidPsbt) Error() string {
	return fmt.Sprint("InvalidPsbt",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidPsbt) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidPsbt
}

type RgbLibErrorInvalidPubkey struct {
	Details string
}

func NewRgbLibErrorInvalidPubkey(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidPubkey{
		Details: details}}
}

func (e RgbLibErrorInvalidPubkey) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidPubkey) Error() string {
	return fmt.Sprint("InvalidPubkey",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidPubkey) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidPubkey
}

type RgbLibErrorInvalidRecipientData struct {
	Details string
}

func NewRgbLibErrorInvalidRecipientData(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidRecipientData{
		Details: details}}
}

func (e RgbLibErrorInvalidRecipientData) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidRecipientData) Error() string {
	return fmt.Sprint("InvalidRecipientData",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidRecipientData) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidRecipientData
}

type RgbLibErrorInvalidRecipientId struct {
}

func NewRgbLibErrorInvalidRecipientId() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidRecipientId{}}
}

func (e RgbLibErrorInvalidRecipientId) destroy() {
}

func (err RgbLibErrorInvalidRecipientId) Error() string {
	return fmt.Sprint("InvalidRecipientId")
}

func (self RgbLibErrorInvalidRecipientId) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidRecipientId
}

type RgbLibErrorInvalidRecipientMap struct {
}

func NewRgbLibErrorInvalidRecipientMap() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidRecipientMap{}}
}

func (e RgbLibErrorInvalidRecipientMap) destroy() {
}

func (err RgbLibErrorInvalidRecipientMap) Error() string {
	return fmt.Sprint("InvalidRecipientMap")
}

func (self RgbLibErrorInvalidRecipientMap) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidRecipientMap
}

type RgbLibErrorInvalidRecipientNetwork struct {
}

func NewRgbLibErrorInvalidRecipientNetwork() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidRecipientNetwork{}}
}

func (e RgbLibErrorInvalidRecipientNetwork) destroy() {
}

func (err RgbLibErrorInvalidRecipientNetwork) Error() string {
	return fmt.Sprint("InvalidRecipientNetwork")
}

func (self RgbLibErrorInvalidRecipientNetwork) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidRecipientNetwork
}

type RgbLibErrorInvalidRejectListUrl struct {
	Details string
}

func NewRgbLibErrorInvalidRejectListUrl(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidRejectListUrl{
		Details: details}}
}

func (e RgbLibErrorInvalidRejectListUrl) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidRejectListUrl) Error() string {
	return fmt.Sprint("InvalidRejectListUrl",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidRejectListUrl) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidRejectListUrl
}

type RgbLibErrorInvalidRightOutpoint struct {
	Details string
}

func NewRgbLibErrorInvalidRightOutpoint(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidRightOutpoint{
		Details: details}}
}

func (e RgbLibErrorInvalidRightOutpoint) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidRightOutpoint) Error() string {
	return fmt.Sprint("InvalidRightOutpoint",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidRightOutpoint) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidRightOutpoint
}

type RgbLibErrorInvalidTicker struct {
	Details string
}

func NewRgbLibErrorInvalidTicker(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidTicker{
		Details: details}}
}

func (e RgbLibErrorInvalidTicker) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidTicker) Error() string {
	return fmt.Sprint("InvalidTicker",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidTicker) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidTicker
}

type RgbLibErrorInvalidTransportEndpoint struct {
	Details string
}

func NewRgbLibErrorInvalidTransportEndpoint(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidTransportEndpoint{
		Details: details}}
}

func (e RgbLibErrorInvalidTransportEndpoint) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidTransportEndpoint) Error() string {
	return fmt.Sprint("InvalidTransportEndpoint",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidTransportEndpoint) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidTransportEndpoint
}

type RgbLibErrorInvalidTransportEndpoints struct {
	Details string
}

func NewRgbLibErrorInvalidTransportEndpoints(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidTransportEndpoints{
		Details: details}}
}

func (e RgbLibErrorInvalidTransportEndpoints) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorInvalidTransportEndpoints) Error() string {
	return fmt.Sprint("InvalidTransportEndpoints",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorInvalidTransportEndpoints) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidTransportEndpoints
}

type RgbLibErrorInvalidTxid struct {
}

func NewRgbLibErrorInvalidTxid() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidTxid{}}
}

func (e RgbLibErrorInvalidTxid) destroy() {
}

func (err RgbLibErrorInvalidTxid) Error() string {
	return fmt.Sprint("InvalidTxid")
}

func (self RgbLibErrorInvalidTxid) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidTxid
}

type RgbLibErrorInvalidVanillaKeychain struct {
}

func NewRgbLibErrorInvalidVanillaKeychain() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidVanillaKeychain{}}
}

func (e RgbLibErrorInvalidVanillaKeychain) destroy() {
}

func (err RgbLibErrorInvalidVanillaKeychain) Error() string {
	return fmt.Sprint("InvalidVanillaKeychain")
}

func (self RgbLibErrorInvalidVanillaKeychain) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidVanillaKeychain
}

type RgbLibErrorInvalidWitnessVersion struct {
	WitnessVersion string
}

func NewRgbLibErrorInvalidWitnessVersion(
	witnessVersion string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorInvalidWitnessVersion{
		WitnessVersion: witnessVersion}}
}

func (e RgbLibErrorInvalidWitnessVersion) destroy() {
	FfiDestroyerString{}.Destroy(e.WitnessVersion)
}

func (err RgbLibErrorInvalidWitnessVersion) Error() string {
	return fmt.Sprint("InvalidWitnessVersion",
		": ",

		"WitnessVersion=",
		err.WitnessVersion,
	)
}

func (self RgbLibErrorInvalidWitnessVersion) Is(target error) bool {
	return target == ErrRgbLibErrorInvalidWitnessVersion
}

type RgbLibErrorMaxFeeExceeded struct {
	Txid string
}

func NewRgbLibErrorMaxFeeExceeded(
	txid string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMaxFeeExceeded{
		Txid: txid}}
}

func (e RgbLibErrorMaxFeeExceeded) destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
}

func (err RgbLibErrorMaxFeeExceeded) Error() string {
	return fmt.Sprint("MaxFeeExceeded",
		": ",

		"Txid=",
		err.Txid,
	)
}

func (self RgbLibErrorMaxFeeExceeded) Is(target error) bool {
	return target == ErrRgbLibErrorMaxFeeExceeded
}

type RgbLibErrorMinFeeNotMet struct {
	Txid string
}

func NewRgbLibErrorMinFeeNotMet(
	txid string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMinFeeNotMet{
		Txid: txid}}
}

func (e RgbLibErrorMinFeeNotMet) destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
}

func (err RgbLibErrorMinFeeNotMet) Error() string {
	return fmt.Sprint("MinFeeNotMet",
		": ",

		"Txid=",
		err.Txid,
	)
}

func (self RgbLibErrorMinFeeNotMet) Is(target error) bool {
	return target == ErrRgbLibErrorMinFeeNotMet
}

type RgbLibErrorMpcProvider struct {
	Details string
}

func NewRgbLibErrorMpcProvider(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMpcProvider{
		Details: details}}
}

func (e RgbLibErrorMpcProvider) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorMpcProvider) Error() string {
	return fmt.Sprint("MpcProvider",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorMpcProvider) Is(target error) bool {
	return target == ErrRgbLibErrorMpcProvider
}

type RgbLibErrorMultisigHubService struct {
	Details string
}

func NewRgbLibErrorMultisigHubService(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigHubService{
		Details: details}}
}

func (e RgbLibErrorMultisigHubService) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorMultisigHubService) Error() string {
	return fmt.Sprint("MultisigHubService",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorMultisigHubService) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigHubService
}

type RgbLibErrorMultisigCannotMarkOperationProcessed struct {
	Details string
}

func NewRgbLibErrorMultisigCannotMarkOperationProcessed(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigCannotMarkOperationProcessed{
		Details: details}}
}

func (e RgbLibErrorMultisigCannotMarkOperationProcessed) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorMultisigCannotMarkOperationProcessed) Error() string {
	return fmt.Sprint("MultisigCannotMarkOperationProcessed",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorMultisigCannotMarkOperationProcessed) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigCannotMarkOperationProcessed
}

type RgbLibErrorMultisigCannotRespondToOperation struct {
	Details string
}

func NewRgbLibErrorMultisigCannotRespondToOperation(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigCannotRespondToOperation{
		Details: details}}
}

func (e RgbLibErrorMultisigCannotRespondToOperation) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorMultisigCannotRespondToOperation) Error() string {
	return fmt.Sprint("MultisigCannotRespondToOperation",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorMultisigCannotRespondToOperation) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigCannotRespondToOperation
}

type RgbLibErrorMultisigOperationInProgress struct {
}

func NewRgbLibErrorMultisigOperationInProgress() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigOperationInProgress{}}
}

func (e RgbLibErrorMultisigOperationInProgress) destroy() {
}

func (err RgbLibErrorMultisigOperationInProgress) Error() string {
	return fmt.Sprint("MultisigOperationInProgress")
}

func (self RgbLibErrorMultisigOperationInProgress) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigOperationInProgress
}

type RgbLibErrorMultisigOperationNotFound struct {
	OperationIdx int32
}

func NewRgbLibErrorMultisigOperationNotFound(
	operationIdx int32,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigOperationNotFound{
		OperationIdx: operationIdx}}
}

func (e RgbLibErrorMultisigOperationNotFound) destroy() {
	FfiDestroyerInt32{}.Destroy(e.OperationIdx)
}

func (err RgbLibErrorMultisigOperationNotFound) Error() string {
	return fmt.Sprint("MultisigOperationNotFound",
		": ",

		"OperationIdx=",
		err.OperationIdx,
	)
}

func (self RgbLibErrorMultisigOperationNotFound) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigOperationNotFound
}

type RgbLibErrorMultisigTransferStatusMismatch struct {
}

func NewRgbLibErrorMultisigTransferStatusMismatch() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigTransferStatusMismatch{}}
}

func (e RgbLibErrorMultisigTransferStatusMismatch) destroy() {
}

func (err RgbLibErrorMultisigTransferStatusMismatch) Error() string {
	return fmt.Sprint("MultisigTransferStatusMismatch")
}

func (self RgbLibErrorMultisigTransferStatusMismatch) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigTransferStatusMismatch
}

type RgbLibErrorMultisigUnexpectedData struct {
	Details string
}

func NewRgbLibErrorMultisigUnexpectedData(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigUnexpectedData{
		Details: details}}
}

func (e RgbLibErrorMultisigUnexpectedData) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorMultisigUnexpectedData) Error() string {
	return fmt.Sprint("MultisigUnexpectedData",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorMultisigUnexpectedData) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigUnexpectedData
}

type RgbLibErrorMultisigUserNotCosigner struct {
}

func NewRgbLibErrorMultisigUserNotCosigner() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorMultisigUserNotCosigner{}}
}

func (e RgbLibErrorMultisigUserNotCosigner) destroy() {
}

func (err RgbLibErrorMultisigUserNotCosigner) Error() string {
	return fmt.Sprint("MultisigUserNotCosigner")
}

func (self RgbLibErrorMultisigUserNotCosigner) Is(target error) bool {
	return target == ErrRgbLibErrorMultisigUserNotCosigner
}

type RgbLibErrorNetwork struct {
	Details string
}

func NewRgbLibErrorNetwork(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNetwork{
		Details: details}}
}

func (e RgbLibErrorNetwork) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorNetwork) Error() string {
	return fmt.Sprint("Network",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorNetwork) Is(target error) bool {
	return target == ErrRgbLibErrorNetwork
}

type RgbLibErrorNoConsignment struct {
}

func NewRgbLibErrorNoConsignment() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoConsignment{}}
}

func (e RgbLibErrorNoConsignment) destroy() {
}

func (err RgbLibErrorNoConsignment) Error() string {
	return fmt.Sprint("NoConsignment")
}

func (self RgbLibErrorNoConsignment) Is(target error) bool {
	return target == ErrRgbLibErrorNoConsignment
}

type RgbLibErrorNoCosignersSupplied struct {
}

func NewRgbLibErrorNoCosignersSupplied() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoCosignersSupplied{}}
}

func (e RgbLibErrorNoCosignersSupplied) destroy() {
}

func (err RgbLibErrorNoCosignersSupplied) Error() string {
	return fmt.Sprint("NoCosignersSupplied")
}

func (self RgbLibErrorNoCosignersSupplied) Is(target error) bool {
	return target == ErrRgbLibErrorNoCosignersSupplied
}

type RgbLibErrorNoBurnAmount struct {
}

func NewRgbLibErrorNoBurnAmount() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoBurnAmount{}}
}

func (e RgbLibErrorNoBurnAmount) destroy() {
}

func (err RgbLibErrorNoBurnAmount) Error() string {
	return fmt.Sprint("NoBurnAmount")
}

func (self RgbLibErrorNoBurnAmount) Is(target error) bool {
	return target == ErrRgbLibErrorNoBurnAmount
}

type RgbLibErrorNoInflationAmounts struct {
}

func NewRgbLibErrorNoInflationAmounts() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoInflationAmounts{}}
}

func (e RgbLibErrorNoInflationAmounts) destroy() {
}

func (err RgbLibErrorNoInflationAmounts) Error() string {
	return fmt.Sprint("NoInflationAmounts")
}

func (self RgbLibErrorNoInflationAmounts) Is(target error) bool {
	return target == ErrRgbLibErrorNoInflationAmounts
}

type RgbLibErrorNoIssuanceAmounts struct {
}

func NewRgbLibErrorNoIssuanceAmounts() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoIssuanceAmounts{}}
}

func (e RgbLibErrorNoIssuanceAmounts) destroy() {
}

func (err RgbLibErrorNoIssuanceAmounts) Error() string {
	return fmt.Sprint("NoIssuanceAmounts")
}

func (self RgbLibErrorNoIssuanceAmounts) Is(target error) bool {
	return target == ErrRgbLibErrorNoIssuanceAmounts
}

type RgbLibErrorNoKeysSupplied struct {
}

func NewRgbLibErrorNoKeysSupplied() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoKeysSupplied{}}
}

func (e RgbLibErrorNoKeysSupplied) destroy() {
}

func (err RgbLibErrorNoKeysSupplied) Error() string {
	return fmt.Sprint("NoKeysSupplied")
}

func (self RgbLibErrorNoKeysSupplied) Is(target error) bool {
	return target == ErrRgbLibErrorNoKeysSupplied
}

type RgbLibErrorNoSupportedSchemas struct {
}

func NewRgbLibErrorNoSupportedSchemas() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoSupportedSchemas{}}
}

func (e RgbLibErrorNoSupportedSchemas) destroy() {
}

func (err RgbLibErrorNoSupportedSchemas) Error() string {
	return fmt.Sprint("NoSupportedSchemas")
}

func (self RgbLibErrorNoSupportedSchemas) Is(target error) bool {
	return target == ErrRgbLibErrorNoSupportedSchemas
}

type RgbLibErrorNoValidTransportEndpoint struct {
}

func NewRgbLibErrorNoValidTransportEndpoint() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorNoValidTransportEndpoint{}}
}

func (e RgbLibErrorNoValidTransportEndpoint) destroy() {
}

func (err RgbLibErrorNoValidTransportEndpoint) Error() string {
	return fmt.Sprint("NoValidTransportEndpoint")
}

func (self RgbLibErrorNoValidTransportEndpoint) Is(target error) bool {
	return target == ErrRgbLibErrorNoValidTransportEndpoint
}

type RgbLibErrorOffline struct {
}

func NewRgbLibErrorOffline() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorOffline{}}
}

func (e RgbLibErrorOffline) destroy() {
}

func (err RgbLibErrorOffline) Error() string {
	return fmt.Sprint("Offline")
}

func (self RgbLibErrorOffline) Is(target error) bool {
	return target == ErrRgbLibErrorOffline
}

type RgbLibErrorOnlineNeeded struct {
}

func NewRgbLibErrorOnlineNeeded() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorOnlineNeeded{}}
}

func (e RgbLibErrorOnlineNeeded) destroy() {
}

func (err RgbLibErrorOnlineNeeded) Error() string {
	return fmt.Sprint("OnlineNeeded")
}

func (self RgbLibErrorOnlineNeeded) Is(target error) bool {
	return target == ErrRgbLibErrorOnlineNeeded
}

type RgbLibErrorOutputBelowDustLimit struct {
}

func NewRgbLibErrorOutputBelowDustLimit() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorOutputBelowDustLimit{}}
}

func (e RgbLibErrorOutputBelowDustLimit) destroy() {
}

func (err RgbLibErrorOutputBelowDustLimit) Error() string {
	return fmt.Sprint("OutputBelowDustLimit")
}

func (self RgbLibErrorOutputBelowDustLimit) Is(target error) bool {
	return target == ErrRgbLibErrorOutputBelowDustLimit
}

type RgbLibErrorProxy struct {
	Details string
}

func NewRgbLibErrorProxy(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorProxy{
		Details: details}}
}

func (e RgbLibErrorProxy) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorProxy) Error() string {
	return fmt.Sprint("Proxy",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorProxy) Is(target error) bool {
	return target == ErrRgbLibErrorProxy
}

type RgbLibErrorPsbtInspection struct {
	Details string
}

func NewRgbLibErrorPsbtInspection(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorPsbtInspection{
		Details: details}}
}

func (e RgbLibErrorPsbtInspection) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorPsbtInspection) Error() string {
	return fmt.Sprint("PsbtInspection",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorPsbtInspection) Is(target error) bool {
	return target == ErrRgbLibErrorPsbtInspection
}

type RgbLibErrorRecipientIdAlreadyUsed struct {
}

func NewRgbLibErrorRecipientIdAlreadyUsed() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorRecipientIdAlreadyUsed{}}
}

func (e RgbLibErrorRecipientIdAlreadyUsed) destroy() {
}

func (err RgbLibErrorRecipientIdAlreadyUsed) Error() string {
	return fmt.Sprint("RecipientIdAlreadyUsed")
}

func (self RgbLibErrorRecipientIdAlreadyUsed) Is(target error) bool {
	return target == ErrRgbLibErrorRecipientIdAlreadyUsed
}

type RgbLibErrorRecipientIdDuplicated struct {
}

func NewRgbLibErrorRecipientIdDuplicated() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorRecipientIdDuplicated{}}
}

func (e RgbLibErrorRecipientIdDuplicated) destroy() {
}

func (err RgbLibErrorRecipientIdDuplicated) Error() string {
	return fmt.Sprint("RecipientIdDuplicated")
}

func (self RgbLibErrorRecipientIdDuplicated) Is(target error) bool {
	return target == ErrRgbLibErrorRecipientIdDuplicated
}

type RgbLibErrorRejectListService struct {
	Details string
}

func NewRgbLibErrorRejectListService(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorRejectListService{
		Details: details}}
}

func (e RgbLibErrorRejectListService) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorRejectListService) Error() string {
	return fmt.Sprint("RejectListService",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorRejectListService) Is(target error) bool {
	return target == ErrRgbLibErrorRejectListService
}

type RgbLibErrorRestClientBuild struct {
	Details string
}

func NewRgbLibErrorRestClientBuild(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorRestClientBuild{
		Details: details}}
}

func (e RgbLibErrorRestClientBuild) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorRestClientBuild) Error() string {
	return fmt.Sprint("RestClientBuild",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorRestClientBuild) Is(target error) bool {
	return target == ErrRgbLibErrorRestClientBuild
}

type RgbLibErrorRestoredBackupInconsistent struct {
	Details string
}

func NewRgbLibErrorRestoredBackupInconsistent(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorRestoredBackupInconsistent{
		Details: details}}
}

func (e RgbLibErrorRestoredBackupInconsistent) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorRestoredBackupInconsistent) Error() string {
	return fmt.Sprint("RestoredBackupInconsistent",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorRestoredBackupInconsistent) Is(target error) bool {
	return target == ErrRgbLibErrorRestoredBackupInconsistent
}

type RgbLibErrorRgbInspection struct {
	Details string
}

func NewRgbLibErrorRgbInspection(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorRgbInspection{
		Details: details}}
}

func (e RgbLibErrorRgbInspection) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorRgbInspection) Error() string {
	return fmt.Sprint("RgbInspection",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorRgbInspection) Is(target error) bool {
	return target == ErrRgbLibErrorRgbInspection
}

type RgbLibErrorTooHighInflationAmounts struct {
}

func NewRgbLibErrorTooHighInflationAmounts() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorTooHighInflationAmounts{}}
}

func (e RgbLibErrorTooHighInflationAmounts) destroy() {
}

func (err RgbLibErrorTooHighInflationAmounts) Error() string {
	return fmt.Sprint("TooHighInflationAmounts")
}

func (self RgbLibErrorTooHighInflationAmounts) Is(target error) bool {
	return target == ErrRgbLibErrorTooHighInflationAmounts
}

type RgbLibErrorTooHighIssuanceAmounts struct {
}

func NewRgbLibErrorTooHighIssuanceAmounts() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorTooHighIssuanceAmounts{}}
}

func (e RgbLibErrorTooHighIssuanceAmounts) destroy() {
}

func (err RgbLibErrorTooHighIssuanceAmounts) Error() string {
	return fmt.Sprint("TooHighIssuanceAmounts")
}

func (self RgbLibErrorTooHighIssuanceAmounts) Is(target error) bool {
	return target == ErrRgbLibErrorTooHighIssuanceAmounts
}

type RgbLibErrorTooManyCosigners struct {
}

func NewRgbLibErrorTooManyCosigners() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorTooManyCosigners{}}
}

func (e RgbLibErrorTooManyCosigners) destroy() {
}

func (err RgbLibErrorTooManyCosigners) Error() string {
	return fmt.Sprint("TooManyCosigners")
}

func (self RgbLibErrorTooManyCosigners) Is(target error) bool {
	return target == ErrRgbLibErrorTooManyCosigners
}

type RgbLibErrorTooManySignaturesInPsbt struct {
}

func NewRgbLibErrorTooManySignaturesInPsbt() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorTooManySignaturesInPsbt{}}
}

func (e RgbLibErrorTooManySignaturesInPsbt) destroy() {
}

func (err RgbLibErrorTooManySignaturesInPsbt) Error() string {
	return fmt.Sprint("TooManySignaturesInPsbt")
}

func (self RgbLibErrorTooManySignaturesInPsbt) Is(target error) bool {
	return target == ErrRgbLibErrorTooManySignaturesInPsbt
}

type RgbLibErrorUnknownRgbSchema struct {
	SchemaId string
}

func NewRgbLibErrorUnknownRgbSchema(
	schemaId string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnknownRgbSchema{
		SchemaId: schemaId}}
}

func (e RgbLibErrorUnknownRgbSchema) destroy() {
	FfiDestroyerString{}.Destroy(e.SchemaId)
}

func (err RgbLibErrorUnknownRgbSchema) Error() string {
	return fmt.Sprint("UnknownRgbSchema",
		": ",

		"SchemaId=",
		err.SchemaId,
	)
}

func (self RgbLibErrorUnknownRgbSchema) Is(target error) bool {
	return target == ErrRgbLibErrorUnknownRgbSchema
}

type RgbLibErrorUnknownTransfer struct {
	Txid string
}

func NewRgbLibErrorUnknownTransfer(
	txid string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnknownTransfer{
		Txid: txid}}
}

func (e RgbLibErrorUnknownTransfer) destroy() {
	FfiDestroyerString{}.Destroy(e.Txid)
}

func (err RgbLibErrorUnknownTransfer) Error() string {
	return fmt.Sprint("UnknownTransfer",
		": ",

		"Txid=",
		err.Txid,
	)
}

func (self RgbLibErrorUnknownTransfer) Is(target error) bool {
	return target == ErrRgbLibErrorUnknownTransfer
}

type RgbLibErrorUnsupportedBackupVersion struct {
	Version string
}

func NewRgbLibErrorUnsupportedBackupVersion(
	version string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnsupportedBackupVersion{
		Version: version}}
}

func (e RgbLibErrorUnsupportedBackupVersion) destroy() {
	FfiDestroyerString{}.Destroy(e.Version)
}

func (err RgbLibErrorUnsupportedBackupVersion) Error() string {
	return fmt.Sprint("UnsupportedBackupVersion",
		": ",

		"Version=",
		err.Version,
	)
}

func (self RgbLibErrorUnsupportedBackupVersion) Is(target error) bool {
	return target == ErrRgbLibErrorUnsupportedBackupVersion
}

type RgbLibErrorUnsupportedBurn struct {
	AssetSchema AssetSchema
}

func NewRgbLibErrorUnsupportedBurn(
	assetSchema AssetSchema,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnsupportedBurn{
		AssetSchema: assetSchema}}
}

func (e RgbLibErrorUnsupportedBurn) destroy() {
	FfiDestroyerAssetSchema{}.Destroy(e.AssetSchema)
}

func (err RgbLibErrorUnsupportedBurn) Error() string {
	return fmt.Sprint("UnsupportedBurn",
		": ",

		"AssetSchema=",
		err.AssetSchema,
	)
}

func (self RgbLibErrorUnsupportedBurn) Is(target error) bool {
	return target == ErrRgbLibErrorUnsupportedBurn
}

type RgbLibErrorUnsupportedInflation struct {
	AssetSchema AssetSchema
}

func NewRgbLibErrorUnsupportedInflation(
	assetSchema AssetSchema,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnsupportedInflation{
		AssetSchema: assetSchema}}
}

func (e RgbLibErrorUnsupportedInflation) destroy() {
	FfiDestroyerAssetSchema{}.Destroy(e.AssetSchema)
}

func (err RgbLibErrorUnsupportedInflation) Error() string {
	return fmt.Sprint("UnsupportedInflation",
		": ",

		"AssetSchema=",
		err.AssetSchema,
	)
}

func (self RgbLibErrorUnsupportedInflation) Is(target error) bool {
	return target == ErrRgbLibErrorUnsupportedInflation
}

type RgbLibErrorUnsupportedLayer1 struct {
	Layer1 string
}

func NewRgbLibErrorUnsupportedLayer1(
	layer1 string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnsupportedLayer1{
		Layer1: layer1}}
}

func (e RgbLibErrorUnsupportedLayer1) destroy() {
	FfiDestroyerString{}.Destroy(e.Layer1)
}

func (err RgbLibErrorUnsupportedLayer1) Error() string {
	return fmt.Sprint("UnsupportedLayer1",
		": ",

		"Layer1=",
		err.Layer1,
	)
}

func (self RgbLibErrorUnsupportedLayer1) Is(target error) bool {
	return target == ErrRgbLibErrorUnsupportedLayer1
}

type RgbLibErrorUnsupportedSchema struct {
	AssetSchema AssetSchema
}

func NewRgbLibErrorUnsupportedSchema(
	assetSchema AssetSchema,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnsupportedSchema{
		AssetSchema: assetSchema}}
}

func (e RgbLibErrorUnsupportedSchema) destroy() {
	FfiDestroyerAssetSchema{}.Destroy(e.AssetSchema)
}

func (err RgbLibErrorUnsupportedSchema) Error() string {
	return fmt.Sprint("UnsupportedSchema",
		": ",

		"AssetSchema=",
		err.AssetSchema,
	)
}

func (self RgbLibErrorUnsupportedSchema) Is(target error) bool {
	return target == ErrRgbLibErrorUnsupportedSchema
}

type RgbLibErrorUnsupportedTransportType struct {
}

func NewRgbLibErrorUnsupportedTransportType() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorUnsupportedTransportType{}}
}

func (e RgbLibErrorUnsupportedTransportType) destroy() {
}

func (err RgbLibErrorUnsupportedTransportType) Error() string {
	return fmt.Sprint("UnsupportedTransportType")
}

func (self RgbLibErrorUnsupportedTransportType) Is(target error) bool {
	return target == ErrRgbLibErrorUnsupportedTransportType
}

type RgbLibErrorVssAuth struct {
	Details string
}

func NewRgbLibErrorVssAuth(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorVssAuth{
		Details: details}}
}

func (e RgbLibErrorVssAuth) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorVssAuth) Error() string {
	return fmt.Sprint("VssAuth",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorVssAuth) Is(target error) bool {
	return target == ErrRgbLibErrorVssAuth
}

type RgbLibErrorVssBackupNotFound struct {
}

func NewRgbLibErrorVssBackupNotFound() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorVssBackupNotFound{}}
}

func (e RgbLibErrorVssBackupNotFound) destroy() {
}

func (err RgbLibErrorVssBackupNotFound) Error() string {
	return fmt.Sprint("VssBackupNotFound")
}

func (self RgbLibErrorVssBackupNotFound) Is(target error) bool {
	return target == ErrRgbLibErrorVssBackupNotFound
}

type RgbLibErrorVssError struct {
	Details string
}

func NewRgbLibErrorVssError(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorVssError{
		Details: details}}
}

func (e RgbLibErrorVssError) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorVssError) Error() string {
	return fmt.Sprint("VssError",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorVssError) Is(target error) bool {
	return target == ErrRgbLibErrorVssError
}

type RgbLibErrorVssVersionConflict struct {
	Details string
}

func NewRgbLibErrorVssVersionConflict(
	details string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorVssVersionConflict{
		Details: details}}
}

func (e RgbLibErrorVssVersionConflict) destroy() {
	FfiDestroyerString{}.Destroy(e.Details)
}

func (err RgbLibErrorVssVersionConflict) Error() string {
	return fmt.Sprint("VssVersionConflict",
		": ",

		"Details=",
		err.Details,
	)
}

func (self RgbLibErrorVssVersionConflict) Is(target error) bool {
	return target == ErrRgbLibErrorVssVersionConflict
}

type RgbLibErrorWalletDirAlreadyExists struct {
	Path string
}

func NewRgbLibErrorWalletDirAlreadyExists(
	path string,
) *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorWalletDirAlreadyExists{
		Path: path}}
}

func (e RgbLibErrorWalletDirAlreadyExists) destroy() {
	FfiDestroyerString{}.Destroy(e.Path)
}

func (err RgbLibErrorWalletDirAlreadyExists) Error() string {
	return fmt.Sprint("WalletDirAlreadyExists",
		": ",

		"Path=",
		err.Path,
	)
}

func (self RgbLibErrorWalletDirAlreadyExists) Is(target error) bool {
	return target == ErrRgbLibErrorWalletDirAlreadyExists
}

type RgbLibErrorWatchOnly struct {
}

func NewRgbLibErrorWatchOnly() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorWatchOnly{}}
}

func (e RgbLibErrorWatchOnly) destroy() {
}

func (err RgbLibErrorWatchOnly) Error() string {
	return fmt.Sprint("WatchOnly")
}

func (self RgbLibErrorWatchOnly) Is(target error) bool {
	return target == ErrRgbLibErrorWatchOnly
}

type RgbLibErrorWrongPassword struct {
}

func NewRgbLibErrorWrongPassword() *RgbLibError {
	return &RgbLibError{err: &RgbLibErrorWrongPassword{}}
}

func (e RgbLibErrorWrongPassword) destroy() {
}

func (err RgbLibErrorWrongPassword) Error() string {
	return fmt.Sprint("WrongPassword")
}

func (self RgbLibErrorWrongPassword) Is(target error) bool {
	return target == ErrRgbLibErrorWrongPassword
}

type FfiConverterRgbLibError struct{}

var FfiConverterRgbLibErrorINSTANCE = FfiConverterRgbLibError{}

func (c FfiConverterRgbLibError) Lift(eb RustBufferI) *RgbLibError {
	return LiftFromRustBuffer[*RgbLibError](c, eb)
}

func (c FfiConverterRgbLibError) Lower(value *RgbLibError) C.RustBuffer {
	return LowerIntoRustBuffer[*RgbLibError](c, value)
}

func (c FfiConverterRgbLibError) LowerExternal(value *RgbLibError) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*RgbLibError](c, value))
}

func (c FfiConverterRgbLibError) Read(reader io.Reader) *RgbLibError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &RgbLibError{&RgbLibErrorAddressReuseDisabled{}}
	case 2:
		return &RgbLibError{&RgbLibErrorAllocationsAlreadyAvailable{}}
	case 3:
		return &RgbLibError{&RgbLibErrorAssetNotFound{
			AssetId: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 4:
		return &RgbLibError{&RgbLibErrorBatchTransferNotFound{
			Idx: FfiConverterInt32INSTANCE.Read(reader),
		}}
	case 5:
		return &RgbLibError{&RgbLibErrorBitcoinNetworkMismatch{}}
	case 6:
		return &RgbLibError{&RgbLibErrorCannotAbortPendingVanillaTx{}}
	case 7:
		return &RgbLibError{&RgbLibErrorCannotChangeOnline{}}
	case 8:
		return &RgbLibError{&RgbLibErrorCannotCombinePsbts{}}
	case 9:
		return &RgbLibError{&RgbLibErrorCannotDeleteBatchTransfer{}}
	case 10:
		return &RgbLibError{&RgbLibErrorCannotEstimateFees{}}
	case 11:
		return &RgbLibError{&RgbLibErrorCannotFailBatchTransfer{}}
	case 12:
		return &RgbLibError{&RgbLibErrorCannotFinalizePsbt{}}
	case 13:
		return &RgbLibError{&RgbLibErrorCannotUseIfaOnMainnet{}}
	case 14:
		return &RgbLibError{&RgbLibErrorDatabase{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 15:
		return &RgbLibError{&RgbLibErrorEmptyFile{
			FilePath: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 16:
		return &RgbLibError{&RgbLibErrorFailedBdkSync{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 17:
		return &RgbLibError{&RgbLibErrorFailedBroadcast{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 18:
		return &RgbLibError{&RgbLibErrorFailedIssuance{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 19:
		return &RgbLibError{&RgbLibErrorFileAlreadyExists{
			Path: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 20:
		return &RgbLibError{&RgbLibErrorFingerprintMismatch{}}
	case 21:
		return &RgbLibError{&RgbLibErrorIo{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 22:
		return &RgbLibError{&RgbLibErrorInconsistency{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 23:
		return &RgbLibError{&RgbLibErrorIndexer{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 24:
		return &RgbLibError{&RgbLibErrorInexistentDataDir{}}
	case 25:
		return &RgbLibError{&RgbLibErrorInsufficientAllocationSlots{}}
	case 26:
		return &RgbLibError{&RgbLibErrorInsufficientAssignments{
			AssetId:   FfiConverterStringINSTANCE.Read(reader),
			Available: FfiConverterAssignmentsCollectionINSTANCE.Read(reader),
		}}
	case 27:
		return &RgbLibError{&RgbLibErrorInsufficientBitcoins{
			Needed:    FfiConverterUint64INSTANCE.Read(reader),
			Available: FfiConverterUint64INSTANCE.Read(reader),
		}}
	case 28:
		return &RgbLibError{&RgbLibErrorInternal{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 29:
		return &RgbLibError{&RgbLibErrorInvalidAddress{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 30:
		return &RgbLibError{&RgbLibErrorInvalidAmountZero{}}
	case 31:
		return &RgbLibError{&RgbLibErrorInvalidAssignment{}}
	case 32:
		return &RgbLibError{&RgbLibErrorInvalidAttachments{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 33:
		return &RgbLibError{&RgbLibErrorInvalidBitcoinKeys{}}
	case 34:
		return &RgbLibError{&RgbLibErrorInvalidBitcoinNetwork{
			Network: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 35:
		return &RgbLibError{&RgbLibErrorInvalidColoringInfo{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 36:
		return &RgbLibError{&RgbLibErrorInvalidConsignment{}}
	case 37:
		return &RgbLibError{&RgbLibErrorInvalidContractLink{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 38:
		return &RgbLibError{&RgbLibErrorInvalidCosigner{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 39:
		return &RgbLibError{&RgbLibErrorInvalidDetails{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 40:
		return &RgbLibError{&RgbLibErrorInvalidElectrum{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 41:
		return &RgbLibError{&RgbLibErrorInvalidEstimationBlocks{}}
	case 42:
		return &RgbLibError{&RgbLibErrorInvalidExpiration{}}
	case 43:
		return &RgbLibError{&RgbLibErrorInvalidFeeRate{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 44:
		return &RgbLibError{&RgbLibErrorInvalidFilePath{
			FilePath: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 45:
		return &RgbLibError{&RgbLibErrorInvalidFingerprint{}}
	case 46:
		return &RgbLibError{&RgbLibErrorInvalidIndexer{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 47:
		return &RgbLibError{&RgbLibErrorInvalidInvoice{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 48:
		return &RgbLibError{&RgbLibErrorInvalidMnemonic{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 49:
		return &RgbLibError{&RgbLibErrorInvalidMultisigThreshold{
			Required: FfiConverterUint8INSTANCE.Read(reader),
			Total:    FfiConverterUint8INSTANCE.Read(reader),
		}}
	case 50:
		return &RgbLibError{&RgbLibErrorInvalidName{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 51:
		return &RgbLibError{&RgbLibErrorInvalidPrecision{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 52:
		return &RgbLibError{&RgbLibErrorInvalidProxyProtocol{
			Version: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 53:
		return &RgbLibError{&RgbLibErrorInvalidPsbt{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 54:
		return &RgbLibError{&RgbLibErrorInvalidPubkey{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 55:
		return &RgbLibError{&RgbLibErrorInvalidRecipientData{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 56:
		return &RgbLibError{&RgbLibErrorInvalidRecipientId{}}
	case 57:
		return &RgbLibError{&RgbLibErrorInvalidRecipientMap{}}
	case 58:
		return &RgbLibError{&RgbLibErrorInvalidRecipientNetwork{}}
	case 59:
		return &RgbLibError{&RgbLibErrorInvalidRejectListUrl{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 60:
		return &RgbLibError{&RgbLibErrorInvalidRightOutpoint{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 61:
		return &RgbLibError{&RgbLibErrorInvalidTicker{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 62:
		return &RgbLibError{&RgbLibErrorInvalidTransportEndpoint{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 63:
		return &RgbLibError{&RgbLibErrorInvalidTransportEndpoints{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 64:
		return &RgbLibError{&RgbLibErrorInvalidTxid{}}
	case 65:
		return &RgbLibError{&RgbLibErrorInvalidVanillaKeychain{}}
	case 66:
		return &RgbLibError{&RgbLibErrorInvalidWitnessVersion{
			WitnessVersion: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 67:
		return &RgbLibError{&RgbLibErrorMaxFeeExceeded{
			Txid: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 68:
		return &RgbLibError{&RgbLibErrorMinFeeNotMet{
			Txid: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 69:
		return &RgbLibError{&RgbLibErrorMpcProvider{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 70:
		return &RgbLibError{&RgbLibErrorMultisigHubService{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 71:
		return &RgbLibError{&RgbLibErrorMultisigCannotMarkOperationProcessed{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 72:
		return &RgbLibError{&RgbLibErrorMultisigCannotRespondToOperation{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 73:
		return &RgbLibError{&RgbLibErrorMultisigOperationInProgress{}}
	case 74:
		return &RgbLibError{&RgbLibErrorMultisigOperationNotFound{
			OperationIdx: FfiConverterInt32INSTANCE.Read(reader),
		}}
	case 75:
		return &RgbLibError{&RgbLibErrorMultisigTransferStatusMismatch{}}
	case 76:
		return &RgbLibError{&RgbLibErrorMultisigUnexpectedData{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 77:
		return &RgbLibError{&RgbLibErrorMultisigUserNotCosigner{}}
	case 78:
		return &RgbLibError{&RgbLibErrorNetwork{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 79:
		return &RgbLibError{&RgbLibErrorNoConsignment{}}
	case 80:
		return &RgbLibError{&RgbLibErrorNoCosignersSupplied{}}
	case 81:
		return &RgbLibError{&RgbLibErrorNoBurnAmount{}}
	case 82:
		return &RgbLibError{&RgbLibErrorNoInflationAmounts{}}
	case 83:
		return &RgbLibError{&RgbLibErrorNoIssuanceAmounts{}}
	case 84:
		return &RgbLibError{&RgbLibErrorNoKeysSupplied{}}
	case 85:
		return &RgbLibError{&RgbLibErrorNoSupportedSchemas{}}
	case 86:
		return &RgbLibError{&RgbLibErrorNoValidTransportEndpoint{}}
	case 87:
		return &RgbLibError{&RgbLibErrorOffline{}}
	case 88:
		return &RgbLibError{&RgbLibErrorOnlineNeeded{}}
	case 89:
		return &RgbLibError{&RgbLibErrorOutputBelowDustLimit{}}
	case 90:
		return &RgbLibError{&RgbLibErrorProxy{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 91:
		return &RgbLibError{&RgbLibErrorPsbtInspection{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 92:
		return &RgbLibError{&RgbLibErrorRecipientIdAlreadyUsed{}}
	case 93:
		return &RgbLibError{&RgbLibErrorRecipientIdDuplicated{}}
	case 94:
		return &RgbLibError{&RgbLibErrorRejectListService{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 95:
		return &RgbLibError{&RgbLibErrorRestClientBuild{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 96:
		return &RgbLibError{&RgbLibErrorRestoredBackupInconsistent{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 97:
		return &RgbLibError{&RgbLibErrorRgbInspection{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 98:
		return &RgbLibError{&RgbLibErrorTooHighInflationAmounts{}}
	case 99:
		return &RgbLibError{&RgbLibErrorTooHighIssuanceAmounts{}}
	case 100:
		return &RgbLibError{&RgbLibErrorTooManyCosigners{}}
	case 101:
		return &RgbLibError{&RgbLibErrorTooManySignaturesInPsbt{}}
	case 102:
		return &RgbLibError{&RgbLibErrorUnknownRgbSchema{
			SchemaId: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 103:
		return &RgbLibError{&RgbLibErrorUnknownTransfer{
			Txid: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 104:
		return &RgbLibError{&RgbLibErrorUnsupportedBackupVersion{
			Version: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 105:
		return &RgbLibError{&RgbLibErrorUnsupportedBurn{
			AssetSchema: FfiConverterAssetSchemaINSTANCE.Read(reader),
		}}
	case 106:
		return &RgbLibError{&RgbLibErrorUnsupportedInflation{
			AssetSchema: FfiConverterAssetSchemaINSTANCE.Read(reader),
		}}
	case 107:
		return &RgbLibError{&RgbLibErrorUnsupportedLayer1{
			Layer1: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 108:
		return &RgbLibError{&RgbLibErrorUnsupportedSchema{
			AssetSchema: FfiConverterAssetSchemaINSTANCE.Read(reader),
		}}
	case 109:
		return &RgbLibError{&RgbLibErrorUnsupportedTransportType{}}
	case 110:
		return &RgbLibError{&RgbLibErrorVssAuth{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 111:
		return &RgbLibError{&RgbLibErrorVssBackupNotFound{}}
	case 112:
		return &RgbLibError{&RgbLibErrorVssError{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 113:
		return &RgbLibError{&RgbLibErrorVssVersionConflict{
			Details: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 114:
		return &RgbLibError{&RgbLibErrorWalletDirAlreadyExists{
			Path: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 115:
		return &RgbLibError{&RgbLibErrorWatchOnly{}}
	case 116:
		return &RgbLibError{&RgbLibErrorWrongPassword{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterRgbLibError.Read()", errorID))
	}
}

func (c FfiConverterRgbLibError) Write(writer io.Writer, value *RgbLibError) {
	switch variantValue := value.err.(type) {
	case *RgbLibErrorAddressReuseDisabled:
		writeInt32(writer, 1)
	case *RgbLibErrorAllocationsAlreadyAvailable:
		writeInt32(writer, 2)
	case *RgbLibErrorAssetNotFound:
		writeInt32(writer, 3)
		FfiConverterStringINSTANCE.Write(writer, variantValue.AssetId)
	case *RgbLibErrorBatchTransferNotFound:
		writeInt32(writer, 4)
		FfiConverterInt32INSTANCE.Write(writer, variantValue.Idx)
	case *RgbLibErrorBitcoinNetworkMismatch:
		writeInt32(writer, 5)
	case *RgbLibErrorCannotAbortPendingVanillaTx:
		writeInt32(writer, 6)
	case *RgbLibErrorCannotChangeOnline:
		writeInt32(writer, 7)
	case *RgbLibErrorCannotCombinePsbts:
		writeInt32(writer, 8)
	case *RgbLibErrorCannotDeleteBatchTransfer:
		writeInt32(writer, 9)
	case *RgbLibErrorCannotEstimateFees:
		writeInt32(writer, 10)
	case *RgbLibErrorCannotFailBatchTransfer:
		writeInt32(writer, 11)
	case *RgbLibErrorCannotFinalizePsbt:
		writeInt32(writer, 12)
	case *RgbLibErrorCannotUseIfaOnMainnet:
		writeInt32(writer, 13)
	case *RgbLibErrorDatabase:
		writeInt32(writer, 14)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorEmptyFile:
		writeInt32(writer, 15)
		FfiConverterStringINSTANCE.Write(writer, variantValue.FilePath)
	case *RgbLibErrorFailedBdkSync:
		writeInt32(writer, 16)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorFailedBroadcast:
		writeInt32(writer, 17)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorFailedIssuance:
		writeInt32(writer, 18)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorFileAlreadyExists:
		writeInt32(writer, 19)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Path)
	case *RgbLibErrorFingerprintMismatch:
		writeInt32(writer, 20)
	case *RgbLibErrorIo:
		writeInt32(writer, 21)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInconsistency:
		writeInt32(writer, 22)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorIndexer:
		writeInt32(writer, 23)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInexistentDataDir:
		writeInt32(writer, 24)
	case *RgbLibErrorInsufficientAllocationSlots:
		writeInt32(writer, 25)
	case *RgbLibErrorInsufficientAssignments:
		writeInt32(writer, 26)
		FfiConverterStringINSTANCE.Write(writer, variantValue.AssetId)
		FfiConverterAssignmentsCollectionINSTANCE.Write(writer, variantValue.Available)
	case *RgbLibErrorInsufficientBitcoins:
		writeInt32(writer, 27)
		FfiConverterUint64INSTANCE.Write(writer, variantValue.Needed)
		FfiConverterUint64INSTANCE.Write(writer, variantValue.Available)
	case *RgbLibErrorInternal:
		writeInt32(writer, 28)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidAddress:
		writeInt32(writer, 29)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidAmountZero:
		writeInt32(writer, 30)
	case *RgbLibErrorInvalidAssignment:
		writeInt32(writer, 31)
	case *RgbLibErrorInvalidAttachments:
		writeInt32(writer, 32)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidBitcoinKeys:
		writeInt32(writer, 33)
	case *RgbLibErrorInvalidBitcoinNetwork:
		writeInt32(writer, 34)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Network)
	case *RgbLibErrorInvalidColoringInfo:
		writeInt32(writer, 35)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidConsignment:
		writeInt32(writer, 36)
	case *RgbLibErrorInvalidContractLink:
		writeInt32(writer, 37)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidCosigner:
		writeInt32(writer, 38)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidDetails:
		writeInt32(writer, 39)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidElectrum:
		writeInt32(writer, 40)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidEstimationBlocks:
		writeInt32(writer, 41)
	case *RgbLibErrorInvalidExpiration:
		writeInt32(writer, 42)
	case *RgbLibErrorInvalidFeeRate:
		writeInt32(writer, 43)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidFilePath:
		writeInt32(writer, 44)
		FfiConverterStringINSTANCE.Write(writer, variantValue.FilePath)
	case *RgbLibErrorInvalidFingerprint:
		writeInt32(writer, 45)
	case *RgbLibErrorInvalidIndexer:
		writeInt32(writer, 46)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidInvoice:
		writeInt32(writer, 47)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidMnemonic:
		writeInt32(writer, 48)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidMultisigThreshold:
		writeInt32(writer, 49)
		FfiConverterUint8INSTANCE.Write(writer, variantValue.Required)
		FfiConverterUint8INSTANCE.Write(writer, variantValue.Total)
	case *RgbLibErrorInvalidName:
		writeInt32(writer, 50)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidPrecision:
		writeInt32(writer, 51)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidProxyProtocol:
		writeInt32(writer, 52)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Version)
	case *RgbLibErrorInvalidPsbt:
		writeInt32(writer, 53)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidPubkey:
		writeInt32(writer, 54)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidRecipientData:
		writeInt32(writer, 55)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidRecipientId:
		writeInt32(writer, 56)
	case *RgbLibErrorInvalidRecipientMap:
		writeInt32(writer, 57)
	case *RgbLibErrorInvalidRecipientNetwork:
		writeInt32(writer, 58)
	case *RgbLibErrorInvalidRejectListUrl:
		writeInt32(writer, 59)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidRightOutpoint:
		writeInt32(writer, 60)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidTicker:
		writeInt32(writer, 61)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidTransportEndpoint:
		writeInt32(writer, 62)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidTransportEndpoints:
		writeInt32(writer, 63)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorInvalidTxid:
		writeInt32(writer, 64)
	case *RgbLibErrorInvalidVanillaKeychain:
		writeInt32(writer, 65)
	case *RgbLibErrorInvalidWitnessVersion:
		writeInt32(writer, 66)
		FfiConverterStringINSTANCE.Write(writer, variantValue.WitnessVersion)
	case *RgbLibErrorMaxFeeExceeded:
		writeInt32(writer, 67)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Txid)
	case *RgbLibErrorMinFeeNotMet:
		writeInt32(writer, 68)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Txid)
	case *RgbLibErrorMpcProvider:
		writeInt32(writer, 69)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorMultisigHubService:
		writeInt32(writer, 70)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorMultisigCannotMarkOperationProcessed:
		writeInt32(writer, 71)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorMultisigCannotRespondToOperation:
		writeInt32(writer, 72)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorMultisigOperationInProgress:
		writeInt32(writer, 73)
	case *RgbLibErrorMultisigOperationNotFound:
		writeInt32(writer, 74)
		FfiConverterInt32INSTANCE.Write(writer, variantValue.OperationIdx)
	case *RgbLibErrorMultisigTransferStatusMismatch:
		writeInt32(writer, 75)
	case *RgbLibErrorMultisigUnexpectedData:
		writeInt32(writer, 76)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorMultisigUserNotCosigner:
		writeInt32(writer, 77)
	case *RgbLibErrorNetwork:
		writeInt32(writer, 78)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorNoConsignment:
		writeInt32(writer, 79)
	case *RgbLibErrorNoCosignersSupplied:
		writeInt32(writer, 80)
	case *RgbLibErrorNoBurnAmount:
		writeInt32(writer, 81)
	case *RgbLibErrorNoInflationAmounts:
		writeInt32(writer, 82)
	case *RgbLibErrorNoIssuanceAmounts:
		writeInt32(writer, 83)
	case *RgbLibErrorNoKeysSupplied:
		writeInt32(writer, 84)
	case *RgbLibErrorNoSupportedSchemas:
		writeInt32(writer, 85)
	case *RgbLibErrorNoValidTransportEndpoint:
		writeInt32(writer, 86)
	case *RgbLibErrorOffline:
		writeInt32(writer, 87)
	case *RgbLibErrorOnlineNeeded:
		writeInt32(writer, 88)
	case *RgbLibErrorOutputBelowDustLimit:
		writeInt32(writer, 89)
	case *RgbLibErrorProxy:
		writeInt32(writer, 90)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorPsbtInspection:
		writeInt32(writer, 91)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorRecipientIdAlreadyUsed:
		writeInt32(writer, 92)
	case *RgbLibErrorRecipientIdDuplicated:
		writeInt32(writer, 93)
	case *RgbLibErrorRejectListService:
		writeInt32(writer, 94)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorRestClientBuild:
		writeInt32(writer, 95)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorRestoredBackupInconsistent:
		writeInt32(writer, 96)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorRgbInspection:
		writeInt32(writer, 97)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorTooHighInflationAmounts:
		writeInt32(writer, 98)
	case *RgbLibErrorTooHighIssuanceAmounts:
		writeInt32(writer, 99)
	case *RgbLibErrorTooManyCosigners:
		writeInt32(writer, 100)
	case *RgbLibErrorTooManySignaturesInPsbt:
		writeInt32(writer, 101)
	case *RgbLibErrorUnknownRgbSchema:
		writeInt32(writer, 102)
		FfiConverterStringINSTANCE.Write(writer, variantValue.SchemaId)
	case *RgbLibErrorUnknownTransfer:
		writeInt32(writer, 103)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Txid)
	case *RgbLibErrorUnsupportedBackupVersion:
		writeInt32(writer, 104)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Version)
	case *RgbLibErrorUnsupportedBurn:
		writeInt32(writer, 105)
		FfiConverterAssetSchemaINSTANCE.Write(writer, variantValue.AssetSchema)
	case *RgbLibErrorUnsupportedInflation:
		writeInt32(writer, 106)
		FfiConverterAssetSchemaINSTANCE.Write(writer, variantValue.AssetSchema)
	case *RgbLibErrorUnsupportedLayer1:
		writeInt32(writer, 107)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Layer1)
	case *RgbLibErrorUnsupportedSchema:
		writeInt32(writer, 108)
		FfiConverterAssetSchemaINSTANCE.Write(writer, variantValue.AssetSchema)
	case *RgbLibErrorUnsupportedTransportType:
		writeInt32(writer, 109)
	case *RgbLibErrorVssAuth:
		writeInt32(writer, 110)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorVssBackupNotFound:
		writeInt32(writer, 111)
	case *RgbLibErrorVssError:
		writeInt32(writer, 112)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorVssVersionConflict:
		writeInt32(writer, 113)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Details)
	case *RgbLibErrorWalletDirAlreadyExists:
		writeInt32(writer, 114)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Path)
	case *RgbLibErrorWatchOnly:
		writeInt32(writer, 115)
	case *RgbLibErrorWrongPassword:
		writeInt32(writer, 116)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterRgbLibError.Write", value))
	}
}

type FfiDestroyerRgbLibError struct{}

func (_ FfiDestroyerRgbLibError) Destroy(value *RgbLibError) {
	switch variantValue := value.err.(type) {
	case RgbLibErrorAddressReuseDisabled:
		variantValue.destroy()
	case RgbLibErrorAllocationsAlreadyAvailable:
		variantValue.destroy()
	case RgbLibErrorAssetNotFound:
		variantValue.destroy()
	case RgbLibErrorBatchTransferNotFound:
		variantValue.destroy()
	case RgbLibErrorBitcoinNetworkMismatch:
		variantValue.destroy()
	case RgbLibErrorCannotAbortPendingVanillaTx:
		variantValue.destroy()
	case RgbLibErrorCannotChangeOnline:
		variantValue.destroy()
	case RgbLibErrorCannotCombinePsbts:
		variantValue.destroy()
	case RgbLibErrorCannotDeleteBatchTransfer:
		variantValue.destroy()
	case RgbLibErrorCannotEstimateFees:
		variantValue.destroy()
	case RgbLibErrorCannotFailBatchTransfer:
		variantValue.destroy()
	case RgbLibErrorCannotFinalizePsbt:
		variantValue.destroy()
	case RgbLibErrorCannotUseIfaOnMainnet:
		variantValue.destroy()
	case RgbLibErrorDatabase:
		variantValue.destroy()
	case RgbLibErrorEmptyFile:
		variantValue.destroy()
	case RgbLibErrorFailedBdkSync:
		variantValue.destroy()
	case RgbLibErrorFailedBroadcast:
		variantValue.destroy()
	case RgbLibErrorFailedIssuance:
		variantValue.destroy()
	case RgbLibErrorFileAlreadyExists:
		variantValue.destroy()
	case RgbLibErrorFingerprintMismatch:
		variantValue.destroy()
	case RgbLibErrorIo:
		variantValue.destroy()
	case RgbLibErrorInconsistency:
		variantValue.destroy()
	case RgbLibErrorIndexer:
		variantValue.destroy()
	case RgbLibErrorInexistentDataDir:
		variantValue.destroy()
	case RgbLibErrorInsufficientAllocationSlots:
		variantValue.destroy()
	case RgbLibErrorInsufficientAssignments:
		variantValue.destroy()
	case RgbLibErrorInsufficientBitcoins:
		variantValue.destroy()
	case RgbLibErrorInternal:
		variantValue.destroy()
	case RgbLibErrorInvalidAddress:
		variantValue.destroy()
	case RgbLibErrorInvalidAmountZero:
		variantValue.destroy()
	case RgbLibErrorInvalidAssignment:
		variantValue.destroy()
	case RgbLibErrorInvalidAttachments:
		variantValue.destroy()
	case RgbLibErrorInvalidBitcoinKeys:
		variantValue.destroy()
	case RgbLibErrorInvalidBitcoinNetwork:
		variantValue.destroy()
	case RgbLibErrorInvalidColoringInfo:
		variantValue.destroy()
	case RgbLibErrorInvalidConsignment:
		variantValue.destroy()
	case RgbLibErrorInvalidContractLink:
		variantValue.destroy()
	case RgbLibErrorInvalidCosigner:
		variantValue.destroy()
	case RgbLibErrorInvalidDetails:
		variantValue.destroy()
	case RgbLibErrorInvalidElectrum:
		variantValue.destroy()
	case RgbLibErrorInvalidEstimationBlocks:
		variantValue.destroy()
	case RgbLibErrorInvalidExpiration:
		variantValue.destroy()
	case RgbLibErrorInvalidFeeRate:
		variantValue.destroy()
	case RgbLibErrorInvalidFilePath:
		variantValue.destroy()
	case RgbLibErrorInvalidFingerprint:
		variantValue.destroy()
	case RgbLibErrorInvalidIndexer:
		variantValue.destroy()
	case RgbLibErrorInvalidInvoice:
		variantValue.destroy()
	case RgbLibErrorInvalidMnemonic:
		variantValue.destroy()
	case RgbLibErrorInvalidMultisigThreshold:
		variantValue.destroy()
	case RgbLibErrorInvalidName:
		variantValue.destroy()
	case RgbLibErrorInvalidPrecision:
		variantValue.destroy()
	case RgbLibErrorInvalidProxyProtocol:
		variantValue.destroy()
	case RgbLibErrorInvalidPsbt:
		variantValue.destroy()
	case RgbLibErrorInvalidPubkey:
		variantValue.destroy()
	case RgbLibErrorInvalidRecipientData:
		variantValue.destroy()
	case RgbLibErrorInvalidRecipientId:
		variantValue.destroy()
	case RgbLibErrorInvalidRecipientMap:
		variantValue.destroy()
	case RgbLibErrorInvalidRecipientNetwork:
		variantValue.destroy()
	case RgbLibErrorInvalidRejectListUrl:
		variantValue.destroy()
	case RgbLibErrorInvalidRightOutpoint:
		variantValue.destroy()
	case RgbLibErrorInvalidTicker:
		variantValue.destroy()
	case RgbLibErrorInvalidTransportEndpoint:
		variantValue.destroy()
	case RgbLibErrorInvalidTransportEndpoints:
		variantValue.destroy()
	case RgbLibErrorInvalidTxid:
		variantValue.destroy()
	case RgbLibErrorInvalidVanillaKeychain:
		variantValue.destroy()
	case RgbLibErrorInvalidWitnessVersion:
		variantValue.destroy()
	case RgbLibErrorMaxFeeExceeded:
		variantValue.destroy()
	case RgbLibErrorMinFeeNotMet:
		variantValue.destroy()
	case RgbLibErrorMpcProvider:
		variantValue.destroy()
	case RgbLibErrorMultisigHubService:
		variantValue.destroy()
	case RgbLibErrorMultisigCannotMarkOperationProcessed:
		variantValue.destroy()
	case RgbLibErrorMultisigCannotRespondToOperation:
		variantValue.destroy()
	case RgbLibErrorMultisigOperationInProgress:
		variantValue.destroy()
	case RgbLibErrorMultisigOperationNotFound:
		variantValue.destroy()
	case RgbLibErrorMultisigTransferStatusMismatch:
		variantValue.destroy()
	case RgbLibErrorMultisigUnexpectedData:
		variantValue.destroy()
	case RgbLibErrorMultisigUserNotCosigner:
		variantValue.destroy()
	case RgbLibErrorNetwork:
		variantValue.destroy()
	case RgbLibErrorNoConsignment:
		variantValue.destroy()
	case RgbLibErrorNoCosignersSupplied:
		variantValue.destroy()
	case RgbLibErrorNoBurnAmount:
		variantValue.destroy()
	case RgbLibErrorNoInflationAmounts:
		variantValue.destroy()
	case RgbLibErrorNoIssuanceAmounts:
		variantValue.destroy()
	case RgbLibErrorNoKeysSupplied:
		variantValue.destroy()
	case RgbLibErrorNoSupportedSchemas:
		variantValue.destroy()
	case RgbLibErrorNoValidTransportEndpoint:
		variantValue.destroy()
	case RgbLibErrorOffline:
		variantValue.destroy()
	case RgbLibErrorOnlineNeeded:
		variantValue.destroy()
	case RgbLibErrorOutputBelowDustLimit:
		variantValue.destroy()
	case RgbLibErrorProxy:
		variantValue.destroy()
	case RgbLibErrorPsbtInspection:
		variantValue.destroy()
	case RgbLibErrorRecipientIdAlreadyUsed:
		variantValue.destroy()
	case RgbLibErrorRecipientIdDuplicated:
		variantValue.destroy()
	case RgbLibErrorRejectListService:
		variantValue.destroy()
	case RgbLibErrorRestClientBuild:
		variantValue.destroy()
	case RgbLibErrorRestoredBackupInconsistent:
		variantValue.destroy()
	case RgbLibErrorRgbInspection:
		variantValue.destroy()
	case RgbLibErrorTooHighInflationAmounts:
		variantValue.destroy()
	case RgbLibErrorTooHighIssuanceAmounts:
		variantValue.destroy()
	case RgbLibErrorTooManyCosigners:
		variantValue.destroy()
	case RgbLibErrorTooManySignaturesInPsbt:
		variantValue.destroy()
	case RgbLibErrorUnknownRgbSchema:
		variantValue.destroy()
	case RgbLibErrorUnknownTransfer:
		variantValue.destroy()
	case RgbLibErrorUnsupportedBackupVersion:
		variantValue.destroy()
	case RgbLibErrorUnsupportedBurn:
		variantValue.destroy()
	case RgbLibErrorUnsupportedInflation:
		variantValue.destroy()
	case RgbLibErrorUnsupportedLayer1:
		variantValue.destroy()
	case RgbLibErrorUnsupportedSchema:
		variantValue.destroy()
	case RgbLibErrorUnsupportedTransportType:
		variantValue.destroy()
	case RgbLibErrorVssAuth:
		variantValue.destroy()
	case RgbLibErrorVssBackupNotFound:
		variantValue.destroy()
	case RgbLibErrorVssError:
		variantValue.destroy()
	case RgbLibErrorVssVersionConflict:
		variantValue.destroy()
	case RgbLibErrorWalletDirAlreadyExists:
		variantValue.destroy()
	case RgbLibErrorWatchOnly:
		variantValue.destroy()
	case RgbLibErrorWrongPassword:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerRgbLibError.Destroy", value))
	}
}

type SyncKeychain interface {
	Destroy()
}
type SyncKeychainColored struct {
}

func (e SyncKeychainColored) Destroy() {
}

type SyncKeychainVanilla struct {
	Lookback uint32
}

func (e SyncKeychainVanilla) Destroy() {
	FfiDestroyerUint32{}.Destroy(e.Lookback)
}

type FfiConverterSyncKeychain struct{}

var FfiConverterSyncKeychainINSTANCE = FfiConverterSyncKeychain{}

func (c FfiConverterSyncKeychain) Lift(rb RustBufferI) SyncKeychain {
	return LiftFromRustBuffer[SyncKeychain](c, rb)
}

func (c FfiConverterSyncKeychain) Lower(value SyncKeychain) C.RustBuffer {
	return LowerIntoRustBuffer[SyncKeychain](c, value)
}

func (c FfiConverterSyncKeychain) LowerExternal(value SyncKeychain) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[SyncKeychain](c, value))
}
func (FfiConverterSyncKeychain) Read(reader io.Reader) SyncKeychain {
	id := readInt32(reader)
	switch id {
	case 1:
		return SyncKeychainColored{}
	case 2:
		return SyncKeychainVanilla{
			FfiConverterUint32INSTANCE.Read(reader),
		}
	default:
		panic(fmt.Sprintf("invalid enum value %v in FfiConverterSyncKeychain.Read()", id))
	}
}

func (FfiConverterSyncKeychain) Write(writer io.Writer, value SyncKeychain) {
	switch variant_value := value.(type) {
	case SyncKeychainColored:
		writeInt32(writer, 1)
	case SyncKeychainVanilla:
		writeInt32(writer, 2)
		FfiConverterUint32INSTANCE.Write(writer, variant_value.Lookback)
	default:
		_ = variant_value
		panic(fmt.Sprintf("invalid enum value `%v` in FfiConverterSyncKeychain.Write", value))
	}
}

type FfiDestroyerSyncKeychain struct{}

func (_ FfiDestroyerSyncKeychain) Destroy(value SyncKeychain) {
	value.Destroy()
}

type SyncStrategy uint

const (
	SyncStrategyFullScan SyncStrategy = 1
	SyncStrategyFullSync SyncStrategy = 2
	SyncStrategyFastSync SyncStrategy = 3
)

type FfiConverterSyncStrategy struct{}

var FfiConverterSyncStrategyINSTANCE = FfiConverterSyncStrategy{}

func (c FfiConverterSyncStrategy) Lift(rb RustBufferI) SyncStrategy {
	return LiftFromRustBuffer[SyncStrategy](c, rb)
}

func (c FfiConverterSyncStrategy) Lower(value SyncStrategy) C.RustBuffer {
	return LowerIntoRustBuffer[SyncStrategy](c, value)
}

func (c FfiConverterSyncStrategy) LowerExternal(value SyncStrategy) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[SyncStrategy](c, value))
}
func (FfiConverterSyncStrategy) Read(reader io.Reader) SyncStrategy {
	id := readInt32(reader)
	return SyncStrategy(id)
}

func (FfiConverterSyncStrategy) Write(writer io.Writer, value SyncStrategy) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerSyncStrategy struct{}

func (_ FfiDestroyerSyncStrategy) Destroy(value SyncStrategy) {
}

type TransactionType uint

const (
	TransactionTypeRgbSend     TransactionType = 1
	TransactionTypeDrain       TransactionType = 2
	TransactionTypeCreateUtxos TransactionType = 3
	TransactionTypeSendBtc     TransactionType = 4
	TransactionTypeIncoming    TransactionType = 5
)

type FfiConverterTransactionType struct{}

var FfiConverterTransactionTypeINSTANCE = FfiConverterTransactionType{}

func (c FfiConverterTransactionType) Lift(rb RustBufferI) TransactionType {
	return LiftFromRustBuffer[TransactionType](c, rb)
}

func (c FfiConverterTransactionType) Lower(value TransactionType) C.RustBuffer {
	return LowerIntoRustBuffer[TransactionType](c, value)
}

func (c FfiConverterTransactionType) LowerExternal(value TransactionType) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[TransactionType](c, value))
}
func (FfiConverterTransactionType) Read(reader io.Reader) TransactionType {
	id := readInt32(reader)
	return TransactionType(id)
}

func (FfiConverterTransactionType) Write(writer io.Writer, value TransactionType) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerTransactionType struct{}

func (_ FfiDestroyerTransactionType) Destroy(value TransactionType) {
}

type TransferKind uint

const (
	TransferKindIssuance       TransferKind = 1
	TransferKindReceiveBlind   TransferKind = 2
	TransferKindReceiveWitness TransferKind = 3
	TransferKindSend           TransferKind = 4
	TransferKindInflation      TransferKind = 5
	TransferKindBurn           TransferKind = 6
	TransferKindLink           TransferKind = 7
)

type FfiConverterTransferKind struct{}

var FfiConverterTransferKindINSTANCE = FfiConverterTransferKind{}

func (c FfiConverterTransferKind) Lift(rb RustBufferI) TransferKind {
	return LiftFromRustBuffer[TransferKind](c, rb)
}

func (c FfiConverterTransferKind) Lower(value TransferKind) C.RustBuffer {
	return LowerIntoRustBuffer[TransferKind](c, value)
}

func (c FfiConverterTransferKind) LowerExternal(value TransferKind) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[TransferKind](c, value))
}
func (FfiConverterTransferKind) Read(reader io.Reader) TransferKind {
	id := readInt32(reader)
	return TransferKind(id)
}

func (FfiConverterTransferKind) Write(writer io.Writer, value TransferKind) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerTransferKind struct{}

func (_ FfiDestroyerTransferKind) Destroy(value TransferKind) {
}

type TransferStatus uint

const (
	TransferStatusWaitingCounterparty  TransferStatus = 1
	TransferStatusWaitingSafeHeight    TransferStatus = 2
	TransferStatusWaitingConfirmations TransferStatus = 3
	TransferStatusSettled              TransferStatus = 4
	TransferStatusFailed               TransferStatus = 5
	TransferStatusInitiated            TransferStatus = 6
)

type FfiConverterTransferStatus struct{}

var FfiConverterTransferStatusINSTANCE = FfiConverterTransferStatus{}

func (c FfiConverterTransferStatus) Lift(rb RustBufferI) TransferStatus {
	return LiftFromRustBuffer[TransferStatus](c, rb)
}

func (c FfiConverterTransferStatus) Lower(value TransferStatus) C.RustBuffer {
	return LowerIntoRustBuffer[TransferStatus](c, value)
}

func (c FfiConverterTransferStatus) LowerExternal(value TransferStatus) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[TransferStatus](c, value))
}
func (FfiConverterTransferStatus) Read(reader io.Reader) TransferStatus {
	id := readInt32(reader)
	return TransferStatus(id)
}

func (FfiConverterTransferStatus) Write(writer io.Writer, value TransferStatus) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerTransferStatus struct{}

func (_ FfiDestroyerTransferStatus) Destroy(value TransferStatus) {
}

type TransportType uint

const (
	TransportTypeJsonRpc TransportType = 1
)

type FfiConverterTransportType struct{}

var FfiConverterTransportTypeINSTANCE = FfiConverterTransportType{}

func (c FfiConverterTransportType) Lift(rb RustBufferI) TransportType {
	return LiftFromRustBuffer[TransportType](c, rb)
}

func (c FfiConverterTransportType) Lower(value TransportType) C.RustBuffer {
	return LowerIntoRustBuffer[TransportType](c, value)
}

func (c FfiConverterTransportType) LowerExternal(value TransportType) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[TransportType](c, value))
}
func (FfiConverterTransportType) Read(reader io.Reader) TransportType {
	id := readInt32(reader)
	return TransportType(id)
}

func (FfiConverterTransportType) Write(writer io.Writer, value TransportType) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerTransportType struct{}

func (_ FfiDestroyerTransportType) Destroy(value TransportType) {
}

type TypeOfTransition uint

const (
	TypeOfTransitionInflate  TypeOfTransition = 1
	TypeOfTransitionTransfer TypeOfTransition = 2
	TypeOfTransitionBurn     TypeOfTransition = 3
	TypeOfTransitionLink     TypeOfTransition = 4
)

type FfiConverterTypeOfTransition struct{}

var FfiConverterTypeOfTransitionINSTANCE = FfiConverterTypeOfTransition{}

func (c FfiConverterTypeOfTransition) Lift(rb RustBufferI) TypeOfTransition {
	return LiftFromRustBuffer[TypeOfTransition](c, rb)
}

func (c FfiConverterTypeOfTransition) Lower(value TypeOfTransition) C.RustBuffer {
	return LowerIntoRustBuffer[TypeOfTransition](c, value)
}

func (c FfiConverterTypeOfTransition) LowerExternal(value TypeOfTransition) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[TypeOfTransition](c, value))
}
func (FfiConverterTypeOfTransition) Read(reader io.Reader) TypeOfTransition {
	id := readInt32(reader)
	return TypeOfTransition(id)
}

func (FfiConverterTypeOfTransition) Write(writer io.Writer, value TypeOfTransition) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerTypeOfTransition struct{}

func (_ FfiDestroyerTypeOfTransition) Destroy(value TypeOfTransition) {
}

type UserRole uint

const (
	UserRoleCosigner  UserRole = 1
	UserRoleWatchOnly UserRole = 2
)

type FfiConverterUserRole struct{}

var FfiConverterUserRoleINSTANCE = FfiConverterUserRole{}

func (c FfiConverterUserRole) Lift(rb RustBufferI) UserRole {
	return LiftFromRustBuffer[UserRole](c, rb)
}

func (c FfiConverterUserRole) Lower(value UserRole) C.RustBuffer {
	return LowerIntoRustBuffer[UserRole](c, value)
}

func (c FfiConverterUserRole) LowerExternal(value UserRole) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[UserRole](c, value))
}
func (FfiConverterUserRole) Read(reader io.Reader) UserRole {
	id := readInt32(reader)
	return UserRole(id)
}

func (FfiConverterUserRole) Write(writer io.Writer, value UserRole) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerUserRole struct{}

func (_ FfiDestroyerUserRole) Destroy(value UserRole) {
}

type VssBackupMode uint

const (
	VssBackupModeAsync    VssBackupMode = 1
	VssBackupModeBlocking VssBackupMode = 2
)

type FfiConverterVssBackupMode struct{}

var FfiConverterVssBackupModeINSTANCE = FfiConverterVssBackupMode{}

func (c FfiConverterVssBackupMode) Lift(rb RustBufferI) VssBackupMode {
	return LiftFromRustBuffer[VssBackupMode](c, rb)
}

func (c FfiConverterVssBackupMode) Lower(value VssBackupMode) C.RustBuffer {
	return LowerIntoRustBuffer[VssBackupMode](c, value)
}

func (c FfiConverterVssBackupMode) LowerExternal(value VssBackupMode) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[VssBackupMode](c, value))
}
func (FfiConverterVssBackupMode) Read(reader io.Reader) VssBackupMode {
	id := readInt32(reader)
	return VssBackupMode(id)
}

func (FfiConverterVssBackupMode) Write(writer io.Writer, value VssBackupMode) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerVssBackupMode struct{}

func (_ FfiDestroyerVssBackupMode) Destroy(value VssBackupMode) {
}

type WalletTransactionType uint

const (
	WalletTransactionTypeCreateUtxos WalletTransactionType = 1
	WalletTransactionTypeDrain       WalletTransactionType = 2
	WalletTransactionTypeSendBtc     WalletTransactionType = 3
)

type FfiConverterWalletTransactionType struct{}

var FfiConverterWalletTransactionTypeINSTANCE = FfiConverterWalletTransactionType{}

func (c FfiConverterWalletTransactionType) Lift(rb RustBufferI) WalletTransactionType {
	return LiftFromRustBuffer[WalletTransactionType](c, rb)
}

func (c FfiConverterWalletTransactionType) Lower(value WalletTransactionType) C.RustBuffer {
	return LowerIntoRustBuffer[WalletTransactionType](c, value)
}

func (c FfiConverterWalletTransactionType) LowerExternal(value WalletTransactionType) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[WalletTransactionType](c, value))
}
func (FfiConverterWalletTransactionType) Read(reader io.Reader) WalletTransactionType {
	id := readInt32(reader)
	return WalletTransactionType(id)
}

func (FfiConverterWalletTransactionType) Write(writer io.Writer, value WalletTransactionType) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerWalletTransactionType struct{}

func (_ FfiDestroyerWalletTransactionType) Destroy(value WalletTransactionType) {
}

type WitnessVersion uint

const (
	WitnessVersionSegWitV0 WitnessVersion = 1
	WitnessVersionTaproot  WitnessVersion = 2
)

type FfiConverterWitnessVersion struct{}

var FfiConverterWitnessVersionINSTANCE = FfiConverterWitnessVersion{}

func (c FfiConverterWitnessVersion) Lift(rb RustBufferI) WitnessVersion {
	return LiftFromRustBuffer[WitnessVersion](c, rb)
}

func (c FfiConverterWitnessVersion) Lower(value WitnessVersion) C.RustBuffer {
	return LowerIntoRustBuffer[WitnessVersion](c, value)
}

func (c FfiConverterWitnessVersion) LowerExternal(value WitnessVersion) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[WitnessVersion](c, value))
}
func (FfiConverterWitnessVersion) Read(reader io.Reader) WitnessVersion {
	id := readInt32(reader)
	return WitnessVersion(id)
}

func (FfiConverterWitnessVersion) Write(writer io.Writer, value WitnessVersion) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerWitnessVersion struct{}

func (_ FfiDestroyerWitnessVersion) Destroy(value WitnessVersion) {
}

type FfiConverterOptionalUint8 struct{}

var FfiConverterOptionalUint8INSTANCE = FfiConverterOptionalUint8{}

func (c FfiConverterOptionalUint8) Lift(rb RustBufferI) *uint8 {
	return LiftFromRustBuffer[*uint8](c, rb)
}

func (_ FfiConverterOptionalUint8) Read(reader io.Reader) *uint8 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint8INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint8) Lower(value *uint8) C.RustBuffer {
	return LowerIntoRustBuffer[*uint8](c, value)
}

func (c FfiConverterOptionalUint8) LowerExternal(value *uint8) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*uint8](c, value))
}

func (_ FfiConverterOptionalUint8) Write(writer io.Writer, value *uint8) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint8INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint8 struct{}

func (_ FfiDestroyerOptionalUint8) Destroy(value *uint8) {
	if value != nil {
		FfiDestroyerUint8{}.Destroy(*value)
	}
}

type FfiConverterOptionalUint32 struct{}

var FfiConverterOptionalUint32INSTANCE = FfiConverterOptionalUint32{}

func (c FfiConverterOptionalUint32) Lift(rb RustBufferI) *uint32 {
	return LiftFromRustBuffer[*uint32](c, rb)
}

func (_ FfiConverterOptionalUint32) Read(reader io.Reader) *uint32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint32INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint32) Lower(value *uint32) C.RustBuffer {
	return LowerIntoRustBuffer[*uint32](c, value)
}

func (c FfiConverterOptionalUint32) LowerExternal(value *uint32) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*uint32](c, value))
}

func (_ FfiConverterOptionalUint32) Write(writer io.Writer, value *uint32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint32INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint32 struct{}

func (_ FfiDestroyerOptionalUint32) Destroy(value *uint32) {
	if value != nil {
		FfiDestroyerUint32{}.Destroy(*value)
	}
}

type FfiConverterOptionalInt32 struct{}

var FfiConverterOptionalInt32INSTANCE = FfiConverterOptionalInt32{}

func (c FfiConverterOptionalInt32) Lift(rb RustBufferI) *int32 {
	return LiftFromRustBuffer[*int32](c, rb)
}

func (_ FfiConverterOptionalInt32) Read(reader io.Reader) *int32 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterInt32INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalInt32) Lower(value *int32) C.RustBuffer {
	return LowerIntoRustBuffer[*int32](c, value)
}

func (c FfiConverterOptionalInt32) LowerExternal(value *int32) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*int32](c, value))
}

func (_ FfiConverterOptionalInt32) Write(writer io.Writer, value *int32) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterInt32INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalInt32 struct{}

func (_ FfiDestroyerOptionalInt32) Destroy(value *int32) {
	if value != nil {
		FfiDestroyerInt32{}.Destroy(*value)
	}
}

type FfiConverterOptionalUint64 struct{}

var FfiConverterOptionalUint64INSTANCE = FfiConverterOptionalUint64{}

func (c FfiConverterOptionalUint64) Lift(rb RustBufferI) *uint64 {
	return LiftFromRustBuffer[*uint64](c, rb)
}

func (_ FfiConverterOptionalUint64) Read(reader io.Reader) *uint64 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterUint64INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalUint64) Lower(value *uint64) C.RustBuffer {
	return LowerIntoRustBuffer[*uint64](c, value)
}

func (c FfiConverterOptionalUint64) LowerExternal(value *uint64) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*uint64](c, value))
}

func (_ FfiConverterOptionalUint64) Write(writer io.Writer, value *uint64) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterUint64INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalUint64 struct{}

func (_ FfiDestroyerOptionalUint64) Destroy(value *uint64) {
	if value != nil {
		FfiDestroyerUint64{}.Destroy(*value)
	}
}

type FfiConverterOptionalInt64 struct{}

var FfiConverterOptionalInt64INSTANCE = FfiConverterOptionalInt64{}

func (c FfiConverterOptionalInt64) Lift(rb RustBufferI) *int64 {
	return LiftFromRustBuffer[*int64](c, rb)
}

func (_ FfiConverterOptionalInt64) Read(reader io.Reader) *int64 {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterInt64INSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalInt64) Lower(value *int64) C.RustBuffer {
	return LowerIntoRustBuffer[*int64](c, value)
}

func (c FfiConverterOptionalInt64) LowerExternal(value *int64) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*int64](c, value))
}

func (_ FfiConverterOptionalInt64) Write(writer io.Writer, value *int64) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterInt64INSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalInt64 struct{}

func (_ FfiDestroyerOptionalInt64) Destroy(value *int64) {
	if value != nil {
		FfiDestroyerInt64{}.Destroy(*value)
	}
}

type FfiConverterOptionalBool struct{}

var FfiConverterOptionalBoolINSTANCE = FfiConverterOptionalBool{}

func (c FfiConverterOptionalBool) Lift(rb RustBufferI) *bool {
	return LiftFromRustBuffer[*bool](c, rb)
}

func (_ FfiConverterOptionalBool) Read(reader io.Reader) *bool {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterBoolINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalBool) Lower(value *bool) C.RustBuffer {
	return LowerIntoRustBuffer[*bool](c, value)
}

func (c FfiConverterOptionalBool) LowerExternal(value *bool) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*bool](c, value))
}

func (_ FfiConverterOptionalBool) Write(writer io.Writer, value *bool) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterBoolINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalBool struct{}

func (_ FfiDestroyerOptionalBool) Destroy(value *bool) {
	if value != nil {
		FfiDestroyerBool{}.Destroy(*value)
	}
}

type FfiConverterOptionalString struct{}

var FfiConverterOptionalStringINSTANCE = FfiConverterOptionalString{}

func (c FfiConverterOptionalString) Lift(rb RustBufferI) *string {
	return LiftFromRustBuffer[*string](c, rb)
}

func (_ FfiConverterOptionalString) Read(reader io.Reader) *string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalString) Lower(value *string) C.RustBuffer {
	return LowerIntoRustBuffer[*string](c, value)
}

func (c FfiConverterOptionalString) LowerExternal(value *string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*string](c, value))
}

func (_ FfiConverterOptionalString) Write(writer io.Writer, value *string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalString struct{}

func (_ FfiDestroyerOptionalString) Destroy(value *string) {
	if value != nil {
		FfiDestroyerString{}.Destroy(*value)
	}
}

type FfiConverterOptionalBlockTime struct{}

var FfiConverterOptionalBlockTimeINSTANCE = FfiConverterOptionalBlockTime{}

func (c FfiConverterOptionalBlockTime) Lift(rb RustBufferI) *BlockTime {
	return LiftFromRustBuffer[*BlockTime](c, rb)
}

func (_ FfiConverterOptionalBlockTime) Read(reader io.Reader) *BlockTime {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterBlockTimeINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalBlockTime) Lower(value *BlockTime) C.RustBuffer {
	return LowerIntoRustBuffer[*BlockTime](c, value)
}

func (c FfiConverterOptionalBlockTime) LowerExternal(value *BlockTime) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*BlockTime](c, value))
}

func (_ FfiConverterOptionalBlockTime) Write(writer io.Writer, value *BlockTime) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterBlockTimeINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalBlockTime struct{}

func (_ FfiDestroyerOptionalBlockTime) Destroy(value *BlockTime) {
	if value != nil {
		FfiDestroyerBlockTime{}.Destroy(*value)
	}
}

type FfiConverterOptionalEmbeddedMedia struct{}

var FfiConverterOptionalEmbeddedMediaINSTANCE = FfiConverterOptionalEmbeddedMedia{}

func (c FfiConverterOptionalEmbeddedMedia) Lift(rb RustBufferI) *EmbeddedMedia {
	return LiftFromRustBuffer[*EmbeddedMedia](c, rb)
}

func (_ FfiConverterOptionalEmbeddedMedia) Read(reader io.Reader) *EmbeddedMedia {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterEmbeddedMediaINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalEmbeddedMedia) Lower(value *EmbeddedMedia) C.RustBuffer {
	return LowerIntoRustBuffer[*EmbeddedMedia](c, value)
}

func (c FfiConverterOptionalEmbeddedMedia) LowerExternal(value *EmbeddedMedia) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*EmbeddedMedia](c, value))
}

func (_ FfiConverterOptionalEmbeddedMedia) Write(writer io.Writer, value *EmbeddedMedia) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterEmbeddedMediaINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalEmbeddedMedia struct{}

func (_ FfiDestroyerOptionalEmbeddedMedia) Destroy(value *EmbeddedMedia) {
	if value != nil {
		FfiDestroyerEmbeddedMedia{}.Destroy(*value)
	}
}

type FfiConverterOptionalMedia struct{}

var FfiConverterOptionalMediaINSTANCE = FfiConverterOptionalMedia{}

func (c FfiConverterOptionalMedia) Lift(rb RustBufferI) *Media {
	return LiftFromRustBuffer[*Media](c, rb)
}

func (_ FfiConverterOptionalMedia) Read(reader io.Reader) *Media {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterMediaINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalMedia) Lower(value *Media) C.RustBuffer {
	return LowerIntoRustBuffer[*Media](c, value)
}

func (c FfiConverterOptionalMedia) LowerExternal(value *Media) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*Media](c, value))
}

func (_ FfiConverterOptionalMedia) Write(writer io.Writer, value *Media) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterMediaINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalMedia struct{}

func (_ FfiDestroyerOptionalMedia) Destroy(value *Media) {
	if value != nil {
		FfiDestroyerMedia{}.Destroy(*value)
	}
}

type FfiConverterOptionalOnline struct{}

var FfiConverterOptionalOnlineINSTANCE = FfiConverterOptionalOnline{}

func (c FfiConverterOptionalOnline) Lift(rb RustBufferI) *Online {
	return LiftFromRustBuffer[*Online](c, rb)
}

func (_ FfiConverterOptionalOnline) Read(reader io.Reader) *Online {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterOnlineINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalOnline) Lower(value *Online) C.RustBuffer {
	return LowerIntoRustBuffer[*Online](c, value)
}

func (c FfiConverterOptionalOnline) LowerExternal(value *Online) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*Online](c, value))
}

func (_ FfiConverterOptionalOnline) Write(writer io.Writer, value *Online) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterOnlineINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalOnline struct{}

func (_ FfiDestroyerOptionalOnline) Destroy(value *Online) {
	if value != nil {
		FfiDestroyerOnline{}.Destroy(*value)
	}
}

type FfiConverterOptionalOperationInfo struct{}

var FfiConverterOptionalOperationInfoINSTANCE = FfiConverterOptionalOperationInfo{}

func (c FfiConverterOptionalOperationInfo) Lift(rb RustBufferI) *OperationInfo {
	return LiftFromRustBuffer[*OperationInfo](c, rb)
}

func (_ FfiConverterOptionalOperationInfo) Read(reader io.Reader) *OperationInfo {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterOperationInfoINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalOperationInfo) Lower(value *OperationInfo) C.RustBuffer {
	return LowerIntoRustBuffer[*OperationInfo](c, value)
}

func (c FfiConverterOptionalOperationInfo) LowerExternal(value *OperationInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*OperationInfo](c, value))
}

func (_ FfiConverterOptionalOperationInfo) Write(writer io.Writer, value *OperationInfo) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterOperationInfoINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalOperationInfo struct{}

func (_ FfiDestroyerOptionalOperationInfo) Destroy(value *OperationInfo) {
	if value != nil {
		FfiDestroyerOperationInfo{}.Destroy(*value)
	}
}

type FfiConverterOptionalOutpoint struct{}

var FfiConverterOptionalOutpointINSTANCE = FfiConverterOptionalOutpoint{}

func (c FfiConverterOptionalOutpoint) Lift(rb RustBufferI) *Outpoint {
	return LiftFromRustBuffer[*Outpoint](c, rb)
}

func (_ FfiConverterOptionalOutpoint) Read(reader io.Reader) *Outpoint {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterOutpointINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalOutpoint) Lower(value *Outpoint) C.RustBuffer {
	return LowerIntoRustBuffer[*Outpoint](c, value)
}

func (c FfiConverterOptionalOutpoint) LowerExternal(value *Outpoint) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*Outpoint](c, value))
}

func (_ FfiConverterOptionalOutpoint) Write(writer io.Writer, value *Outpoint) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterOutpointINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalOutpoint struct{}

func (_ FfiDestroyerOptionalOutpoint) Destroy(value *Outpoint) {
	if value != nil {
		FfiDestroyerOutpoint{}.Destroy(*value)
	}
}

type FfiConverterOptionalProofOfReserves struct{}

var FfiConverterOptionalProofOfReservesINSTANCE = FfiConverterOptionalProofOfReserves{}

func (c FfiConverterOptionalProofOfReserves) Lift(rb RustBufferI) *ProofOfReserves {
	return LiftFromRustBuffer[*ProofOfReserves](c, rb)
}

func (_ FfiConverterOptionalProofOfReserves) Read(reader io.Reader) *ProofOfReserves {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterProofOfReservesINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalProofOfReserves) Lower(value *ProofOfReserves) C.RustBuffer {
	return LowerIntoRustBuffer[*ProofOfReserves](c, value)
}

func (c FfiConverterOptionalProofOfReserves) LowerExternal(value *ProofOfReserves) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*ProofOfReserves](c, value))
}

func (_ FfiConverterOptionalProofOfReserves) Write(writer io.Writer, value *ProofOfReserves) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterProofOfReservesINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalProofOfReserves struct{}

func (_ FfiDestroyerOptionalProofOfReserves) Destroy(value *ProofOfReserves) {
	if value != nil {
		FfiDestroyerProofOfReserves{}.Destroy(*value)
	}
}

type FfiConverterOptionalToken struct{}

var FfiConverterOptionalTokenINSTANCE = FfiConverterOptionalToken{}

func (c FfiConverterOptionalToken) Lift(rb RustBufferI) *Token {
	return LiftFromRustBuffer[*Token](c, rb)
}

func (_ FfiConverterOptionalToken) Read(reader io.Reader) *Token {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTokenINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalToken) Lower(value *Token) C.RustBuffer {
	return LowerIntoRustBuffer[*Token](c, value)
}

func (c FfiConverterOptionalToken) LowerExternal(value *Token) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*Token](c, value))
}

func (_ FfiConverterOptionalToken) Write(writer io.Writer, value *Token) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTokenINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalToken struct{}

func (_ FfiDestroyerOptionalToken) Destroy(value *Token) {
	if value != nil {
		FfiDestroyerToken{}.Destroy(*value)
	}
}

type FfiConverterOptionalTokenLight struct{}

var FfiConverterOptionalTokenLightINSTANCE = FfiConverterOptionalTokenLight{}

func (c FfiConverterOptionalTokenLight) Lift(rb RustBufferI) *TokenLight {
	return LiftFromRustBuffer[*TokenLight](c, rb)
}

func (_ FfiConverterOptionalTokenLight) Read(reader io.Reader) *TokenLight {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTokenLightINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTokenLight) Lower(value *TokenLight) C.RustBuffer {
	return LowerIntoRustBuffer[*TokenLight](c, value)
}

func (c FfiConverterOptionalTokenLight) LowerExternal(value *TokenLight) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*TokenLight](c, value))
}

func (_ FfiConverterOptionalTokenLight) Write(writer io.Writer, value *TokenLight) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTokenLightINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTokenLight struct{}

func (_ FfiDestroyerOptionalTokenLight) Destroy(value *TokenLight) {
	if value != nil {
		FfiDestroyerTokenLight{}.Destroy(*value)
	}
}

type FfiConverterOptionalWitnessData struct{}

var FfiConverterOptionalWitnessDataINSTANCE = FfiConverterOptionalWitnessData{}

func (c FfiConverterOptionalWitnessData) Lift(rb RustBufferI) *WitnessData {
	return LiftFromRustBuffer[*WitnessData](c, rb)
}

func (_ FfiConverterOptionalWitnessData) Read(reader io.Reader) *WitnessData {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterWitnessDataINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalWitnessData) Lower(value *WitnessData) C.RustBuffer {
	return LowerIntoRustBuffer[*WitnessData](c, value)
}

func (c FfiConverterOptionalWitnessData) LowerExternal(value *WitnessData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*WitnessData](c, value))
}

func (_ FfiConverterOptionalWitnessData) Write(writer io.Writer, value *WitnessData) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterWitnessDataINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalWitnessData struct{}

func (_ FfiDestroyerOptionalWitnessData) Destroy(value *WitnessData) {
	if value != nil {
		FfiDestroyerWitnessData{}.Destroy(*value)
	}
}

type FfiConverterOptionalAssetSchema struct{}

var FfiConverterOptionalAssetSchemaINSTANCE = FfiConverterOptionalAssetSchema{}

func (c FfiConverterOptionalAssetSchema) Lift(rb RustBufferI) *AssetSchema {
	return LiftFromRustBuffer[*AssetSchema](c, rb)
}

func (_ FfiConverterOptionalAssetSchema) Read(reader io.Reader) *AssetSchema {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterAssetSchemaINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalAssetSchema) Lower(value *AssetSchema) C.RustBuffer {
	return LowerIntoRustBuffer[*AssetSchema](c, value)
}

func (c FfiConverterOptionalAssetSchema) LowerExternal(value *AssetSchema) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*AssetSchema](c, value))
}

func (_ FfiConverterOptionalAssetSchema) Write(writer io.Writer, value *AssetSchema) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterAssetSchemaINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalAssetSchema struct{}

func (_ FfiDestroyerOptionalAssetSchema) Destroy(value *AssetSchema) {
	if value != nil {
		FfiDestroyerAssetSchema{}.Destroy(*value)
	}
}

type FfiConverterOptionalAssignment struct{}

var FfiConverterOptionalAssignmentINSTANCE = FfiConverterOptionalAssignment{}

func (c FfiConverterOptionalAssignment) Lift(rb RustBufferI) *Assignment {
	return LiftFromRustBuffer[*Assignment](c, rb)
}

func (_ FfiConverterOptionalAssignment) Read(reader io.Reader) *Assignment {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterAssignmentINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalAssignment) Lower(value *Assignment) C.RustBuffer {
	return LowerIntoRustBuffer[*Assignment](c, value)
}

func (c FfiConverterOptionalAssignment) LowerExternal(value *Assignment) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*Assignment](c, value))
}

func (_ FfiConverterOptionalAssignment) Write(writer io.Writer, value *Assignment) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterAssignmentINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalAssignment struct{}

func (_ FfiDestroyerOptionalAssignment) Destroy(value *Assignment) {
	if value != nil {
		FfiDestroyerAssignment{}.Destroy(*value)
	}
}

type FfiConverterOptionalRgbLibError struct{}

var FfiConverterOptionalRgbLibErrorINSTANCE = FfiConverterOptionalRgbLibError{}

func (c FfiConverterOptionalRgbLibError) Lift(rb RustBufferI) **RgbLibError {
	return LiftFromRustBuffer[**RgbLibError](c, rb)
}

func (_ FfiConverterOptionalRgbLibError) Read(reader io.Reader) **RgbLibError {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterRgbLibErrorINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalRgbLibError) Lower(value **RgbLibError) C.RustBuffer {
	return LowerIntoRustBuffer[**RgbLibError](c, value)
}

func (c FfiConverterOptionalRgbLibError) LowerExternal(value **RgbLibError) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[**RgbLibError](c, value))
}

func (_ FfiConverterOptionalRgbLibError) Write(writer io.Writer, value **RgbLibError) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterRgbLibErrorINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalRgbLibError struct{}

func (_ FfiDestroyerOptionalRgbLibError) Destroy(value **RgbLibError) {
	if value != nil {
		FfiDestroyerRgbLibError{}.Destroy(*value)
	}
}

type FfiConverterOptionalTransferStatus struct{}

var FfiConverterOptionalTransferStatusINSTANCE = FfiConverterOptionalTransferStatus{}

func (c FfiConverterOptionalTransferStatus) Lift(rb RustBufferI) *TransferStatus {
	return LiftFromRustBuffer[*TransferStatus](c, rb)
}

func (_ FfiConverterOptionalTransferStatus) Read(reader io.Reader) *TransferStatus {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTransferStatusINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTransferStatus) Lower(value *TransferStatus) C.RustBuffer {
	return LowerIntoRustBuffer[*TransferStatus](c, value)
}

func (c FfiConverterOptionalTransferStatus) LowerExternal(value *TransferStatus) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*TransferStatus](c, value))
}

func (_ FfiConverterOptionalTransferStatus) Write(writer io.Writer, value *TransferStatus) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTransferStatusINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTransferStatus struct{}

func (_ FfiDestroyerOptionalTransferStatus) Destroy(value *TransferStatus) {
	if value != nil {
		FfiDestroyerTransferStatus{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceString struct{}

var FfiConverterOptionalSequenceStringINSTANCE = FfiConverterOptionalSequenceString{}

func (c FfiConverterOptionalSequenceString) Lift(rb RustBufferI) *[]string {
	return LiftFromRustBuffer[*[]string](c, rb)
}

func (_ FfiConverterOptionalSequenceString) Read(reader io.Reader) *[]string {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceStringINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceString) Lower(value *[]string) C.RustBuffer {
	return LowerIntoRustBuffer[*[]string](c, value)
}

func (c FfiConverterOptionalSequenceString) LowerExternal(value *[]string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*[]string](c, value))
}

func (_ FfiConverterOptionalSequenceString) Write(writer io.Writer, value *[]string) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceStringINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceString struct{}

func (_ FfiDestroyerOptionalSequenceString) Destroy(value *[]string) {
	if value != nil {
		FfiDestroyerSequenceString{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceAssetCfa struct{}

var FfiConverterOptionalSequenceAssetCfaINSTANCE = FfiConverterOptionalSequenceAssetCfa{}

func (c FfiConverterOptionalSequenceAssetCfa) Lift(rb RustBufferI) *[]AssetCfa {
	return LiftFromRustBuffer[*[]AssetCfa](c, rb)
}

func (_ FfiConverterOptionalSequenceAssetCfa) Read(reader io.Reader) *[]AssetCfa {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceAssetCfaINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceAssetCfa) Lower(value *[]AssetCfa) C.RustBuffer {
	return LowerIntoRustBuffer[*[]AssetCfa](c, value)
}

func (c FfiConverterOptionalSequenceAssetCfa) LowerExternal(value *[]AssetCfa) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*[]AssetCfa](c, value))
}

func (_ FfiConverterOptionalSequenceAssetCfa) Write(writer io.Writer, value *[]AssetCfa) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceAssetCfaINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceAssetCfa struct{}

func (_ FfiDestroyerOptionalSequenceAssetCfa) Destroy(value *[]AssetCfa) {
	if value != nil {
		FfiDestroyerSequenceAssetCfa{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceAssetIfa struct{}

var FfiConverterOptionalSequenceAssetIfaINSTANCE = FfiConverterOptionalSequenceAssetIfa{}

func (c FfiConverterOptionalSequenceAssetIfa) Lift(rb RustBufferI) *[]AssetIfa {
	return LiftFromRustBuffer[*[]AssetIfa](c, rb)
}

func (_ FfiConverterOptionalSequenceAssetIfa) Read(reader io.Reader) *[]AssetIfa {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceAssetIfaINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceAssetIfa) Lower(value *[]AssetIfa) C.RustBuffer {
	return LowerIntoRustBuffer[*[]AssetIfa](c, value)
}

func (c FfiConverterOptionalSequenceAssetIfa) LowerExternal(value *[]AssetIfa) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*[]AssetIfa](c, value))
}

func (_ FfiConverterOptionalSequenceAssetIfa) Write(writer io.Writer, value *[]AssetIfa) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceAssetIfaINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceAssetIfa struct{}

func (_ FfiDestroyerOptionalSequenceAssetIfa) Destroy(value *[]AssetIfa) {
	if value != nil {
		FfiDestroyerSequenceAssetIfa{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceAssetNia struct{}

var FfiConverterOptionalSequenceAssetNiaINSTANCE = FfiConverterOptionalSequenceAssetNia{}

func (c FfiConverterOptionalSequenceAssetNia) Lift(rb RustBufferI) *[]AssetNia {
	return LiftFromRustBuffer[*[]AssetNia](c, rb)
}

func (_ FfiConverterOptionalSequenceAssetNia) Read(reader io.Reader) *[]AssetNia {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceAssetNiaINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceAssetNia) Lower(value *[]AssetNia) C.RustBuffer {
	return LowerIntoRustBuffer[*[]AssetNia](c, value)
}

func (c FfiConverterOptionalSequenceAssetNia) LowerExternal(value *[]AssetNia) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*[]AssetNia](c, value))
}

func (_ FfiConverterOptionalSequenceAssetNia) Write(writer io.Writer, value *[]AssetNia) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceAssetNiaINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceAssetNia struct{}

func (_ FfiDestroyerOptionalSequenceAssetNia) Destroy(value *[]AssetNia) {
	if value != nil {
		FfiDestroyerSequenceAssetNia{}.Destroy(*value)
	}
}

type FfiConverterOptionalSequenceAssetUda struct{}

var FfiConverterOptionalSequenceAssetUdaINSTANCE = FfiConverterOptionalSequenceAssetUda{}

func (c FfiConverterOptionalSequenceAssetUda) Lift(rb RustBufferI) *[]AssetUda {
	return LiftFromRustBuffer[*[]AssetUda](c, rb)
}

func (_ FfiConverterOptionalSequenceAssetUda) Read(reader io.Reader) *[]AssetUda {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterSequenceAssetUdaINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalSequenceAssetUda) Lower(value *[]AssetUda) C.RustBuffer {
	return LowerIntoRustBuffer[*[]AssetUda](c, value)
}

func (c FfiConverterOptionalSequenceAssetUda) LowerExternal(value *[]AssetUda) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*[]AssetUda](c, value))
}

func (_ FfiConverterOptionalSequenceAssetUda) Write(writer io.Writer, value *[]AssetUda) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterSequenceAssetUdaINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalSequenceAssetUda struct{}

func (_ FfiDestroyerOptionalSequenceAssetUda) Destroy(value *[]AssetUda) {
	if value != nil {
		FfiDestroyerSequenceAssetUda{}.Destroy(*value)
	}
}

type FfiConverterSequenceUint8 struct{}

var FfiConverterSequenceUint8INSTANCE = FfiConverterSequenceUint8{}

func (c FfiConverterSequenceUint8) Lift(rb RustBufferI) []uint8 {
	return LiftFromRustBuffer[[]uint8](c, rb)
}

func (c FfiConverterSequenceUint8) Read(reader io.Reader) []uint8 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint8, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint8INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint8) Lower(value []uint8) C.RustBuffer {
	return LowerIntoRustBuffer[[]uint8](c, value)
}

func (c FfiConverterSequenceUint8) LowerExternal(value []uint8) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]uint8](c, value))
}

func (c FfiConverterSequenceUint8) Write(writer io.Writer, value []uint8) {
	if len(value) > math.MaxInt32 {
		panic("[]uint8 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint8INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint8 struct{}

func (FfiDestroyerSequenceUint8) Destroy(sequence []uint8) {
	for _, value := range sequence {
		FfiDestroyerUint8{}.Destroy(value)
	}
}

type FfiConverterSequenceUint64 struct{}

var FfiConverterSequenceUint64INSTANCE = FfiConverterSequenceUint64{}

func (c FfiConverterSequenceUint64) Lift(rb RustBufferI) []uint64 {
	return LiftFromRustBuffer[[]uint64](c, rb)
}

func (c FfiConverterSequenceUint64) Read(reader io.Reader) []uint64 {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]uint64, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUint64INSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUint64) Lower(value []uint64) C.RustBuffer {
	return LowerIntoRustBuffer[[]uint64](c, value)
}

func (c FfiConverterSequenceUint64) LowerExternal(value []uint64) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]uint64](c, value))
}

func (c FfiConverterSequenceUint64) Write(writer io.Writer, value []uint64) {
	if len(value) > math.MaxInt32 {
		panic("[]uint64 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUint64INSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUint64 struct{}

func (FfiDestroyerSequenceUint64) Destroy(sequence []uint64) {
	for _, value := range sequence {
		FfiDestroyerUint64{}.Destroy(value)
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) LowerExternal(value []string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]string](c, value))
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct{}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

type FfiConverterSequenceAssetCfa struct{}

var FfiConverterSequenceAssetCfaINSTANCE = FfiConverterSequenceAssetCfa{}

func (c FfiConverterSequenceAssetCfa) Lift(rb RustBufferI) []AssetCfa {
	return LiftFromRustBuffer[[]AssetCfa](c, rb)
}

func (c FfiConverterSequenceAssetCfa) Read(reader io.Reader) []AssetCfa {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]AssetCfa, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssetCfaINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssetCfa) Lower(value []AssetCfa) C.RustBuffer {
	return LowerIntoRustBuffer[[]AssetCfa](c, value)
}

func (c FfiConverterSequenceAssetCfa) LowerExternal(value []AssetCfa) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]AssetCfa](c, value))
}

func (c FfiConverterSequenceAssetCfa) Write(writer io.Writer, value []AssetCfa) {
	if len(value) > math.MaxInt32 {
		panic("[]AssetCfa is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssetCfaINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssetCfa struct{}

func (FfiDestroyerSequenceAssetCfa) Destroy(sequence []AssetCfa) {
	for _, value := range sequence {
		FfiDestroyerAssetCfa{}.Destroy(value)
	}
}

type FfiConverterSequenceAssetColoringInfo struct{}

var FfiConverterSequenceAssetColoringInfoINSTANCE = FfiConverterSequenceAssetColoringInfo{}

func (c FfiConverterSequenceAssetColoringInfo) Lift(rb RustBufferI) []AssetColoringInfo {
	return LiftFromRustBuffer[[]AssetColoringInfo](c, rb)
}

func (c FfiConverterSequenceAssetColoringInfo) Read(reader io.Reader) []AssetColoringInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]AssetColoringInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssetColoringInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssetColoringInfo) Lower(value []AssetColoringInfo) C.RustBuffer {
	return LowerIntoRustBuffer[[]AssetColoringInfo](c, value)
}

func (c FfiConverterSequenceAssetColoringInfo) LowerExternal(value []AssetColoringInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]AssetColoringInfo](c, value))
}

func (c FfiConverterSequenceAssetColoringInfo) Write(writer io.Writer, value []AssetColoringInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]AssetColoringInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssetColoringInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssetColoringInfo struct{}

func (FfiDestroyerSequenceAssetColoringInfo) Destroy(sequence []AssetColoringInfo) {
	for _, value := range sequence {
		FfiDestroyerAssetColoringInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceAssetConsignment struct{}

var FfiConverterSequenceAssetConsignmentINSTANCE = FfiConverterSequenceAssetConsignment{}

func (c FfiConverterSequenceAssetConsignment) Lift(rb RustBufferI) []AssetConsignment {
	return LiftFromRustBuffer[[]AssetConsignment](c, rb)
}

func (c FfiConverterSequenceAssetConsignment) Read(reader io.Reader) []AssetConsignment {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]AssetConsignment, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssetConsignmentINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssetConsignment) Lower(value []AssetConsignment) C.RustBuffer {
	return LowerIntoRustBuffer[[]AssetConsignment](c, value)
}

func (c FfiConverterSequenceAssetConsignment) LowerExternal(value []AssetConsignment) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]AssetConsignment](c, value))
}

func (c FfiConverterSequenceAssetConsignment) Write(writer io.Writer, value []AssetConsignment) {
	if len(value) > math.MaxInt32 {
		panic("[]AssetConsignment is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssetConsignmentINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssetConsignment struct{}

func (FfiDestroyerSequenceAssetConsignment) Destroy(sequence []AssetConsignment) {
	for _, value := range sequence {
		FfiDestroyerAssetConsignment{}.Destroy(value)
	}
}

type FfiConverterSequenceAssetIfa struct{}

var FfiConverterSequenceAssetIfaINSTANCE = FfiConverterSequenceAssetIfa{}

func (c FfiConverterSequenceAssetIfa) Lift(rb RustBufferI) []AssetIfa {
	return LiftFromRustBuffer[[]AssetIfa](c, rb)
}

func (c FfiConverterSequenceAssetIfa) Read(reader io.Reader) []AssetIfa {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]AssetIfa, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssetIfaINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssetIfa) Lower(value []AssetIfa) C.RustBuffer {
	return LowerIntoRustBuffer[[]AssetIfa](c, value)
}

func (c FfiConverterSequenceAssetIfa) LowerExternal(value []AssetIfa) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]AssetIfa](c, value))
}

func (c FfiConverterSequenceAssetIfa) Write(writer io.Writer, value []AssetIfa) {
	if len(value) > math.MaxInt32 {
		panic("[]AssetIfa is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssetIfaINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssetIfa struct{}

func (FfiDestroyerSequenceAssetIfa) Destroy(sequence []AssetIfa) {
	for _, value := range sequence {
		FfiDestroyerAssetIfa{}.Destroy(value)
	}
}

type FfiConverterSequenceAssetNia struct{}

var FfiConverterSequenceAssetNiaINSTANCE = FfiConverterSequenceAssetNia{}

func (c FfiConverterSequenceAssetNia) Lift(rb RustBufferI) []AssetNia {
	return LiftFromRustBuffer[[]AssetNia](c, rb)
}

func (c FfiConverterSequenceAssetNia) Read(reader io.Reader) []AssetNia {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]AssetNia, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssetNiaINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssetNia) Lower(value []AssetNia) C.RustBuffer {
	return LowerIntoRustBuffer[[]AssetNia](c, value)
}

func (c FfiConverterSequenceAssetNia) LowerExternal(value []AssetNia) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]AssetNia](c, value))
}

func (c FfiConverterSequenceAssetNia) Write(writer io.Writer, value []AssetNia) {
	if len(value) > math.MaxInt32 {
		panic("[]AssetNia is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssetNiaINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssetNia struct{}

func (FfiDestroyerSequenceAssetNia) Destroy(sequence []AssetNia) {
	for _, value := range sequence {
		FfiDestroyerAssetNia{}.Destroy(value)
	}
}

type FfiConverterSequenceAssetUda struct{}

var FfiConverterSequenceAssetUdaINSTANCE = FfiConverterSequenceAssetUda{}

func (c FfiConverterSequenceAssetUda) Lift(rb RustBufferI) []AssetUda {
	return LiftFromRustBuffer[[]AssetUda](c, rb)
}

func (c FfiConverterSequenceAssetUda) Read(reader io.Reader) []AssetUda {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]AssetUda, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssetUdaINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssetUda) Lower(value []AssetUda) C.RustBuffer {
	return LowerIntoRustBuffer[[]AssetUda](c, value)
}

func (c FfiConverterSequenceAssetUda) LowerExternal(value []AssetUda) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]AssetUda](c, value))
}

func (c FfiConverterSequenceAssetUda) Write(writer io.Writer, value []AssetUda) {
	if len(value) > math.MaxInt32 {
		panic("[]AssetUda is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssetUdaINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssetUda struct{}

func (FfiDestroyerSequenceAssetUda) Destroy(sequence []AssetUda) {
	for _, value := range sequence {
		FfiDestroyerAssetUda{}.Destroy(value)
	}
}

type FfiConverterSequenceCosignerData struct{}

var FfiConverterSequenceCosignerDataINSTANCE = FfiConverterSequenceCosignerData{}

func (c FfiConverterSequenceCosignerData) Lift(rb RustBufferI) []CosignerData {
	return LiftFromRustBuffer[[]CosignerData](c, rb)
}

func (c FfiConverterSequenceCosignerData) Read(reader io.Reader) []CosignerData {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]CosignerData, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterCosignerDataINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceCosignerData) Lower(value []CosignerData) C.RustBuffer {
	return LowerIntoRustBuffer[[]CosignerData](c, value)
}

func (c FfiConverterSequenceCosignerData) LowerExternal(value []CosignerData) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]CosignerData](c, value))
}

func (c FfiConverterSequenceCosignerData) Write(writer io.Writer, value []CosignerData) {
	if len(value) > math.MaxInt32 {
		panic("[]CosignerData is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterCosignerDataINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceCosignerData struct{}

func (FfiDestroyerSequenceCosignerData) Destroy(sequence []CosignerData) {
	for _, value := range sequence {
		FfiDestroyerCosignerData{}.Destroy(value)
	}
}

type FfiConverterSequenceOutpoint struct{}

var FfiConverterSequenceOutpointINSTANCE = FfiConverterSequenceOutpoint{}

func (c FfiConverterSequenceOutpoint) Lift(rb RustBufferI) []Outpoint {
	return LiftFromRustBuffer[[]Outpoint](c, rb)
}

func (c FfiConverterSequenceOutpoint) Read(reader io.Reader) []Outpoint {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Outpoint, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterOutpointINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceOutpoint) Lower(value []Outpoint) C.RustBuffer {
	return LowerIntoRustBuffer[[]Outpoint](c, value)
}

func (c FfiConverterSequenceOutpoint) LowerExternal(value []Outpoint) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]Outpoint](c, value))
}

func (c FfiConverterSequenceOutpoint) Write(writer io.Writer, value []Outpoint) {
	if len(value) > math.MaxInt32 {
		panic("[]Outpoint is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterOutpointINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceOutpoint struct{}

func (FfiDestroyerSequenceOutpoint) Destroy(sequence []Outpoint) {
	for _, value := range sequence {
		FfiDestroyerOutpoint{}.Destroy(value)
	}
}

type FfiConverterSequenceOutpointAssignments struct{}

var FfiConverterSequenceOutpointAssignmentsINSTANCE = FfiConverterSequenceOutpointAssignments{}

func (c FfiConverterSequenceOutpointAssignments) Lift(rb RustBufferI) []OutpointAssignments {
	return LiftFromRustBuffer[[]OutpointAssignments](c, rb)
}

func (c FfiConverterSequenceOutpointAssignments) Read(reader io.Reader) []OutpointAssignments {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]OutpointAssignments, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterOutpointAssignmentsINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceOutpointAssignments) Lower(value []OutpointAssignments) C.RustBuffer {
	return LowerIntoRustBuffer[[]OutpointAssignments](c, value)
}

func (c FfiConverterSequenceOutpointAssignments) LowerExternal(value []OutpointAssignments) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]OutpointAssignments](c, value))
}

func (c FfiConverterSequenceOutpointAssignments) Write(writer io.Writer, value []OutpointAssignments) {
	if len(value) > math.MaxInt32 {
		panic("[]OutpointAssignments is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterOutpointAssignmentsINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceOutpointAssignments struct{}

func (FfiDestroyerSequenceOutpointAssignments) Destroy(sequence []OutpointAssignments) {
	for _, value := range sequence {
		FfiDestroyerOutpointAssignments{}.Destroy(value)
	}
}

type FfiConverterSequencePendingVanillaTx struct{}

var FfiConverterSequencePendingVanillaTxINSTANCE = FfiConverterSequencePendingVanillaTx{}

func (c FfiConverterSequencePendingVanillaTx) Lift(rb RustBufferI) []PendingVanillaTx {
	return LiftFromRustBuffer[[]PendingVanillaTx](c, rb)
}

func (c FfiConverterSequencePendingVanillaTx) Read(reader io.Reader) []PendingVanillaTx {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]PendingVanillaTx, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterPendingVanillaTxINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequencePendingVanillaTx) Lower(value []PendingVanillaTx) C.RustBuffer {
	return LowerIntoRustBuffer[[]PendingVanillaTx](c, value)
}

func (c FfiConverterSequencePendingVanillaTx) LowerExternal(value []PendingVanillaTx) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]PendingVanillaTx](c, value))
}

func (c FfiConverterSequencePendingVanillaTx) Write(writer io.Writer, value []PendingVanillaTx) {
	if len(value) > math.MaxInt32 {
		panic("[]PendingVanillaTx is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterPendingVanillaTxINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequencePendingVanillaTx struct{}

func (FfiDestroyerSequencePendingVanillaTx) Destroy(sequence []PendingVanillaTx) {
	for _, value := range sequence {
		FfiDestroyerPendingVanillaTx{}.Destroy(value)
	}
}

type FfiConverterSequencePsbtInputInfo struct{}

var FfiConverterSequencePsbtInputInfoINSTANCE = FfiConverterSequencePsbtInputInfo{}

func (c FfiConverterSequencePsbtInputInfo) Lift(rb RustBufferI) []PsbtInputInfo {
	return LiftFromRustBuffer[[]PsbtInputInfo](c, rb)
}

func (c FfiConverterSequencePsbtInputInfo) Read(reader io.Reader) []PsbtInputInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]PsbtInputInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterPsbtInputInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequencePsbtInputInfo) Lower(value []PsbtInputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[[]PsbtInputInfo](c, value)
}

func (c FfiConverterSequencePsbtInputInfo) LowerExternal(value []PsbtInputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]PsbtInputInfo](c, value))
}

func (c FfiConverterSequencePsbtInputInfo) Write(writer io.Writer, value []PsbtInputInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]PsbtInputInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterPsbtInputInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequencePsbtInputInfo struct{}

func (FfiDestroyerSequencePsbtInputInfo) Destroy(sequence []PsbtInputInfo) {
	for _, value := range sequence {
		FfiDestroyerPsbtInputInfo{}.Destroy(value)
	}
}

type FfiConverterSequencePsbtOutputInfo struct{}

var FfiConverterSequencePsbtOutputInfoINSTANCE = FfiConverterSequencePsbtOutputInfo{}

func (c FfiConverterSequencePsbtOutputInfo) Lift(rb RustBufferI) []PsbtOutputInfo {
	return LiftFromRustBuffer[[]PsbtOutputInfo](c, rb)
}

func (c FfiConverterSequencePsbtOutputInfo) Read(reader io.Reader) []PsbtOutputInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]PsbtOutputInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterPsbtOutputInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequencePsbtOutputInfo) Lower(value []PsbtOutputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[[]PsbtOutputInfo](c, value)
}

func (c FfiConverterSequencePsbtOutputInfo) LowerExternal(value []PsbtOutputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]PsbtOutputInfo](c, value))
}

func (c FfiConverterSequencePsbtOutputInfo) Write(writer io.Writer, value []PsbtOutputInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]PsbtOutputInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterPsbtOutputInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequencePsbtOutputInfo struct{}

func (FfiDestroyerSequencePsbtOutputInfo) Destroy(sequence []PsbtOutputInfo) {
	for _, value := range sequence {
		FfiDestroyerPsbtOutputInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceRecipient struct{}

var FfiConverterSequenceRecipientINSTANCE = FfiConverterSequenceRecipient{}

func (c FfiConverterSequenceRecipient) Lift(rb RustBufferI) []Recipient {
	return LiftFromRustBuffer[[]Recipient](c, rb)
}

func (c FfiConverterSequenceRecipient) Read(reader io.Reader) []Recipient {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Recipient, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterRecipientINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceRecipient) Lower(value []Recipient) C.RustBuffer {
	return LowerIntoRustBuffer[[]Recipient](c, value)
}

func (c FfiConverterSequenceRecipient) LowerExternal(value []Recipient) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]Recipient](c, value))
}

func (c FfiConverterSequenceRecipient) Write(writer io.Writer, value []Recipient) {
	if len(value) > math.MaxInt32 {
		panic("[]Recipient is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterRecipientINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceRecipient struct{}

func (FfiDestroyerSequenceRecipient) Destroy(sequence []Recipient) {
	for _, value := range sequence {
		FfiDestroyerRecipient{}.Destroy(value)
	}
}

type FfiConverterSequenceRefreshFilter struct{}

var FfiConverterSequenceRefreshFilterINSTANCE = FfiConverterSequenceRefreshFilter{}

func (c FfiConverterSequenceRefreshFilter) Lift(rb RustBufferI) []RefreshFilter {
	return LiftFromRustBuffer[[]RefreshFilter](c, rb)
}

func (c FfiConverterSequenceRefreshFilter) Read(reader io.Reader) []RefreshFilter {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]RefreshFilter, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterRefreshFilterINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceRefreshFilter) Lower(value []RefreshFilter) C.RustBuffer {
	return LowerIntoRustBuffer[[]RefreshFilter](c, value)
}

func (c FfiConverterSequenceRefreshFilter) LowerExternal(value []RefreshFilter) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]RefreshFilter](c, value))
}

func (c FfiConverterSequenceRefreshFilter) Write(writer io.Writer, value []RefreshFilter) {
	if len(value) > math.MaxInt32 {
		panic("[]RefreshFilter is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterRefreshFilterINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceRefreshFilter struct{}

func (FfiDestroyerSequenceRefreshFilter) Destroy(sequence []RefreshFilter) {
	for _, value := range sequence {
		FfiDestroyerRefreshFilter{}.Destroy(value)
	}
}

type FfiConverterSequenceRgbAllocation struct{}

var FfiConverterSequenceRgbAllocationINSTANCE = FfiConverterSequenceRgbAllocation{}

func (c FfiConverterSequenceRgbAllocation) Lift(rb RustBufferI) []RgbAllocation {
	return LiftFromRustBuffer[[]RgbAllocation](c, rb)
}

func (c FfiConverterSequenceRgbAllocation) Read(reader io.Reader) []RgbAllocation {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]RgbAllocation, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterRgbAllocationINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceRgbAllocation) Lower(value []RgbAllocation) C.RustBuffer {
	return LowerIntoRustBuffer[[]RgbAllocation](c, value)
}

func (c FfiConverterSequenceRgbAllocation) LowerExternal(value []RgbAllocation) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]RgbAllocation](c, value))
}

func (c FfiConverterSequenceRgbAllocation) Write(writer io.Writer, value []RgbAllocation) {
	if len(value) > math.MaxInt32 {
		panic("[]RgbAllocation is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterRgbAllocationINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceRgbAllocation struct{}

func (FfiDestroyerSequenceRgbAllocation) Destroy(sequence []RgbAllocation) {
	for _, value := range sequence {
		FfiDestroyerRgbAllocation{}.Destroy(value)
	}
}

type FfiConverterSequenceRgbInputInfo struct{}

var FfiConverterSequenceRgbInputInfoINSTANCE = FfiConverterSequenceRgbInputInfo{}

func (c FfiConverterSequenceRgbInputInfo) Lift(rb RustBufferI) []RgbInputInfo {
	return LiftFromRustBuffer[[]RgbInputInfo](c, rb)
}

func (c FfiConverterSequenceRgbInputInfo) Read(reader io.Reader) []RgbInputInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]RgbInputInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterRgbInputInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceRgbInputInfo) Lower(value []RgbInputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[[]RgbInputInfo](c, value)
}

func (c FfiConverterSequenceRgbInputInfo) LowerExternal(value []RgbInputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]RgbInputInfo](c, value))
}

func (c FfiConverterSequenceRgbInputInfo) Write(writer io.Writer, value []RgbInputInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]RgbInputInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterRgbInputInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceRgbInputInfo struct{}

func (FfiDestroyerSequenceRgbInputInfo) Destroy(sequence []RgbInputInfo) {
	for _, value := range sequence {
		FfiDestroyerRgbInputInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceRgbOperationInfo struct{}

var FfiConverterSequenceRgbOperationInfoINSTANCE = FfiConverterSequenceRgbOperationInfo{}

func (c FfiConverterSequenceRgbOperationInfo) Lift(rb RustBufferI) []RgbOperationInfo {
	return LiftFromRustBuffer[[]RgbOperationInfo](c, rb)
}

func (c FfiConverterSequenceRgbOperationInfo) Read(reader io.Reader) []RgbOperationInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]RgbOperationInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterRgbOperationInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceRgbOperationInfo) Lower(value []RgbOperationInfo) C.RustBuffer {
	return LowerIntoRustBuffer[[]RgbOperationInfo](c, value)
}

func (c FfiConverterSequenceRgbOperationInfo) LowerExternal(value []RgbOperationInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]RgbOperationInfo](c, value))
}

func (c FfiConverterSequenceRgbOperationInfo) Write(writer io.Writer, value []RgbOperationInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]RgbOperationInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterRgbOperationInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceRgbOperationInfo struct{}

func (FfiDestroyerSequenceRgbOperationInfo) Destroy(sequence []RgbOperationInfo) {
	for _, value := range sequence {
		FfiDestroyerRgbOperationInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceRgbOutputInfo struct{}

var FfiConverterSequenceRgbOutputInfoINSTANCE = FfiConverterSequenceRgbOutputInfo{}

func (c FfiConverterSequenceRgbOutputInfo) Lift(rb RustBufferI) []RgbOutputInfo {
	return LiftFromRustBuffer[[]RgbOutputInfo](c, rb)
}

func (c FfiConverterSequenceRgbOutputInfo) Read(reader io.Reader) []RgbOutputInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]RgbOutputInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterRgbOutputInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceRgbOutputInfo) Lower(value []RgbOutputInfo) C.RustBuffer {
	return LowerIntoRustBuffer[[]RgbOutputInfo](c, value)
}

func (c FfiConverterSequenceRgbOutputInfo) LowerExternal(value []RgbOutputInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]RgbOutputInfo](c, value))
}

func (c FfiConverterSequenceRgbOutputInfo) Write(writer io.Writer, value []RgbOutputInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]RgbOutputInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterRgbOutputInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceRgbOutputInfo struct{}

func (FfiDestroyerSequenceRgbOutputInfo) Destroy(sequence []RgbOutputInfo) {
	for _, value := range sequence {
		FfiDestroyerRgbOutputInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceRgbTransitionInfo struct{}

var FfiConverterSequenceRgbTransitionInfoINSTANCE = FfiConverterSequenceRgbTransitionInfo{}

func (c FfiConverterSequenceRgbTransitionInfo) Lift(rb RustBufferI) []RgbTransitionInfo {
	return LiftFromRustBuffer[[]RgbTransitionInfo](c, rb)
}

func (c FfiConverterSequenceRgbTransitionInfo) Read(reader io.Reader) []RgbTransitionInfo {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]RgbTransitionInfo, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterRgbTransitionInfoINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceRgbTransitionInfo) Lower(value []RgbTransitionInfo) C.RustBuffer {
	return LowerIntoRustBuffer[[]RgbTransitionInfo](c, value)
}

func (c FfiConverterSequenceRgbTransitionInfo) LowerExternal(value []RgbTransitionInfo) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]RgbTransitionInfo](c, value))
}

func (c FfiConverterSequenceRgbTransitionInfo) Write(writer io.Writer, value []RgbTransitionInfo) {
	if len(value) > math.MaxInt32 {
		panic("[]RgbTransitionInfo is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterRgbTransitionInfoINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceRgbTransitionInfo struct{}

func (FfiDestroyerSequenceRgbTransitionInfo) Destroy(sequence []RgbTransitionInfo) {
	for _, value := range sequence {
		FfiDestroyerRgbTransitionInfo{}.Destroy(value)
	}
}

type FfiConverterSequenceTransaction struct{}

var FfiConverterSequenceTransactionINSTANCE = FfiConverterSequenceTransaction{}

func (c FfiConverterSequenceTransaction) Lift(rb RustBufferI) []Transaction {
	return LiftFromRustBuffer[[]Transaction](c, rb)
}

func (c FfiConverterSequenceTransaction) Read(reader io.Reader) []Transaction {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Transaction, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTransactionINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTransaction) Lower(value []Transaction) C.RustBuffer {
	return LowerIntoRustBuffer[[]Transaction](c, value)
}

func (c FfiConverterSequenceTransaction) LowerExternal(value []Transaction) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]Transaction](c, value))
}

func (c FfiConverterSequenceTransaction) Write(writer io.Writer, value []Transaction) {
	if len(value) > math.MaxInt32 {
		panic("[]Transaction is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTransactionINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTransaction struct{}

func (FfiDestroyerSequenceTransaction) Destroy(sequence []Transaction) {
	for _, value := range sequence {
		FfiDestroyerTransaction{}.Destroy(value)
	}
}

type FfiConverterSequenceTransfer struct{}

var FfiConverterSequenceTransferINSTANCE = FfiConverterSequenceTransfer{}

func (c FfiConverterSequenceTransfer) Lift(rb RustBufferI) []Transfer {
	return LiftFromRustBuffer[[]Transfer](c, rb)
}

func (c FfiConverterSequenceTransfer) Read(reader io.Reader) []Transfer {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Transfer, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTransferINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTransfer) Lower(value []Transfer) C.RustBuffer {
	return LowerIntoRustBuffer[[]Transfer](c, value)
}

func (c FfiConverterSequenceTransfer) LowerExternal(value []Transfer) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]Transfer](c, value))
}

func (c FfiConverterSequenceTransfer) Write(writer io.Writer, value []Transfer) {
	if len(value) > math.MaxInt32 {
		panic("[]Transfer is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTransferINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTransfer struct{}

func (FfiDestroyerSequenceTransfer) Destroy(sequence []Transfer) {
	for _, value := range sequence {
		FfiDestroyerTransfer{}.Destroy(value)
	}
}

type FfiConverterSequenceTransferTransportEndpoint struct{}

var FfiConverterSequenceTransferTransportEndpointINSTANCE = FfiConverterSequenceTransferTransportEndpoint{}

func (c FfiConverterSequenceTransferTransportEndpoint) Lift(rb RustBufferI) []TransferTransportEndpoint {
	return LiftFromRustBuffer[[]TransferTransportEndpoint](c, rb)
}

func (c FfiConverterSequenceTransferTransportEndpoint) Read(reader io.Reader) []TransferTransportEndpoint {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]TransferTransportEndpoint, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTransferTransportEndpointINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTransferTransportEndpoint) Lower(value []TransferTransportEndpoint) C.RustBuffer {
	return LowerIntoRustBuffer[[]TransferTransportEndpoint](c, value)
}

func (c FfiConverterSequenceTransferTransportEndpoint) LowerExternal(value []TransferTransportEndpoint) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]TransferTransportEndpoint](c, value))
}

func (c FfiConverterSequenceTransferTransportEndpoint) Write(writer io.Writer, value []TransferTransportEndpoint) {
	if len(value) > math.MaxInt32 {
		panic("[]TransferTransportEndpoint is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTransferTransportEndpointINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTransferTransportEndpoint struct{}

func (FfiDestroyerSequenceTransferTransportEndpoint) Destroy(sequence []TransferTransportEndpoint) {
	for _, value := range sequence {
		FfiDestroyerTransferTransportEndpoint{}.Destroy(value)
	}
}

type FfiConverterSequenceUnspent struct{}

var FfiConverterSequenceUnspentINSTANCE = FfiConverterSequenceUnspent{}

func (c FfiConverterSequenceUnspent) Lift(rb RustBufferI) []Unspent {
	return LiftFromRustBuffer[[]Unspent](c, rb)
}

func (c FfiConverterSequenceUnspent) Read(reader io.Reader) []Unspent {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Unspent, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterUnspentINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceUnspent) Lower(value []Unspent) C.RustBuffer {
	return LowerIntoRustBuffer[[]Unspent](c, value)
}

func (c FfiConverterSequenceUnspent) LowerExternal(value []Unspent) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]Unspent](c, value))
}

func (c FfiConverterSequenceUnspent) Write(writer io.Writer, value []Unspent) {
	if len(value) > math.MaxInt32 {
		panic("[]Unspent is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterUnspentINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceUnspent struct{}

func (FfiDestroyerSequenceUnspent) Destroy(sequence []Unspent) {
	for _, value := range sequence {
		FfiDestroyerUnspent{}.Destroy(value)
	}
}

type FfiConverterSequenceAssetSchema struct{}

var FfiConverterSequenceAssetSchemaINSTANCE = FfiConverterSequenceAssetSchema{}

func (c FfiConverterSequenceAssetSchema) Lift(rb RustBufferI) []AssetSchema {
	return LiftFromRustBuffer[[]AssetSchema](c, rb)
}

func (c FfiConverterSequenceAssetSchema) Read(reader io.Reader) []AssetSchema {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]AssetSchema, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssetSchemaINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssetSchema) Lower(value []AssetSchema) C.RustBuffer {
	return LowerIntoRustBuffer[[]AssetSchema](c, value)
}

func (c FfiConverterSequenceAssetSchema) LowerExternal(value []AssetSchema) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]AssetSchema](c, value))
}

func (c FfiConverterSequenceAssetSchema) Write(writer io.Writer, value []AssetSchema) {
	if len(value) > math.MaxInt32 {
		panic("[]AssetSchema is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssetSchemaINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssetSchema struct{}

func (FfiDestroyerSequenceAssetSchema) Destroy(sequence []AssetSchema) {
	for _, value := range sequence {
		FfiDestroyerAssetSchema{}.Destroy(value)
	}
}

type FfiConverterSequenceAssignment struct{}

var FfiConverterSequenceAssignmentINSTANCE = FfiConverterSequenceAssignment{}

func (c FfiConverterSequenceAssignment) Lift(rb RustBufferI) []Assignment {
	return LiftFromRustBuffer[[]Assignment](c, rb)
}

func (c FfiConverterSequenceAssignment) Read(reader io.Reader) []Assignment {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]Assignment, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterAssignmentINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceAssignment) Lower(value []Assignment) C.RustBuffer {
	return LowerIntoRustBuffer[[]Assignment](c, value)
}

func (c FfiConverterSequenceAssignment) LowerExternal(value []Assignment) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]Assignment](c, value))
}

func (c FfiConverterSequenceAssignment) Write(writer io.Writer, value []Assignment) {
	if len(value) > math.MaxInt32 {
		panic("[]Assignment is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterAssignmentINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceAssignment struct{}

func (FfiDestroyerSequenceAssignment) Destroy(sequence []Assignment) {
	for _, value := range sequence {
		FfiDestroyerAssignment{}.Destroy(value)
	}
}

type FfiConverterMapUint8Media struct{}

var FfiConverterMapUint8MediaINSTANCE = FfiConverterMapUint8Media{}

func (c FfiConverterMapUint8Media) Lift(rb RustBufferI) map[uint8]Media {
	return LiftFromRustBuffer[map[uint8]Media](c, rb)
}

func (_ FfiConverterMapUint8Media) Read(reader io.Reader) map[uint8]Media {
	result := make(map[uint8]Media)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterUint8INSTANCE.Read(reader)
		value := FfiConverterMediaINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapUint8Media) Lower(value map[uint8]Media) C.RustBuffer {
	return LowerIntoRustBuffer[map[uint8]Media](c, value)
}

func (c FfiConverterMapUint8Media) LowerExternal(value map[uint8]Media) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[map[uint8]Media](c, value))
}

func (_ FfiConverterMapUint8Media) Write(writer io.Writer, mapValue map[uint8]Media) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[uint8]Media is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterUint8INSTANCE.Write(writer, key)
		FfiConverterMediaINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapUint8Media struct{}

func (_ FfiDestroyerMapUint8Media) Destroy(mapValue map[uint8]Media) {
	for key, value := range mapValue {
		FfiDestroyerUint8{}.Destroy(key)
		FfiDestroyerMedia{}.Destroy(value)
	}
}

type FfiConverterMapUint32Uint64 struct{}

var FfiConverterMapUint32Uint64INSTANCE = FfiConverterMapUint32Uint64{}

func (c FfiConverterMapUint32Uint64) Lift(rb RustBufferI) map[uint32]uint64 {
	return LiftFromRustBuffer[map[uint32]uint64](c, rb)
}

func (_ FfiConverterMapUint32Uint64) Read(reader io.Reader) map[uint32]uint64 {
	result := make(map[uint32]uint64)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterUint32INSTANCE.Read(reader)
		value := FfiConverterUint64INSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapUint32Uint64) Lower(value map[uint32]uint64) C.RustBuffer {
	return LowerIntoRustBuffer[map[uint32]uint64](c, value)
}

func (c FfiConverterMapUint32Uint64) LowerExternal(value map[uint32]uint64) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[map[uint32]uint64](c, value))
}

func (_ FfiConverterMapUint32Uint64) Write(writer io.Writer, mapValue map[uint32]uint64) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[uint32]uint64 is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterUint32INSTANCE.Write(writer, key)
		FfiConverterUint64INSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapUint32Uint64 struct{}

func (_ FfiDestroyerMapUint32Uint64) Destroy(mapValue map[uint32]uint64) {
	for key, value := range mapValue {
		FfiDestroyerUint32{}.Destroy(key)
		FfiDestroyerUint64{}.Destroy(value)
	}
}

type FfiConverterMapInt32RefreshedTransfer struct{}

var FfiConverterMapInt32RefreshedTransferINSTANCE = FfiConverterMapInt32RefreshedTransfer{}

func (c FfiConverterMapInt32RefreshedTransfer) Lift(rb RustBufferI) map[int32]RefreshedTransfer {
	return LiftFromRustBuffer[map[int32]RefreshedTransfer](c, rb)
}

func (_ FfiConverterMapInt32RefreshedTransfer) Read(reader io.Reader) map[int32]RefreshedTransfer {
	result := make(map[int32]RefreshedTransfer)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterInt32INSTANCE.Read(reader)
		value := FfiConverterRefreshedTransferINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapInt32RefreshedTransfer) Lower(value map[int32]RefreshedTransfer) C.RustBuffer {
	return LowerIntoRustBuffer[map[int32]RefreshedTransfer](c, value)
}

func (c FfiConverterMapInt32RefreshedTransfer) LowerExternal(value map[int32]RefreshedTransfer) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[map[int32]RefreshedTransfer](c, value))
}

func (_ FfiConverterMapInt32RefreshedTransfer) Write(writer io.Writer, mapValue map[int32]RefreshedTransfer) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[int32]RefreshedTransfer is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterInt32INSTANCE.Write(writer, key)
		FfiConverterRefreshedTransferINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapInt32RefreshedTransfer struct{}

func (_ FfiDestroyerMapInt32RefreshedTransfer) Destroy(mapValue map[int32]RefreshedTransfer) {
	for key, value := range mapValue {
		FfiDestroyerInt32{}.Destroy(key)
		FfiDestroyerRefreshedTransfer{}.Destroy(value)
	}
}

type FfiConverterMapStringSequenceRecipient struct{}

var FfiConverterMapStringSequenceRecipientINSTANCE = FfiConverterMapStringSequenceRecipient{}

func (c FfiConverterMapStringSequenceRecipient) Lift(rb RustBufferI) map[string][]Recipient {
	return LiftFromRustBuffer[map[string][]Recipient](c, rb)
}

func (_ FfiConverterMapStringSequenceRecipient) Read(reader io.Reader) map[string][]Recipient {
	result := make(map[string][]Recipient)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterStringINSTANCE.Read(reader)
		value := FfiConverterSequenceRecipientINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapStringSequenceRecipient) Lower(value map[string][]Recipient) C.RustBuffer {
	return LowerIntoRustBuffer[map[string][]Recipient](c, value)
}

func (c FfiConverterMapStringSequenceRecipient) LowerExternal(value map[string][]Recipient) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[map[string][]Recipient](c, value))
}

func (_ FfiConverterMapStringSequenceRecipient) Write(writer io.Writer, mapValue map[string][]Recipient) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[string][]Recipient is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterStringINSTANCE.Write(writer, key)
		FfiConverterSequenceRecipientINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapStringSequenceRecipient struct{}

func (_ FfiDestroyerMapStringSequenceRecipient) Destroy(mapValue map[string][]Recipient) {
	for key, value := range mapValue {
		FfiDestroyerString{}.Destroy(key)
		FfiDestroyerSequenceRecipient{}.Destroy(value)
	}
}

func GenerateKeys(bitcoinNetwork BitcoinNetwork, witnessVersion WitnessVersion) Keys {
	return FfiConverterKeysINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_func_generate_keys(FfiConverterBitcoinNetworkINSTANCE.Lower(bitcoinNetwork), FfiConverterWitnessVersionINSTANCE.Lower(witnessVersion), _uniffiStatus),
		}
	}))
}

func RestoreBackup(backupPath string, password string, dataDir string) error {
	_, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_rgblibuniffi_fn_func_restore_backup(FfiConverterStringINSTANCE.Lower(backupPath), FfiConverterStringINSTANCE.Lower(password), FfiConverterStringINSTANCE.Lower(dataDir), _uniffiStatus)
		return false
	})
	return _uniffiErr.AsError()
}

func RestoreFromVss(config VssBackupConfig, targetDir string) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_func_restore_from_vss(FfiConverterVssBackupConfigINSTANCE.Lower(config), FfiConverterStringINSTANCE.Lower(targetDir), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func RestoreKeys(bitcoinNetwork BitcoinNetwork, mnemonic string, witnessVersion WitnessVersion) (Keys, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_func_restore_keys(FfiConverterBitcoinNetworkINSTANCE.Lower(bitcoinNetwork), FfiConverterStringINSTANCE.Lower(mnemonic), FfiConverterWitnessVersionINSTANCE.Lower(witnessVersion), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Keys
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterKeysINSTANCE.Lift(_uniffiRV), nil
	}
}

func ScriptHexFromRecipientId(recipientId string) (*string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_func_script_hex_from_recipient_id(FfiConverterStringINSTANCE.Lower(recipientId), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterOptionalStringINSTANCE.Lift(_uniffiRV), nil
	}
}

func ValidateConsignment(filePath string, indexerUrl string, bitcoinNetwork BitcoinNetwork) (ValidateConsignmentResult, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_func_validate_consignment(FfiConverterStringINSTANCE.Lower(filePath), FfiConverterStringINSTANCE.Lower(indexerUrl), FfiConverterBitcoinNetworkINSTANCE.Lower(bitcoinNetwork), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ValidateConsignmentResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterValidateConsignmentResultINSTANCE.Lift(_uniffiRV), nil
	}
}

func ValidateConsignmentOffchain(filePath string, txid string, indexerUrl string, bitcoinNetwork BitcoinNetwork) (ValidateConsignmentResult, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*RgbLibError](FfiConverterRgbLibError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_rgblibuniffi_fn_func_validate_consignment_offchain(FfiConverterStringINSTANCE.Lower(filePath), FfiConverterStringINSTANCE.Lower(txid), FfiConverterStringINSTANCE.Lower(indexerUrl), FfiConverterBitcoinNetworkINSTANCE.Lower(bitcoinNetwork), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ValidateConsignmentResult
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterValidateConsignmentResultINSTANCE.Lift(_uniffiRV), nil
	}
}
