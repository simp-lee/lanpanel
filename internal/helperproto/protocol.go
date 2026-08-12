package helperproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	frameHeaderBytes = 16
	maxRequestBytes  = 16 << 10
	maxResponseBytes = 16 << 10
	maxSecretBytes   = 8 << 10
)

var frameMagic = [4]byte{'L', 'P', 'H', '1'}

type frameKind byte

const (
	frameRequest  frameKind = 1
	frameSecret   frameKind = 2
	frameResponse frameKind = 3
)

var ErrProtocol = errors.New("helper protocol violation")

type Secret struct{ value []byte }

func (secret *Secret) Present() bool { return secret != nil && len(secret.value) != 0 }

func NewOutputSecret(value []byte) (*Secret, error) {
	if len(value) == 0 || len(value) > maxSecretBytes {
		return nil, fmt.Errorf("output secret is empty or unbounded")
	}
	return &Secret{value: append([]byte(nil), value...)}, nil
}

// Use exposes secret bytes only to the immediate intended consumer and always
// clears the protocol-owned buffer before returning.
func (secret *Secret) Use(consumer func([]byte) error) error {
	if secret == nil || consumer == nil || len(secret.value) == 0 {
		return fmt.Errorf("secret frame is unavailable")
	}
	defer secret.Destroy()
	return consumer(secret.value)
}

func (secret *Secret) OutputCopy() ([]byte, error) {
	if secret == nil || len(secret.value) == 0 {
		return nil, fmt.Errorf("secret frame unavailable")
	}
	value := append([]byte(nil), secret.value...)
	secret.Destroy()
	return value, nil
}

func (secret *Secret) Destroy() {
	if secret == nil {
		return
	}
	clear(secret.value)
	secret.value = nil
}

func WriteRequest(writer io.Writer, request Request, secret []byte) error {
	if writer == nil {
		return fmt.Errorf("helper protocol writer is nil")
	}
	policy, known := PolicyFor(request.Operation)
	if !known {
		return fmt.Errorf("helper operation is unknown")
	}
	if policy.SecretInput && len(secret) == 0 || !policy.SecretInput && len(secret) != 0 {
		return fmt.Errorf("helper request secret shape is invalid")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := writeFrame(writer, frameRequest, payload, maxRequestBytes); err != nil {
		return err
	}
	if policy.SecretInput {
		return writeFrame(writer, frameSecret, secret, maxSecretBytes)
	}
	return nil
}

// ReadRequest reads exactly one request transaction. A required secret frame
// must immediately follow its request; no queued request can intervene.
func ReadRequest(reader io.Reader) (Request, *Secret, error) {
	payload, err := readFrame(reader, frameRequest, maxRequestBytes)
	if err != nil {
		return Request{}, nil, err
	}
	var request Request
	if err := decodeCanonical(payload, &request); err != nil {
		return Request{}, nil, err
	}
	policy, known := PolicyFor(request.Operation)
	if !known {
		return Request{}, nil, fmt.Errorf("%w: unknown operation", ErrProtocol)
	}
	if !policy.SecretInput {
		return request, nil, nil
	}
	value, err := readFrame(reader, frameSecret, maxSecretBytes)
	if err != nil {
		return Request{}, nil, err
	}
	if len(value) == 0 {
		return Request{}, nil, fmt.Errorf("%w: empty required secret", ErrProtocol)
	}
	return request, &Secret{value: value}, nil
}

func WriteResponse(writer io.Writer, operation Operation, response Response, secret *Secret) error {
	if secret != nil {
		defer secret.Destroy()
	}
	policy, known := PolicyFor(operation)
	wantsSecret := known && policy.SecretOutput && response.Code == ResponseSucceeded
	if !known || wantsSecret != (secret != nil && secret.Present()) {
		return fmt.Errorf("helper response secret shape is invalid")
	}
	if err := ValidateResponse(operation, response); err != nil {
		return err
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if err := writeFrame(writer, frameResponse, payload, maxResponseBytes); err != nil {
		return err
	}
	if wantsSecret {
		return writeFrame(writer, frameSecret, secret.value, maxSecretBytes)
	}
	return nil
}

func ReadResponse(reader io.Reader, operation Operation) (Response, *Secret, error) {
	policy, known := PolicyFor(operation)
	if !known {
		return Response{}, nil, fmt.Errorf("helper response operation is unknown")
	}
	payload, err := readFrame(reader, frameResponse, maxResponseBytes)
	if err != nil {
		return Response{}, nil, err
	}
	var response Response
	if err := decodeCanonical(payload, &response); err != nil {
		return Response{}, nil, err
	}
	if err := ValidateResponse(operation, response); err != nil {
		return Response{}, nil, err
	}
	if !policy.SecretOutput || response.Code != ResponseSucceeded {
		return response, nil, nil
	}
	value, err := readFrame(reader, frameSecret, maxSecretBytes)
	if err != nil {
		return Response{}, nil, err
	}
	return response, &Secret{value: value}, nil
}

func writeFrame(writer io.Writer, kind frameKind, payload []byte, maximum int) error {
	if len(payload) == 0 || len(payload) > maximum {
		return fmt.Errorf("%w: frame size", ErrProtocol)
	}
	header := make([]byte, frameHeaderBytes)
	copy(header[:4], frameMagic[:])
	header[4] = byte(kind)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[12:16], crc32.ChecksumIEEE(payload))
	if err := writeFull(writer, header); err != nil {
		return err
	}
	return writeFull(writer, payload)
}

func readFrame(reader io.Reader, expected frameKind, maximum int) ([]byte, error) {
	header := make([]byte, frameHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("%w: read header", ErrProtocol)
	}
	if !bytes.Equal(header[:4], frameMagic[:]) || frameKind(header[4]) != expected || header[5] != 0 || header[6] != 0 || header[7] != 0 {
		return nil, fmt.Errorf("%w: frame identity", ErrProtocol)
	}
	length := int(binary.BigEndian.Uint32(header[8:12]))
	if length <= 0 || length > maximum {
		return nil, fmt.Errorf("%w: frame bound", ErrProtocol)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return nil, fmt.Errorf("%w: read payload", ErrProtocol)
	}
	if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(header[12:16]) {
		clear(payload)
		return nil, fmt.Errorf("%w: frame checksum", ErrProtocol)
	}
	return payload, nil
}

func decodeCanonical(payload []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%w: typed JSON", ErrProtocol)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrProtocol)
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, payload) {
		return fmt.Errorf("%w: non-canonical JSON", ErrProtocol)
	}
	return nil
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
