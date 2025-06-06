package widevine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Eyevinn/mp4ff/mp4"
	"google.golang.org/protobuf/proto"

	wvpb "wvgo/gowidevine/widevinepb"
)

// WidevineSystemID is the system ID of Widevine.
const WidevineSystemID = "edef8ba979d64acea3c827dcd51d21ed"

// PSSH represents a PSSH box containing Widevine data.
type PSSH struct {
	box  *mp4.PsshBox
	data *wvpb.WidevinePsshData
}

// NewPSSH creates a PSSH from bytes
func NewPSSH(b []byte) (*PSSH, error) {
	box, err := mp4.DecodeBox(0, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("decode box: %w", err)
	}

	psshBox, ok := box.(*mp4.PsshBox)
	if !ok {
		return nil, fmt.Errorf("box is a %s instead of a PSSH", box.Type())
	}

	if hex.EncodeToString(psshBox.SystemID) != WidevineSystemID {
		return nil, fmt.Errorf("system id is %s instead of widevine", hex.EncodeToString(psshBox.SystemID))
	}

	data := &wvpb.WidevinePsshData{}
	if err = proto.Unmarshal(psshBox.Data, data); err != nil {
		return nil, fmt.Errorf("unmarshal pssh data: %w", err)
	}

	return &PSSH{
		box:  psshBox,
		data: data,
	}, nil
}

// Version returns the version of the PSSH box.
func (p *PSSH) Version() byte {
	return p.box.Version
}

// Flags returns the flags of the PSSH box.
func (p *PSSH) Flags() uint32 {
	return p.box.Flags
}

// RawData returns the data of the PSSH box.
func (p *PSSH) RawData() []byte {
	return p.box.Data
}

// Data returns the parsed data of the PSSH box.
func (p *PSSH) Data() *wvpb.WidevinePsshData {
	return p.data
}

// CreatePSSH membuat PSSH box baru dari daftar key IDs.
func CreatePSSH(keyIDs [][]byte) ([]byte, error) {
	// Membuat objek WidevinePsshData dengan key IDs yang diberikan.
	data := &wvpb.WidevinePsshData{}
	for _, keyID := range keyIDs {
		data.KeyIds = append(data.KeyIds, keyID)
	}

	// Serialisasi objek WidevinePsshData menggunakan protobuf.
	encodedData, err := proto.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal WidevinePsshData: %w", err)
	}

	// Decode WidevineSystemID sebagai mp4.UUID untuk PSSH box
	systemID, err := hex.DecodeString(WidevineSystemID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Widevine system ID: %w", err)
	}

	// Buat PSSH box baru dengan SystemID Widevine.
	psshBox := &mp4.PsshBox{
		SystemID: systemID,
		Version:  0, // Set versi sesuai kebutuhan
		Flags:    0,
		Data:     encodedData,
	}

	// Encode PSSH box menjadi byte array.
	buf := &bytes.Buffer{}
	if err := psshBox.Encode(buf); err != nil {
		return nil, fmt.Errorf("failed to encode PSSH box: %w", err)
	}

	return buf.Bytes(), nil
}

// Fungsi untuk mengubah hex string ke byte array.
func HexToByte(hexStr string) ([]byte, error) {
	// Hilangkan karakter `-` dari hexStr jika ada.
	cleanedHexStr := strings.ReplaceAll(hexStr, "-", "")
	cleanedHexStr = strings.ReplaceAll(cleanedHexStr, " ", "")
	bytes, err := hex.DecodeString(cleanedHexStr)
	if err != nil {
		return nil, fmt.Errorf("gagal mengonversi hex ke byte array: %w", err)
	}
	return bytes, nil
}
