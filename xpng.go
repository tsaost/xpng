// https://raw.githubusercontent.com/parsiya/Go-Security/master/png-tests/png-chunk-extraction.go
// Simple PNG parser. Can be used to discover and extract hidden chunks.
// Minimal error handling, does not play well with malformed chunks and doesn't
// check chunk CRC32 checksums.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// 89 50 4E 47 0D 0A 1A 0A
var PNGHeader = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
var iHDRlength = 13

// uInt32ToInt converts a 4 byte big-endian buffer to int.
func uInt32ToInt(buf []byte) (int, error) {
	if len(buf) == 0 || len(buf) > 4 {
		return 0, errors.New("invalid buffer")
	}
	return int(binary.BigEndian.Uint32(buf)), nil
}

// Chunk starts with a uint32 length (big endian), then 4 byte name,
// then data and finally the CRC32 of the chunk data.
type Chunk struct {
	Length int    // chunk data length
	CType  string // chunk type
	Data   []byte // chunk data
	Crc32  []byte // CRC32 of chunk data
}

// Populate will read bytes from the reader and populate a chunk.
func (c *Chunk) Populate(r io.Reader) error {

	// Four byte buffer.
	buf := make([]byte, 4)

	// Read first four bytes == chunk length.
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	// Convert bytes to int.
	// c.length = int(binary.BigEndian.Uint32(buf))
	var err error
	c.Length, err = uInt32ToInt(buf)
	if err != nil {
		return errors.New("cannot convert length to int")
	}

	// Read second four bytes == chunk type.
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	c.CType = string(buf)

	// Read chunk data.
	tmp := make([]byte, c.Length)
	if _, err := io.ReadFull(r, tmp); err != nil {
		return err
	}
	c.Data = tmp

	// Read CRC32 hash
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	// We don't really care about checking the hash.
	c.Crc32 = buf

	return nil
}

// -----------

type PNG struct {
	Width             int
	Height            int
	BitDepth          int
	ColorType         int
	CompressionMethod int
	FilterMethod      int
	InterlaceMethod   int
	chunks            []*Chunk // Not exported == won't appear in JSON string.
	NumberOfChunks    int
}

// Parse IHDR chunk.
// https://golang.org/src/image/png/reader.go?#L142 is your friend.
func (png *PNG) parseIHDR(iHDR *Chunk) error {
	if iHDR.Length != iHDRlength {
		errString := fmt.Sprintf("invalid IHDR length: got %d - expected %d",
			iHDR.Length, iHDRlength)
		return errors.New(errString)
	}

	// IHDR: http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html#C.IHDR

	// Width:              4 bytes
	// Height:             4 bytes
	// Bit depth:          1 byte
	// Color type:         1 byte
	// Compression method: 1 byte
	// Filter method:      1 byte
	// Interlace method:   1 byte

	tmp := iHDR.Data
	var err error

	png.Width, err = uInt32ToInt(tmp[0:4])
	if err != nil || png.Width <= 0 {
		errString := fmt.Sprintf("invalid width in iHDR - got %x", tmp[0:4])
		return errors.New(errString)
	}

	png.Height, err = uInt32ToInt(tmp[4:8])
	if err != nil || png.Height <= 0 {
		errString := fmt.Sprintf("invalid height in iHDR - got %x", tmp[4:8])
		return errors.New(errString)
	}

	png.BitDepth = int(tmp[8])
	png.ColorType = int(tmp[9])

	// Only compression method 0 is supported
	if int(tmp[10]) != 0 {
		errString := fmt.Sprintf("invalid compression method - expected 0 - got %x",
			tmp[10])
		return errors.New(errString)
	}
	png.CompressionMethod = int(tmp[10])

	// Only filter method 0 is supported
	if int(tmp[11]) != 0 {
		errString := fmt.Sprintf("invalid filter method - expected 0 - got %x",
			tmp[11])
		return errors.New(errString)
	}
	png.FilterMethod = int(tmp[11])

	// Only interlace methods 0 and 1 are supported
	if int(tmp[12]) != 0 {
		errString := fmt.Sprintf("invalid interlace method - expected 0 or 1 - got %x",
			tmp[12])
		return errors.New(errString)
	}
	png.InterlaceMethod = int(tmp[12])

	return nil
}

// Populate populates the PNG fields (and other fields).
func (png *PNG) Populate() error {
	if err := png.parseIHDR(png.chunks[0]); err != nil {
		return err
	}
	png.NumberOfChunks = len(png.chunks)
	return nil
}

// PrintOtherChunks will return a string containing chunk number,
func (png *PNG) PrintOtherChunks() string {
	var output string
	for i, c := range png.chunks {
		output += fmt.Sprintf("-----------\n")
		output += fmt.Sprintf("Chunk # %d\n", i+1)
		output += fmt.Sprintf("Chunk length: %d\n", c.Length)
		output += fmt.Sprintf("Chunk type: %v\n", c.CType)
		limit := 20
		if len(c.Data) < 20 {
			limit = len(c.Data)
		}
		output += fmt.Sprintf("Chunk data (20 bytes): % x\n", c.Data[:limit])
	}
	return output
}

/*
a photo of a dog, style of <lora:robots:1>, absurdres, 8k, best quality (\n)

				(one linebreak only)

Negative prompt:  verybadimagenegative_v1.3,  NG_DeepNegative_V1_75T (\n)

				(one linebreak only)
		(below parameters seperated by comma)

Steps: 50,
Sampler: Euler a,
CFG scale: 5,
Seed: 3943585291,
Size: 640x640,
Model hash: 7f668f12f8,
Model: cyberrealistic_v12,
Denoising strength: 0.5,
Clip skip: 3,
Hires upscale: 1.5000000000000002,
Hires steps: 25,
Hires upscaler: SwinIR_4x,
Eta: 0.9, Score: 5.57

		(above was mostly all on one line)
				(one linebreak only)

Template: a photo of a dog, style of <lora:robots:1>, absurdres, 8k, best quality (\n)

				(one linebreak only)

Negative Template:  verybadimagenegative_v1.3,  NG_DeepNegative_V1_75T
*/

type WebUIMetadata struct {
	Positive          string  `json:"prompt"`
	Negative          string  `json:"negative"`
	Steps             int     `json:"steps"`
	Sampler           string  `json:"sampler"`
	CFGScale          int     `json:"cfg_scale"`
	Seed              int     `json:"seed"`
	Size              string  `json:"size"`
	ModelHash         string  `json:"model_hash"`
	Model             string  `json:"model"`
	DenoisingStrength float64 `json:"denoising_strength"`
	ClipSkip          int     `json:"clip_skip"`
	HiresUpscale      float64 `json:"hires_upscale"`
	HiresSteps        int     `json:"hires_steps"`
	HiresUpscaler     string  `json:"hires_upscaler"`
	Eta               float64 `json:"eta"`
	Score             float64 `json:"score"`
	Template          string  `json:"template,omitempty"`
	NegativeTemplate  string  `json:"negative_template,omitempty"`
}

// implement io.Writer
func (meta *WebUIMetadata) Write(p []byte) (n int, err error) {
	// parse the data returned by GetMetadata into the struct by reading and splitting the bytes by newlines and commas
	// also split by colons to get the key and value
	// then assign the values to the struct fields

	// first split by newlines
	lines := bytes.Split(p, []byte("\n"))
	// then split by commas
	for i, line := range lines {
		switch {
		case i == 0:
			meta.Positive = string(line)
		case i == 1:
			meta.Negative = string(bytes.ReplaceAll(line, []byte("Negative prompt: "), []byte("")))
		case i == 2:
			// split by commas
			// then split by colons
			// then assign to struct fields
			fields := bytes.Split(line, []byte(","))
			for _, field := range fields {
				field = bytes.TrimSpace(field)
				kv := bytes.Split(field, []byte(":"))
				if len(kv) != 2 {
					continue
				}
				kv[0] = bytes.TrimSpace(kv[0])
				kv[0] = bytes.ReplaceAll(kv[0], []byte(" "), []byte("_"))
				kv[1] = bytes.TrimSpace(kv[1])
				switch string(bytes.ToLower(kv[0])) {
				case "steps":
					if meta.Steps, err = strconv.Atoi(string(kv[1])); err != nil {
						return 0, err
					}
				case "sampler":
					meta.Sampler = string(kv[1])
				case "cfg_scale":
					if meta.CFGScale, err = strconv.Atoi(string(kv[1])); err != nil {
						return 0, err
					}
				case "seed":
					if meta.Seed, err = strconv.Atoi(string(kv[1])); err != nil {
						return 0, err
					}
				case "size":
					meta.Size = string(kv[1])
				case "model_hash":
					meta.ModelHash = string(kv[1])
				case "model":
					meta.Model = string(kv[1])
				case "denoising_strength":
					if meta.DenoisingStrength, err = strconv.ParseFloat(string(kv[1]), 64); err != nil {
						return 0, err
					}
				case "clip_skip":
					if meta.ClipSkip, err = strconv.Atoi(string(kv[1])); err != nil {
						return 0, err
					}
				case "hires_upscale":
					if meta.HiresUpscale, err = strconv.ParseFloat(string(kv[1]), 64); err != nil {
						return 0, err
					}
				case "hires_steps":
					if meta.HiresSteps, err = strconv.Atoi(string(kv[1])); err != nil {
						return 0, err
					}
				case "hires_upscaler":
					meta.HiresUpscaler = string(kv[1])
				case "eta":
					if meta.Eta, err = strconv.ParseFloat(string(kv[1]), 64); err != nil {
						return 0, err
					}
				case "score":
					if meta.Score, err = strconv.ParseFloat(string(kv[1]), 64); err != nil {
						return 0, err
					}
				}
			}
		}
	}
	return len(p), nil
}

func (png *PNG) GetMetadata() ([]byte, error) {
	c := png.chunks[1]
	if c.CType == "tEXt" &&
		strings.HasPrefix(string(c.Data), "parameters\000") {
		//					01234567890"
		return c.Data[11:], nil
	}
	return nil, errors.New("no webui metadata found")
}

func stderr(s string) {
	_, _ = os.Stderr.WriteString(s)
	_, _ = os.Stderr.WriteString("\n")
}

func parsePng(filename string) error {
	imgFile, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer imgFile.Close()

	// Read first 8 bytes == PNG header.
	header := make([]byte, 8)
	// Read CRC32 hash
	if _, err = io.ReadFull(imgFile, header); err != nil {
		return err
	}
	if string(header) != PNGHeader {
		return fmt.Errorf("invalid png header. got %x - expected %x\n",
			header, PNGHeader)
	}

	var png PNG

	// Reset err
	err = nil
	for err == nil {
		var c Chunk
		err = (&c).Populate(imgFile)
		// Drop the last empty chunk.
		if c.CType != "" {
			png.chunks = append(png.chunks, &c)
		}
	}

	if err = (&png).Populate(); err != nil {
		fmt.Println("Failed to populate PNG fields.")
		panic(err)
	}

	if verbose {
		fmt.Println("PNG info")
		jsoned, err := json.MarshalIndent(png, "", "    ")
		if err != nil {
			fmt.Printf("%+v", png)
		} else {
			fmt.Println(string(jsoned))
		}

		fmt.Println("\nPrinting chunks\n----------")
		fmt.Println(png.PrintOtherChunks())
		fmt.Println("----------")
	}
	meta := new(WebUIMetadata)
	m, err := png.GetMetadata()
	if err != nil {
		return err
	}
	if _, err = meta.Write(m); err != nil {
		return err
	}
	var dat []byte
	if dat, err = json.MarshalIndent(meta, "", "    "); err != nil {
		return err
	}
	_, _ = os.Stdout.Write(dat)
	return nil
}

func usage() {
	xpng := filepath.Base(os.Args[0])
	fmt.Printf("%s -v(erbose) pattern1 [pattern2] ....\n", xpng)
}

var verbose = false

func parsePngWithWildcard(wildcardArgs []string) error {
	// fmt.Println("moveMatchedFiles directory:", directory)
	f, err := os.Open(".")
	if err != nil {
		return err
	}
	allInfos, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return err
	}
	for _, x := range allInfos {
		if x.IsDir() {
			continue
		}
		name := x.Name()
		if name == "." || name == ".." {
			continue
		}
		lowercaseName := strings.ToLower(name) // ignore case
		for _, y := range wildcardArgs {
			matched, err := filepath.Match(y, lowercaseName)
			if err != nil {
				return err
			}
			if matched {
				fmt.Println(name)
				parsePng(name)
				break
			}
		}
	}
	return nil
}

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		return
	}

	wildcardArgs := make([]string, 0, len(args))
	for _, x := range args {
		switch {
		case x == "-v", x == "-verbose":
			verbose = true
			continue
		case strings.Index(x, "*") >= 0,
			strings.Index(x, "?") >= 0:
			wildcardArgs = append(wildcardArgs, x)
		default:
			if err := parsePng(x); err != nil {
				stderr(err.Error())
			}
		}
	}
	if err := parsePngWithWildcard(wildcardArgs); err != nil {
		stderr(err.Error())
	}
}
