package aff4

import (
	"strings"
	"unicode"
)

// parseYAML reads the typed subset of information.yaml this package accepts:
//
//	version: "1.0"
//	streams:
//	  - uri: "aff4://image"
//	    type: Image
//	    category: imageStream
//	    size: 250
//	    chunkSize: 64
//	    chunksPerSegment: 2
//	    compressionMethod: zlib
//	    stored: "aff4://image"
//	    target: "aff4://source-a"
//	    dependentStream: "aff4://source-b"
//	    dataStream: "aff4://map-data"
//	    hash: "SHA1:0123..."
//
// Sequences, flow collections, anchors, aliases and multi-line scalars are
// refused by name rather than guessed at.
func parseYAML(member, text string, limits Limits) (turtleParse, error) {
	if err := checkLines(member, text, limits.MaxLineBytes); err != nil {
		return turtleParse{}, err
	}
	text = strings.TrimPrefix(text, "\xef\xbb\xbf")

	var (
		version     string
		versionLine uint64
		builders    []*streamBuilder
		inStreams   bool
		warnings    []string
		ignored     int
		unknownKeys = make(map[string]struct{})
	)

	for index, raw := range strings.Split(text, "\n") {
		lineNo := uint64(index + 1)
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" || trimmed == "..." {
			continue
		}
		leading := line[:len(line)-len(strings.TrimLeftFunc(line, unicode.IsSpace))]
		if (len(line) > 0 && line[0] == '\t') || strings.Contains(leading, "\t") {
			return turtleParse{}, corruptf(
				"AFF4 descriptor %s line %d: tabs are not accepted in YAML indentation", member, lineNo)
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Version keys are accepted only at the top level and follow the same
		// conflict rule as the line-oriented reader.
		rest, isVersion := "", false
		if after, ok := strings.CutPrefix(trimmed, "aff4:version:"); ok {
			rest, isVersion = after, true
		} else if after, ok := strings.CutPrefix(trimmed, "version:"); ok {
			rest, isVersion = after, true
		}
		if isVersion && indent == 0 {
			value, err := yamlValue(member, lineNo, rest, limits)
			if err != nil {
				return turtleParse{}, err
			}
			parsed, ok := parseVersionNumber(value)
			if !ok {
				return turtleParse{}, corruptf(
					"AFF4 descriptor %s line %d: expected an AFF4 version, found %q", member, lineNo, value)
			}
			if version != "" && version != parsed {
				return turtleParse{}, corruptf(
					"AFF4 descriptor %s line %d: conflicting version lines: %s and %s",
					member, lineNo, version, parsed)
			}
			if version == "" {
				version = parsed
				versionLine = lineNo
			}
			continue
		}

		if !inStreams {
			if trimmed == "streams:" || trimmed == "streams: []" {
				if trimmed == "streams: []" {
					return turtleParse{version: version, versionLine: versionLine}, nil
				}
				inStreams = true
				continue
			}
			if !strings.Contains(trimmed, ":") {
				return turtleParse{}, corruptf(
					"AFF4 descriptor %s line %d: expected a key, found %q", member, lineNo, trimmed)
			}
			continue
		}

		body := trimmed
		isItem := false
		if after, ok := strings.CutPrefix(trimmed, "- "); ok {
			isItem = true
			body = strings.TrimSpace(after)
		} else if trimmed == "-" {
			isItem = true
			body = ""
		}
		key, valueText, ok := strings.Cut(body, ":")
		if !ok {
			return turtleParse{}, corruptf(
				"AFF4 descriptor %s line %d: expected key: value, found %q", member, lineNo, body)
		}
		key = strings.TrimSpace(key)
		var value *string
		if strings.TrimSpace(valueText) != "" {
			parsed, err := yamlValue(member, lineNo, valueText, limits)
			if err != nil {
				return turtleParse{}, err
			}
			value = &parsed
		}

		if isItem {
			if indent > 2 && len(builders) > 0 {
				return turtleParse{}, corruptf(
					"AFF4 descriptor %s line %d: a stream item does not start at the sequence indent",
					member, lineNo)
			}
			builder := &streamBuilder{}
			if err := applyYAMLKey(member, lineNo, limits, builder, key, value, &ignored, unknownKeys); err != nil {
				return turtleParse{}, err
			}
			builders = append(builders, builder)
			continue
		}

		if len(builders) == 0 {
			return turtleParse{}, corruptf(
				"AFF4 descriptor %s line %d: stream property appears before the first item", member, lineNo)
		}
		if err := applyYAMLKey(member, lineNo, limits, builders[len(builders)-1], key, value, &ignored, unknownKeys); err != nil {
			return turtleParse{}, err
		}
	}

	if inStreams && len(builders) == 0 {
		return turtleParse{}, corruptf(
			"AFF4 descriptor %s line 1: streams block declares no item", member)
	}

	byURI := make(map[string]*streamBuilder, len(builders))
	for _, builder := range builders {
		if builder.uri == "" {
			return turtleParse{}, corruptf("AFF4 descriptor %s line 1: stream item has no uri", member)
		}
		byURI[builder.uri] = builder
	}
	subjectCount := len(byURI)
	streams := finalizeStreams(byURI)
	images, maps, zeros, segments, fileImages := classifyStreams(streams)
	for _, key := range sortedKeys(unknownKeys) {
		pushWarning(&warnings, limits.MaxWarnings, "%s ignores unknown stream key %s", member, key)
	}

	return turtleParse{
		subjects:              subjectCount,
		version:               version,
		versionLine:           versionLine,
		streams:               streams,
		imageStreams:          images,
		mapStreams:            maps,
		zeroStreams:           zeros,
		segmentStreams:        segments,
		fileImageStreams:      fileImages,
		ignoredPredicates:     sortedKeys(unknownKeys),
		ignoredPredicateCount: ignored,
		warnings:              warnings,
	}, nil
}

// yamlValue decodes one scalar: a single- or double-quoted string, or a bare
// word with an optional " #" comment.  Flow collections and anchors are
// refused by name.
func yamlValue(member string, line uint64, raw string, limits Limits) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", corruptf("AFF4 descriptor %s line %d: key has no value", member, line)
	}
	switch raw[0] {
	case '{', '[', '&', '*', '|', '>':
		return "", corruptf(
			"AFF4 descriptor %s line %d: unsupported YAML construct in a stream value", member, line)
	}
	var value string
	if raw[0] == '"' || raw[0] == '\'' {
		quote := raw[0]
		rest := raw[1:]
		end := strings.IndexByte(rest, quote)
		if end < 0 {
			return "", corruptf(
				"AFF4 descriptor %s line %d: unterminated quoted scalar", member, line)
		}
		value = rest[:end]
	} else {
		end := strings.Index(raw, " #")
		if end < 0 {
			end = len(raw)
		}
		value = strings.TrimSpace(raw[:end])
	}
	if len(value) > limits.MaxLiteralBytes {
		return "", limitf("AFF4 Turtle line %d has a %d-byte literal, limit is %d",
			line, len(value), limits.MaxLiteralBytes)
	}
	return value, nil
}

func applyYAMLKey(member string, line uint64, limits Limits, builder *streamBuilder,
	key string, value *string, ignored *int, unknownKeys map[string]struct{}) error {

	need := func() (string, error) {
		if value == nil {
			return "", corruptf(
				"AFF4 descriptor %s line %d: stream key %s has no value", member, line, key)
		}
		return *value, nil
	}
	number := func() (uint64, error) {
		text, err := need()
		if err != nil {
			return 0, err
		}
		parsed, ok := parseU64(text)
		if !ok {
			return 0, corruptf(
				"AFF4 descriptor %s line %d: stream key %s is not a non-negative integer: %q",
				member, line, key, text)
		}
		return parsed, nil
	}

	switch key {
	case "uri":
		text, err := need()
		if err != nil {
			return err
		}
		builder.uri = text
	case "type", "class":
		text, err := need()
		if err != nil {
			return err
		}
		if class, ok := yamlClassName(text); ok {
			builder.class = class
		} else {
			(*ignored)++
		}
	case "category":
		text, err := need()
		if err != nil {
			return err
		}
		if category, ok := yamlCategoryName(text); ok {
			builder.category = category
		} else {
			(*ignored)++
		}
	case "size":
		parsed, err := number()
		if err != nil {
			return err
		}
		builder.size = &parsed
	case "chunkSize", "chunk_size":
		parsed, err := number()
		if err != nil {
			return err
		}
		builder.chunkSize = &parsed
	case "chunksPerSegment", "chunks_per_segment":
		parsed, err := number()
		if err != nil {
			return err
		}
		builder.chunksPerSegment = &parsed
	case "compressionMethod", "compression_method":
		text, err := need()
		if err != nil {
			return err
		}
		builder.compression = text
	case "stored":
		text, err := need()
		if err != nil {
			return err
		}
		builder.stored = append(builder.stored, text)
	case "target":
		text, err := need()
		if err != nil {
			return err
		}
		builder.targets = append(builder.targets, text)
	case "dependentStream", "dependent_stream":
		text, err := need()
		if err != nil {
			return err
		}
		builder.dependentStreams = append(builder.dependentStreams, text)
	case "dataStream", "data_stream":
		text, err := need()
		if err != nil {
			return err
		}
		builder.dataStream = text
	case "hash":
		text, err := need()
		if err != nil {
			return err
		}
		algorithm, hashValue, ok := strings.Cut(text, ":")
		if !ok {
			return corruptf(
				"AFF4 descriptor %s line %d: hash value must be ALGORITHM:VALUE", member, line)
		}
		if len(builder.hashes) < limits.MaxHashesPerStream {
			builder.hashes = append(builder.hashes, Hash{
				Algorithm:    strings.TrimSpace(algorithm),
				ValuePresent: hashValue != "",
				ValueLen:     len(hashValue),
			})
		}
	default:
		(*ignored)++
		if len(unknownKeys) < limits.MaxIgnoredPredicates {
			unknownKeys[key] = struct{}{}
		}
	}
	return nil
}

func yamlClassName(value string) (string, bool) {
	local, ok := yamlLocal(value)
	if !ok {
		return "", false
	}
	switch local {
	case "Image", "ImageStream", "Map", "Zero", "ZipSegment", "FileImage":
		return local, true
	default:
		return "", false
	}
}

func yamlCategoryName(value string) (string, bool) {
	local, ok := yamlLocal(value)
	if !ok {
		return "", false
	}
	switch local {
	case "imageStream", "map", "zero", "fileImage":
		return local, true
	default:
		return "", false
	}
}

func yamlLocal(value string) (string, bool) {
	if strings.ContainsAny(value, "#/") {
		return iriLocal(value)
	}
	return strings.TrimPrefix(value, "aff4:"), true
}
