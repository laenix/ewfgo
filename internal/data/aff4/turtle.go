package aff4

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// turtleObject is one Turtle object: an IRI or a literal.
type turtleObject struct {
	isIRI bool
	text  string
}

type aff4Triple struct {
	subject   string
	predicate string
	object    turtleObject
	line      uint64
}

// turtleParse is what one metadata member produced.
type turtleParse struct {
	triples               int
	subjects              int
	version               string
	versionLine           uint64
	streams               []Stream
	storedLinks           []StoredLink
	imageStreams          int
	mapStreams            int
	zeroStreams           int
	segmentStreams        int
	fileImageStreams      int
	unknownSubjects       int
	ignoredPredicates     []string
	ignoredPredicateCount int
	warnings              []string
}

type streamBuilder struct {
	uri              string
	class            string
	category         string
	size             *uint64
	chunkSize        *uint64
	chunksPerSegment *uint64
	compression      string
	hashes           []Hash
	stored           []string
	targets          []string
	dependentStreams []string
	dataStream       string
}

type prefixDecl struct {
	name string
	iri  string
}

type nameTerm struct {
	isIRI bool
	iri   string
	bare  string
}

type turtleParser struct {
	bytes    []byte
	pos      int
	line     uint64
	limits   Limits
	prefixes []prefixDecl
	triples  []aff4Triple
	subjects map[string]struct{}
}

func parseTurtle(member, text string, limits Limits) (turtleParse, error) {
	if err := checkLines(member, text, limits.MaxLineBytes); err != nil {
		return turtleParse{}, err
	}
	parser := &turtleParser{
		bytes:    []byte(text),
		line:     1,
		limits:   limits,
		subjects: make(map[string]struct{}),
	}
	if err := parser.run(); err != nil {
		return turtleParse{}, err
	}
	return interpretTriples(parser.triples, len(parser.subjects), limits), nil
}

func (p *turtleParser) byte() (byte, bool) {
	if p.pos >= len(p.bytes) {
		return 0, false
	}
	return p.bytes[p.pos], true
}

func (p *turtleParser) bump() (byte, bool) {
	value, ok := p.byte()
	if !ok {
		return 0, false
	}
	p.pos++
	if value == '\n' {
		p.line++
	}
	return value, true
}

func (p *turtleParser) eof() bool { return p.pos >= len(p.bytes) }

func (p *turtleParser) errorf(format string, args ...any) error {
	return corruptf("malformed AFF4 Turtle at line %d: %s", p.line, fmt.Sprintf(format, args...))
}

func (p *turtleParser) unsupported(construct string) error {
	return unsupportedf("unsupported AFF4 Turtle construct at line %d: %s", p.line, construct)
}

func (p *turtleParser) skipSpace() {
	for {
		value, ok := p.byte()
		if !ok {
			return
		}
		if isASCIISpace(value) {
			p.bump()
			continue
		}
		if value == '#' {
			for {
				consumed, present := p.bump()
				if !present || consumed == '\n' {
					break
				}
			}
			continue
		}
		return
	}
}

func (p *turtleParser) atKeyword(keyword string, caseInsensitive bool) bool {
	if p.pos+len(keyword) > len(p.bytes) {
		return false
	}
	slice := p.bytes[p.pos : p.pos+len(keyword)]
	matches := true
	if caseInsensitive {
		matches = strings.EqualFold(string(slice), keyword)
	} else {
		matches = string(slice) == keyword
	}
	if !matches {
		return false
	}
	if p.pos+len(keyword) == len(p.bytes) {
		return true
	}
	return isASCIISpace(p.bytes[p.pos+len(keyword)])
}

func (p *turtleParser) prefixIRI(name string) (string, bool) {
	for _, prefix := range p.prefixes {
		if prefix.name == name {
			return prefix.iri, true
		}
	}
	return "", false
}

func (p *turtleParser) parseIRI() (string, error) {
	value, ok := p.byte()
	if !ok || value != '<' {
		return "", p.errorf("expected '<' to start an IRI")
	}
	p.bump()
	out := make([]byte, 0, 32)
	for {
		consumed, present := p.bump()
		if !present {
			return "", p.errorf("unterminated IRI")
		}
		switch {
		case consumed == '>':
			if !utf8.Valid(out) {
				return "", p.errorf("IRI is not valid UTF-8")
			}
			return string(out), nil
		case consumed == '\\':
			if err := p.parseEscape(&out, true); err != nil {
				return "", err
			}
		case consumed <= 0x20 || consumed == '<':
			return "", p.errorf("invalid character in an IRI")
		default:
			out = append(out, consumed)
		}
		if len(out) > p.limits.MaxURIBytes {
			return "", limitf("AFF4 Turtle line %d has a %d-byte IRI, limit is %d",
				p.line, len(out), p.limits.MaxURIBytes)
		}
	}
}

func (p *turtleParser) parseEscape(out *[]byte, inIRI bool) error {
	value, ok := p.bump()
	if !ok {
		return p.errorf("trailing backslash")
	}
	if value == 'u' || value == 'U' {
		digits := 4
		if value == 'U' {
			digits = 8
		}
		var scalar uint32
		for index := 0; index < digits; index++ {
			digit, present := p.bump()
			if !present {
				return p.errorf("incomplete unicode escape")
			}
			hex, valid := hexValue(digit)
			if !valid {
				return p.errorf("non-hexadecimal digit in a unicode escape")
			}
			scalar = scalar*16 + hex
		}
		r := rune(scalar)
		if scalar > unicode.MaxRune || !utf8.ValidRune(r) {
			return p.errorf("unicode escape is not a scalar value")
		}
		*out = append(*out, string(r)...)
		return nil
	}
	if inIRI {
		return p.unsupported("unsupported escape sequence in an IRI")
	}
	switch value {
	case '"':
		*out = append(*out, '"')
	case '\\':
		*out = append(*out, '\\')
	case '\'':
		*out = append(*out, '\'')
	case 'n':
		*out = append(*out, '\n')
	case 'r':
		*out = append(*out, '\r')
	case 't':
		*out = append(*out, '\t')
	case 'b':
		*out = append(*out, 0x08)
	case 'f':
		*out = append(*out, 0x0c)
	default:
		return p.unsupported("unsupported escape sequence in a literal")
	}
	return nil
}

func (p *turtleParser) parseTerm() (nameTerm, error) {
	start := p.pos
	for {
		value, ok := p.byte()
		if !ok {
			break
		}
		if isASCIISpace(value) || strings.ContainsRune(";,()[]<>\"", rune(value)) {
			break
		}
		if value == '#' {
			break
		}
		if value == '.' {
			next := byte(0)
			hasNext := p.pos+1 < len(p.bytes)
			if hasNext {
				next = p.bytes[p.pos+1]
			}
			terminates := !hasNext || isASCIISpace(next) ||
				next == ';' || next == ',' || next == '.' || next == '#' || next == ')' || next == ']'
			if terminates {
				break
			}
		}
		p.bump()
	}
	if p.pos == start {
		return nameTerm{}, p.errorf("expected a name")
	}
	word := string(p.bytes[start:p.pos])
	if !utf8.ValidString(word) {
		return nameTerm{}, p.errorf("name is not valid UTF-8")
	}
	if colon := strings.IndexByte(word, ':'); colon >= 0 {
		prefix := word[:colon]
		local := word[colon+1:]
		if prefix == "" {
			if _, ok := p.prefixIRI(""); !ok {
				return nameTerm{}, p.errorf("default prefix is not declared")
			}
		}
		base, ok := p.prefixIRI(prefix)
		if !ok {
			return nameTerm{}, p.errorf("undeclared prefix %q", prefix)
		}
		expanded := base + local
		if len(expanded) > p.limits.MaxURIBytes {
			return nameTerm{}, limitf("AFF4 Turtle line %d has a %d-byte IRI, limit is %d",
				p.line, len(expanded), p.limits.MaxURIBytes)
		}
		return nameTerm{isIRI: true, iri: expanded}, nil
	}
	return nameTerm{bare: word}, nil
}

func (p *turtleParser) parseSubject() (string, error) {
	p.skipSpace()
	value, ok := p.byte()
	if !ok {
		return "", p.errorf("expected a subject")
	}
	switch value {
	case '<':
		return p.parseIRI()
	case '[':
		return "", p.unsupported("blank node property list")
	case '(':
		return "", p.unsupported("collection")
	}
	term, err := p.parseTerm()
	if err != nil {
		return "", err
	}
	if term.isIRI {
		return term.iri, nil
	}
	if strings.HasPrefix(term.bare, "_:") {
		return term.bare, nil
	}
	return "", p.errorf("subject is not an IRI or blank node")
}

func (p *turtleParser) parsePredicate() (string, error) {
	p.skipSpace()
	value, ok := p.byte()
	if !ok {
		return "", p.errorf("expected a predicate")
	}
	switch value {
	case '<':
		return p.parseIRI()
	case '[':
		return "", p.unsupported("blank node property list")
	case '(':
		return "", p.unsupported("collection")
	}
	term, err := p.parseTerm()
	if err != nil {
		return "", err
	}
	if term.isIRI {
		return term.iri, nil
	}
	if term.bare == "a" {
		return RDFType, nil
	}
	return "", p.errorf("predicate is not an IRI")
}

func (p *turtleParser) parseLiteral() (string, error) {
	value, ok := p.byte()
	if !ok || value != '"' {
		return "", p.errorf("expected '\"' to start a literal")
	}
	p.bump()
	if p.pos+1 < len(p.bytes) && p.bytes[p.pos] == '"' && p.bytes[p.pos+1] == '"' {
		return "", p.unsupported("long string literal")
	}
	out := make([]byte, 0, 32)
	for {
		consumed, present := p.bump()
		if !present {
			return "", p.errorf("unterminated string literal")
		}
		switch {
		case consumed == '"':
			goto datatype
		case consumed == '\\':
			if err := p.parseEscape(&out, false); err != nil {
				return "", err
			}
		case consumed == '\n' || consumed == '\r':
			return "", p.errorf("line break inside a short string literal")
		default:
			out = append(out, consumed)
		}
		if len(out) > p.limits.MaxLiteralBytes {
			return "", limitf("AFF4 Turtle line %d has a %d-byte literal, limit is %d",
				p.line, len(out), p.limits.MaxLiteralBytes)
		}
	}

datatype:
	p.skipSpace()
	if p.pos+1 < len(p.bytes) && p.bytes[p.pos] == '^' && p.bytes[p.pos+1] == '^' {
		p.pos += 2
		p.skipSpace()
		next, ok := p.byte()
		if !ok {
			return "", p.errorf("datatype is missing")
		}
		if next == '<' {
			if _, err := p.parseIRI(); err != nil {
				return "", err
			}
		} else {
			term, err := p.parseTerm()
			if err != nil {
				return "", err
			}
			if !term.isIRI {
				return "", p.errorf("datatype is not an IRI")
			}
		}
	} else if next, ok := p.byte(); ok && next == '@' {
		p.bump()
		start := p.pos
		for {
			value, present := p.byte()
			if !present || !(isASCIIAlnum(value) || value == '-') {
				break
			}
			p.bump()
		}
		if p.pos == start {
			return "", p.errorf("language tag is empty")
		}
	}
	if !utf8.Valid(out) {
		return "", p.errorf("literal is not valid UTF-8")
	}
	return string(out), nil
}

func (p *turtleParser) parseObject() (turtleObject, error) {
	p.skipSpace()
	value, ok := p.byte()
	if !ok {
		return turtleObject{}, p.errorf("expected an object")
	}
	switch value {
	case '<':
		iri, err := p.parseIRI()
		return turtleObject{isIRI: true, text: iri}, err
	case '"':
		literal, err := p.parseLiteral()
		return turtleObject{text: literal}, err
	case '[':
		return turtleObject{}, p.unsupported("blank node property list")
	case '(':
		return turtleObject{}, p.unsupported("collection")
	}
	term, err := p.parseTerm()
	if err != nil {
		return turtleObject{}, err
	}
	if term.isIRI {
		return turtleObject{isIRI: true, text: term.iri}, nil
	}
	if term.bare == "true" || term.bare == "false" || allDigits(term.bare) {
		return turtleObject{text: term.bare}, nil
	}
	return turtleObject{}, p.errorf("object is not an IRI, string, number, or boolean")
}

func (p *turtleParser) pushTriple(subject, predicate string, object turtleObject) error {
	if len(p.triples) >= p.limits.MaxTriples {
		return limitf("AFF4 Turtle has more than %d triples", p.limits.MaxTriples)
	}
	p.triples = append(p.triples, aff4Triple{
		subject:   subject,
		predicate: predicate,
		object:    object,
		line:      p.line,
	})
	return nil
}

func (p *turtleParser) parsePrefixBody() error {
	p.skipSpace()
	start := p.pos
	for {
		value, ok := p.byte()
		if !ok {
			return p.errorf("prefix declaration is incomplete")
		}
		if value == ':' {
			break
		}
		if !(isASCIIAlnum(value) || value == '_' || value == '-') {
			return p.errorf("malformed prefix name")
		}
		p.bump()
	}
	name := string(p.bytes[start:p.pos])
	if !utf8.ValidString(name) {
		return p.errorf("prefix name is not valid UTF-8")
	}
	p.bump()
	p.skipSpace()
	iri, err := p.parseIRI()
	if err != nil {
		return err
	}
	p.skipSpace()
	if value, ok := p.byte(); ok && value == '.' {
		p.bump()
	}
	for index := range p.prefixes {
		if p.prefixes[index].name == name {
			p.prefixes[index].iri = iri
			return nil
		}
	}
	if len(p.prefixes) >= p.limits.MaxPrefixes {
		return limitf("AFF4 Turtle has more than %d prefix declarations", p.limits.MaxPrefixes)
	}
	p.prefixes = append(p.prefixes, prefixDecl{name: name, iri: iri})
	return nil
}

func (p *turtleParser) parseStatement() error {
	subject, err := p.parseSubject()
	if err != nil {
		return err
	}
	if _, exists := p.subjects[subject]; !exists {
		if len(p.subjects) >= p.limits.MaxSubjects {
			return limitf("AFF4 Turtle has more than %d subjects", p.limits.MaxSubjects)
		}
		p.subjects[subject] = struct{}{}
	}
	for {
		p.skipSpace()
		value, ok := p.byte()
		if !ok {
			return p.errorf("statement has no terminating '.'")
		}
		if value == ';' {
			p.bump()
			continue
		}
		if value == '.' {
			p.bump()
			return nil
		}

		predicate, err := p.parsePredicate()
		if err != nil {
			return err
		}
		for {
			p.skipSpace()
			object, err := p.parseObject()
			if err != nil {
				return err
			}
			if err := p.pushTriple(subject, predicate, object); err != nil {
				return err
			}
			p.skipSpace()
			if next, ok := p.byte(); ok && next == ',' {
				p.bump()
				continue
			}
			break
		}
		p.skipSpace()
		next, ok := p.byte()
		if !ok {
			return p.errorf("expected ';' or '.' after an object")
		}
		switch next {
		case ';':
			p.bump()
		case '.':
			p.bump()
			return nil
		default:
			return p.errorf("expected ';' or '.' after an object")
		}
	}
}

func (p *turtleParser) run() error {
	for {
		p.skipSpace()
		if p.eof() {
			return nil
		}
		if p.atKeyword("@prefix", false) {
			p.pos += len("@prefix")
			if err := p.parsePrefixBody(); err != nil {
				return err
			}
			continue
		}
		if p.atKeyword("PREFIX", true) {
			p.pos += len("PREFIX")
			if err := p.parsePrefixBody(); err != nil {
				return err
			}
			continue
		}
		if p.atKeyword("@base", false) || p.atKeyword("BASE", true) {
			return p.unsupported("@base directive")
		}
		if err := p.parseStatement(); err != nil {
			return err
		}
	}
}

func isASCIISpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r' ||
		value == '\f' || value == '\v'
}

func isASCIIAlnum(value byte) bool {
	return (value >= '0' && value <= '9') ||
		(value >= 'A' && value <= 'Z') ||
		(value >= 'a' && value <= 'z')
}

func hexValue(value byte) (uint32, bool) {
	switch {
	case value >= '0' && value <= '9':
		return uint32(value - '0'), true
	case value >= 'a' && value <= 'f':
		return uint32(value-'a') + 10, true
	case value >= 'A' && value <= 'F':
		return uint32(value-'A') + 10, true
	default:
		return 0, false
	}
}

func objectText(object turtleObject) (string, bool) {
	if object.isIRI {
		return iriLocal(object.text)
	}
	return object.text, true
}

// setU64 records a numeric property, warning about conflicting or non-numeric
// values rather than guessing.
func setU64(slot **uint64, value, predicate, uri string, warnings *[]string, limit int) {
	parsed, ok := parseU64(value)
	if !ok {
		pushWarning(warnings, limit, "%s has a non-numeric %s value %q", uri, predicate, value)
		return
	}
	if *slot != nil {
		if **slot != parsed {
			pushWarning(warnings, limit,
				"%s declares conflicting %s values %d and %d", uri, predicate, **slot, parsed)
		}
		return
	}
	copy := parsed
	*slot = &copy
}

func interpretTriples(triples []aff4Triple, subjectCount int, limits Limits) turtleParse {
	builders := make(map[string]*streamBuilder)
	var storedLinks []StoredLink
	ignoredSet := make(map[string]struct{})
	ignoredCount := 0
	var version string
	var versionLine uint64
	var warnings []string

	addIgnored := func(name string) {
		ignoredCount++
		if len(ignoredSet) < limits.MaxIgnoredPredicates {
			ignoredSet[name] = struct{}{}
		}
	}

	for _, triple := range triples {
		builder, exists := builders[triple.subject]
		if !exists {
			builder = &streamBuilder{uri: triple.subject}
			builders[triple.subject] = builder
		}

		if triple.predicate == RDFType {
			if triple.object.isIRI {
				local, ok := iriLocal(triple.object.text)
				if ok && (local == "Image" || local == "ImageStream" || local == "Map" ||
					local == "Zero" || local == "ZipSegment" || local == "FileImage") {
					builder.class = local
				} else {
					ignoredCount++
				}
			} else {
				ignoredCount++
			}
			continue
		}

		local, isAFF4 := strings.CutPrefix(triple.predicate, Namespace)
		if !isAFF4 {
			addIgnored(triple.predicate)
			continue
		}

		switch local {
		case "version":
			if triple.object.isIRI {
				pushWarning(&warnings, limits.MaxWarnings, "%s has a non-literal version", triple.subject)
			} else if version == "" {
				version = triple.object.text
				versionLine = triple.line
			}
		case "size":
			if !triple.object.isIRI {
				setU64(&builder.size, triple.object.text, "aff4:size", triple.subject, &warnings, limits.MaxWarnings)
			}
		case "chunkSize", "chunk_size":
			if !triple.object.isIRI {
				setU64(&builder.chunkSize, triple.object.text, "aff4:chunkSize", triple.subject, &warnings, limits.MaxWarnings)
			}
		case "chunksPerSegment", "chunks_per_segment":
			if !triple.object.isIRI {
				setU64(&builder.chunksPerSegment, triple.object.text, "aff4:chunksPerSegment", triple.subject, &warnings, limits.MaxWarnings)
			}
		case "compressionMethod", "compression_method":
			if text, ok := objectText(triple.object); ok && builder.compression == "" {
				builder.compression = text
			}
		case "category":
			if text, ok := objectText(triple.object); ok {
				switch text {
				case "imageStream", "map", "zero", "fileImage":
					if builder.category == "" {
						builder.category = text
					}
				default:
					ignoredCount++
				}
			}
		case "stored":
			if triple.object.isIRI {
				if len(builder.stored) < limits.MaxStoredPerStream {
					builder.stored = append(builder.stored, triple.object.text)
				}
				if len(storedLinks) < limits.MaxTriples {
					storedLinks = append(storedLinks, StoredLink{Subject: triple.subject, Object: triple.object.text})
				}
			}
		case "target":
			if triple.object.isIRI && len(builder.targets) < limits.MaxStoredPerStream {
				builder.targets = append(builder.targets, triple.object.text)
			}
		case "dependentStream", "dependent_stream":
			if triple.object.isIRI && len(builder.dependentStreams) < limits.MaxStoredPerStream {
				builder.dependentStreams = append(builder.dependentStreams, triple.object.text)
			}
		case "dataStream", "data_stream":
			if triple.object.isIRI && builder.dataStream == "" {
				builder.dataStream = triple.object.text
			}
		case "SHA1", "BLAKE2b":
			if !triple.object.isIRI && len(builder.hashes) < limits.MaxHashesPerStream {
				builder.hashes = append(builder.hashes, Hash{
					Algorithm:    local,
					ValuePresent: triple.object.text != "",
					ValueLen:     len(triple.object.text),
				})
			}
		default:
			addIgnored(Namespace + local)
		}
	}

	streams := finalizeStreams(builders)
	images, maps, zeros, segments, fileImages := classifyStreams(streams)
	unknown := subjectCount - len(streams)
	if unknown < 0 {
		unknown = 0
	}
	ignored := sortedKeys(ignoredSet)

	return turtleParse{
		triples:               len(triples),
		subjects:              subjectCount,
		version:               version,
		versionLine:           versionLine,
		streams:               streams,
		storedLinks:           storedLinks,
		imageStreams:          images,
		mapStreams:            maps,
		zeroStreams:           zeros,
		segmentStreams:        segments,
		fileImageStreams:      fileImages,
		unknownSubjects:       unknown,
		ignoredPredicates:     ignored,
		ignoredPredicateCount: ignoredCount,
		warnings:              warnings,
	}
}

// finalizeStreams turns the builders into typed streams, sorted by URI.  A
// subject is only a stream when it carries a recognized class or category.
func finalizeStreams(builders map[string]*streamBuilder) []Stream {
	keys := sortedKeys(builders)
	streams := make([]Stream, 0, len(keys))
	for _, key := range keys {
		builder := builders[key]
		if builder.class == "" && builder.category == "" {
			continue
		}
		streams = append(streams, Stream{
			URI:              builder.uri,
			Class:            builder.class,
			Category:         builder.category,
			Size:             builder.size,
			ChunkSize:        builder.chunkSize,
			ChunksPerSegment: builder.chunksPerSegment,
			Compression:      builder.compression,
			Hashes:           append([]Hash(nil), builder.hashes...),
			Stored:           append([]string(nil), builder.stored...),
			Targets:          append([]string(nil), builder.targets...),
			DependentStreams: append([]string(nil), builder.dependentStreams...),
			DataStream:       builder.dataStream,
		})
	}
	sort.SliceStable(streams, func(i, j int) bool { return streams[i].URI < streams[j].URI })
	return streams
}

func classifyStreams(streams []Stream) (images, maps, zeros, segments, fileImages int) {
	for _, stream := range streams {
		if stream.IsImage() {
			images++
		}
		if stream.IsMap() {
			maps++
		}
		if stream.IsZero() {
			zeros++
		}
		if stream.IsSegment() {
			segments++
		}
		if stream.IsFileImage() {
			fileImages++
		}
	}
	return images, maps, zeros, segments, fileImages
}
