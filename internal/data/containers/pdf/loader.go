// Object loading and the facts read out of the object graph.

package pdf

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

type loadedObject struct {
	value Value
	// stream is the offset of the stream body, when the object is a stream.
	stream    uint64
	hasStream bool
	// generation is the generation written in the object's own header. The
	// per-object encryption key mixes it in, so it cannot be dropped after
	// parsing.
	generation uint16
}

type objectStream struct {
	numbers []uint32
	values  []Value
}

type nameTreeEntry struct {
	Name  string
	Value Value
}

type loader struct {
	src     source.ByteSource
	xref    *Xref
	limits  Limits
	cache   map[uint32]*loadedObject
	streams map[uint32]*objectStream
	loading map[uint32]bool
	loaded  int

	decodedStreams      int
	decodedBytes        uint64
	hashedEmbeddedBytes uint64

	// encrypted is true while the document's strings and streams are opaque:
	// no password, a wrong one, or a handler this reader does not implement.
	encrypted bool
	// crypt is present only after the user password verified.
	crypt *cryptState

	notes []string
	seen  map[string]bool
}

func newLoader(src source.ByteSource, xref *Xref, limits Limits) *loader {
	return &loader{
		src:     src,
		xref:    xref,
		limits:  limits,
		cache:   make(map[uint32]*loadedObject),
		streams: make(map[uint32]*objectStream),
		loading: make(map[uint32]bool),
		seen:    make(map[string]bool),
	}
}

func (l *loader) note(format string, args ...any) {
	l.notes = append(l.notes, fmt.Sprintf(format, args...))
}

func (l *loader) noteOnce(format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	if l.seen[text] {
		return
	}
	l.seen[text] = true
	l.notes = append(l.notes, text)
}

// installDecryption checks the encryption dictionary and, when a password is
// offered, verifies it. Failures become notes; the document stays opaque.
func (l *loader) installDecryption(params *encryptParams, password []byte, provided bool) {
	unlocked, err := unlock(params, password, provided)
	if err != nil {
		l.encrypted = true
		l.note("%s", err.Error())
		return
	}
	if unlocked == nil {
		l.encrypted = true
		return
	}
	for _, note := range unlocked.notes {
		l.note("%s", note)
	}
	_, streamCipher := unlocked.state.streamCipher()
	_, stringCipher := unlocked.state.stringCipher()
	usesCipher := streamCipher || stringCipher
	_, streamRefused := unlocked.state.streamUnsupported()
	_, stringRefused := unlocked.state.stringUnsupported()
	l.crypt = unlocked.state
	l.encrypted = false
	if usesCipher {
		l.noteOnce("document encryption: the user password verified; strings and streams were decrypted")
	} else if !streamRefused && !stringRefused {
		l.noteOnce("document encryption: every crypt filter is /Identity; strings and streams were already plaintext")
	}
}

// stringsOpaque reports whether strings cannot be turned into text: no key, or
// a string crypt filter this reader does not implement.
func (l *loader) stringsOpaque() bool {
	if l.encrypted {
		return true
	}
	if l.crypt != nil {
		_, refused := l.crypt.stringUnsupported()
		return refused
	}
	return false
}

// streamsOpaque reports whether stream bodies cannot be read.
func (l *loader) streamsOpaque() bool {
	if l.encrypted {
		return true
	}
	if l.crypt != nil {
		_, refused := l.crypt.streamUnsupported()
		return refused
	}
	return false
}

// decryptionSummary counts what could not be decrypted, once, after the object
// graph has been read.
func (l *loader) decryptionSummary() {
	if l.crypt == nil {
		return
	}
	if l.crypt.failedStreams == 0 && l.crypt.failedStrings == 0 {
		return
	}
	var parts []string
	if l.crypt.failedStreams > 0 {
		parts = append(parts, fmt.Sprintf("%d encrypted stream(s) could not be decrypted", l.crypt.failedStreams))
	}
	if l.crypt.failedStrings > 0 {
		parts = append(parts, fmt.Sprintf("%d encrypted string(s) could not be decrypted", l.crypt.failedStrings))
	}
	l.noteOnce("%s; the ciphertext was not used as content", joinParts(parts))
}

func joinParts(parts []string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += ", "
		}
		out += part
	}
	return out
}

// object loads one object by number. ok is false for a free or absent object.
func (l *loader) object(number uint32) (Value, bool, error) {
	if loaded, ok := l.cache[number]; ok {
		return loaded.value.Clone(), true, nil
	}
	if l.loaded >= l.limits.MaxObjects {
		return Value{}, false, limitError("document has more than %d loaded objects", l.limits.MaxObjects)
	}
	entry, ok := l.xref.Entry(number)
	if !ok || entry.IsFree() {
		return Value{}, false, nil
	}
	var loaded *loadedObject
	switch entry.Kind {
	case EntryInFile:
		generation := entry.Generation
		read, err := l.readAt(number, &generation, entry.Offset)
		if err != nil {
			return Value{}, false, err
		}
		loaded = read
	case EntryInStream:
		if err := l.loadObjectStream(entry.Stream); err != nil {
			return Value{}, false, err
		}
		stream, ok := l.streams[entry.Stream]
		if !ok {
			return Value{}, false, corrupt(0, "object stream %d is missing", entry.Stream)
		}
		index := int(entry.Index)
		if index < 0 || index >= len(stream.numbers) || index >= len(stream.values) {
			return Value{}, false, corrupt(0, "object %d names slot %d of object stream %d, which holds %d objects",
				number, entry.Index, entry.Stream, len(stream.numbers))
		}
		stored := stream.numbers[index]
		if stored != number {
			l.note("object stream %d slot %d holds object %d, not %d", entry.Stream, entry.Index, stored, number)
		}
		loaded = &loadedObject{
			value: stream.values[index].Clone(),
			// Objects stored in an object stream always have generation 0, and
			// their strings are already plaintext.
			generation: 0,
		}
	default:
		return Value{}, false, corrupt(0, "object %d has an unrecognised cross-reference entry", number)
	}
	l.loaded++
	l.cache[number] = loaded
	return loaded.value.Clone(), true, nil
}

func (l *loader) readAt(number uint32, expectedGeneration *uint16, offset uint64) (*loadedObject, error) {
	available := l.src.Len()
	if offset > available {
		available = 0
	} else {
		available -= offset
	}
	want := available
	if want > uint64(l.limits.MaxObjectBytes) {
		want = uint64(l.limits.MaxObjectBytes)
	}
	if want == 0 {
		return nil, corrupt(offset, "object %d starts at byte %d, at the end of the file", number, offset)
	}
	window, err := readSource(l.src, offset, want)
	if err != nil {
		return nil, err
	}
	parser := NewParser(window).WithBase(offset)
	reference, err := parser.ParseIndirectHeader()
	if err != nil {
		return nil, err
	}
	if reference.Number != number {
		return nil, corrupt(offset, "cross-reference names object %d at byte %d, but the object there is %d-%d",
			number, offset, reference.Number, reference.Generation)
	}
	if expectedGeneration != nil && *expectedGeneration != reference.Generation {
		l.noteOnce("cross-reference names object %d generation %d, but its header says generation %d; the header's generation was used",
			number, *expectedGeneration, reference.Generation)
	}
	value, err := parser.ParseValue()
	if err != nil {
		return nil, err
	}
	// Strings in an indirect object are ciphertext; the per-object key mixes
	// in the object's own number and generation.
	if l.crypt != nil {
		l.crypt.decryptStrings(&value, number, reference.Generation)
	}
	loaded := &loadedObject{value: value, generation: reference.Generation}
	saved := parser.Position()
	parser.SkipSpace()
	if parser.TakeKeyword([]byte("stream")) {
		parser.SetPosition(saved)
		start, err := parser.ParseStreamStart()
		if err != nil {
			return nil, err
		}
		loaded.stream = offset + uint64(start)
		loaded.hasStream = true
	} else {
		parser.SetPosition(saved)
	}
	return loaded, nil
}

// loadObjectStream parses object stream number so its members can be served.
func (l *loader) loadObjectStream(number uint32) error {
	if _, ok := l.streams[number]; ok {
		return nil
	}
	if l.loading[number] {
		return corrupt(0, "object stream %d refers to itself", number)
	}
	l.loading[number] = true
	defer delete(l.loading, number)

	value, ok, err := l.object(number)
	if err != nil {
		return err
	}
	if !ok {
		return corrupt(0, "object stream %d is missing", number)
	}
	dict, ok := value.AsDict()
	if !ok {
		return corrupt(0, "object %d is not an object stream", number)
	}
	if typeValue, hasType := dict.Get([]byte("Type")); !hasType || !IsName(typeValue, []byte("ObjStm")) {
		return corrupt(0, "object %d is named as an object stream but its /Type is not /ObjStm", number)
	}
	count, hasCount := dict.GetInt([]byte("N"))
	if !hasCount {
		return corrupt(0, "object stream %d has no /N", number)
	}
	if count < 0 || count > int64(l.limits.MaxObjects) {
		return limitError("object stream %d declares %d objects", number, count)
	}
	first, hasFirst := dict.GetInt([]byte("First"))
	if !hasFirst {
		return corrupt(0, "object stream %d has no /First", number)
	}
	if first < 0 {
		return corrupt(0, "object stream %d has a negative /First", number)
	}
	bytesValue, _, err := l.decodedStreamNumber(number, dict)
	if err != nil {
		return err
	}
	if first > int64(len(bytesValue)) {
		return corrupt(0, "object stream %d starts its bodies at %d, past its %d decoded bytes", number, first, len(bytesValue))
	}
	bodyStart := int(first)
	headerParser := NewParser(bytesValue[:bodyStart])
	numbers := make([]uint32, 0, count)
	offsets := make([]uint32, 0, count)
	for i := int64(0); i < count; i++ {
		stored, err := headerParser.ReadUnsigned("object stream member number")
		if err != nil {
			return err
		}
		offset, err := headerParser.ReadUnsigned("object stream member offset")
		if err != nil {
			return err
		}
		if stored > 0xFFFFFFFF {
			return corrupt(0, "object stream %d names object %d, above 2^32-1", number, stored)
		}
		if offset > 0xFFFFFFFF {
			return corrupt(0, "object stream %d has a member offset above 2^32-1", number)
		}
		numbers = append(numbers, uint32(stored))
		offsets = append(offsets, uint32(offset))
	}
	values := make([]Value, 0, len(offsets))
	for _, offset := range offsets {
		at := bodyStart + int(offset)
		if at < bodyStart || at >= len(bytesValue) {
			return corrupt(0, "object stream %d member starts at %d, past its %d decoded bytes", number, at, len(bytesValue))
		}
		value, err := ParseFirstValue(bytesValue[at:])
		if err != nil {
			return err
		}
		values = append(values, value)
	}
	l.streams[number] = &objectStream{numbers: numbers, values: values}
	return nil
}

// deref follows one reference. wasReference reports whether value was a
// reference, even when the target is free or absent.
func (l *loader) deref(value Value) (Value, uint32, bool, error) {
	if reference, ok := value.AsReference(); ok {
		resolved, found, err := l.object(reference.Number)
		if err != nil {
			return Value{}, reference.Number, true, err
		}
		if !found {
			return NullValue(), reference.Number, true, nil
		}
		return resolved, reference.Number, true, nil
	}
	return value, 0, false, nil
}

func (l *loader) dictOf(value Value) (*Dict, error) {
	resolved, _, _, err := l.deref(value)
	if err != nil {
		return nil, err
	}
	dict, _ := resolved.AsDict()
	return dict, nil
}

func (l *loader) dictObject(number uint32) (*Dict, error) {
	value, ok, err := l.object(number)
	if err != nil || !ok {
		return nil, err
	}
	dict, _ := value.AsDict()
	return dict, nil
}

func (l *loader) dictEntry(dict *Dict, key []byte) (*Dict, error) {
	value, ok := dict.Get(key)
	if !ok {
		return nil, nil
	}
	return l.dictOf(value)
}

func (l *loader) textEntry(dict *Dict, key []byte) (*string, error) {
	value, ok := dict.Get(key)
	if !ok {
		return nil, nil
	}
	return l.textOf(value)
}

func (l *loader) textOf(value Value) (*string, error) {
	resolved, number, wasReference, err := l.deref(value)
	if err != nil {
		return nil, err
	}
	switch resolved.kind {
	case KindString:
		if l.stringsOpaque() {
			l.noteOnce("document strings are encrypted; text fields were not decoded")
			return nil, nil
		}
		text := l.boundedText(DecodePDFText(resolved.bytes))
		return &text, nil
	case KindDictionary:
		dict := resolved.dict
		if wasReference && dict != nil && dict.Contains([]byte("Length")) {
			bytesValue, _, err := l.decodedStreamNumber(number, dict)
			if err != nil {
				var encrypted encryptedError
				if errors.As(err, &encrypted) {
					l.noteOnce("%s", encrypted.Error())
					return nil, nil
				}
				return nil, err
			}
			text := l.boundedText(lossyUTF8(bytesValue))
			return &text, nil
		}
	}
	return nil, nil
}

func (l *loader) boundedText(text string) string {
	if len(text) > l.limits.MaxTextBytes {
		text = text[:charBoundary(text, l.limits.MaxTextBytes)]
		l.noteOnce("text field truncated to %d bytes", l.limits.MaxTextBytes)
	}
	return text
}

func (l *loader) intOf(value Value) (int64, bool, error) {
	resolved, _, _, err := l.deref(value)
	if err != nil {
		return 0, false, err
	}
	valueInt, ok := resolved.AsInt()
	return valueInt, ok, nil
}

func (l *loader) lengthOf(dict *Dict) (uint64, bool, error) {
	value, ok := dict.Get([]byte("Length"))
	if !ok {
		return 0, false, nil
	}
	length, ok, err := l.intOf(value)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, nil
	}
	if length < 0 {
		return 0, false, corrupt(0, "stream /Length is negative")
	}
	return uint64(length), true, nil
}

// rawStream returns the stored bytes of stream number: /Length when direct or
// resolvable, otherwise everything up to endstream inside the bounded window.
func (l *loader) rawStream(number uint32, dict *Dict) ([]byte, error) {
	loaded, ok := l.cache[number]
	if !ok || !loaded.hasStream {
		return nil, corrupt(0, "object %d is not a stream", number)
	}
	offset := loaded.stream
	available := l.src.Len()
	if offset > available {
		available = 0
	} else {
		available -= offset
	}
	length, hasLength, err := l.lengthOf(dict)
	if err != nil {
		return nil, err
	}
	if hasLength {
		if length > uint64(l.limits.MaxStreamBytes) {
			return nil, limitError("stream %d declares %d bytes, above the %d byte limit", number, length, l.limits.MaxStreamBytes)
		}
		if length > available {
			return nil, corrupt(offset, "stream %d declares %d bytes, past the end of the file", number, length)
		}
		return readSource(l.src, offset, length)
	}
	want := available
	if want > uint64(l.limits.MaxStreamBytes) {
		want = uint64(l.limits.MaxStreamBytes)
	}
	if want == 0 {
		return nil, corrupt(offset, "stream %d has no resolvable /Length and no endstream keyword in its %d byte window",
			number, want)
	}
	window, err := readSource(l.src, offset, want)
	if err != nil {
		return nil, err
	}
	end := bytes.Index(window, []byte("endstream"))
	if end < 0 {
		return nil, corrupt(offset, "stream %d has no resolvable /Length and no endstream keyword in its %d byte window",
			number, want)
	}
	for end > 0 && (window[end-1] == '\r' || window[end-1] == '\n') {
		end--
	}
	return append([]byte(nil), window[:end]...), nil
}

func (l *loader) decodedStreamNumber(number uint32, dict *Dict) ([]byte, []string, error) {
	if l.streamsOpaque() {
		return nil, nil, encryptedError{message: fmt.Sprintf("stream %d is encrypted and was not decoded", number)}
	}
	raw, err := l.rawStream(number, dict)
	if err != nil {
		return nil, nil, err
	}
	raw, err = l.decryptStreamBytes(number, dict, raw)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := DecodeStream(dict, raw, l.limits.MaxDecodedBytes)
	if err != nil {
		return nil, nil, err
	}
	l.decodedStreams++
	l.decodedBytes += uint64(len(decoded.Bytes))
	return decoded.Bytes, decoded.Filters, nil
}

// decryptStreamBytes undoes the stream crypt filter before the ordinary
// filters run. With EncryptMetadata false the metadata stream is plaintext,
// and a stream that names /Crypt explicitly is left for the filter layer to
// refuse by name rather than being decrypted twice.
func (l *loader) decryptStreamBytes(number uint32, dict *Dict, raw []byte) ([]byte, error) {
	if l.crypt == nil {
		return raw, nil
	}
	generation := uint16(0)
	if loaded, ok := l.cache[number]; ok {
		generation = loaded.generation
	}
	if !l.crypt.encryptMetadata {
		if typeValue, ok := dict.Get([]byte("Type")); ok && IsName(typeValue, []byte("Metadata")) {
			return raw, nil
		}
	}
	if declaresCryptFilter(dict) {
		return raw, nil
	}
	cipherKindValue, ok := l.crypt.streamCipher()
	if !ok {
		return raw, nil
	}
	plain, err := l.crypt.decryptStream(number, generation, cipherKindValue, raw)
	if err != nil {
		return nil, encryptedError{message: err.Error()}
	}
	return plain, nil
}

// declaresCryptFilter reports whether a stream names /Crypt in its /Filter
// chain.
func declaresCryptFilter(dict *Dict) bool {
	value, ok := dict.Get([]byte("Filter"))
	if !ok {
		return false
	}
	switch value.Kind() {
	case KindName:
		return IsName(value, []byte("Crypt"))
	case KindArray:
		values, _ := value.AsArray()
		for _, item := range values {
			if IsName(item, []byte("Crypt")) {
				return true
			}
		}
	}
	return false
}

// decodedStreamOf returns a stream value's decoded bytes. isStream is false
// when the value is not a stream at all.
func (l *loader) decodedStreamOf(value Value) ([]byte, []string, bool, error) {
	resolved, number, wasReference, err := l.deref(value)
	if err != nil {
		return nil, nil, false, err
	}
	dict, ok := resolved.AsDict()
	if !ok || !dict.Contains([]byte("Length")) {
		return nil, nil, false, nil
	}
	if !wasReference {
		return nil, nil, false, corrupt(0, "stream is not an indirect object")
	}
	bytesValue, filters, err := l.decodedStreamNumber(number, dict)
	if err != nil {
		return nil, nil, true, err
	}
	return bytesValue, filters, true, nil
}

func (l *loader) infoFacts(dict *Dict) (Info, error) {
	var info Info
	for _, item := range dict.Items() {
		key := string(item.Key)
		keyText := lossyUTF8(item.Key)
		text, err := l.textOf(item.Value)
		if err != nil {
			return Info{}, err
		}
		switch key {
		case "Title":
			info.Title = text
		case "Author":
			info.Author = text
		case "Subject":
			info.Subject = text
		case "Keywords":
			info.Keywords = text
		case "Creator":
			info.Creator = text
		case "Producer":
			info.Producer = text
		case "Trapped":
			if name, ok := item.Value.AsName(); ok {
				value := lossyUTF8(name)
				info.Trapped = &value
			} else {
				info.Trapped = text
			}
		case "CreationDate":
			if text != nil {
				info.CreationDate = ParsePDFDate(*text)
			}
		case "ModDate":
			if text != nil {
				info.ModifiedDate = ParsePDFDate(*text)
			}
		default:
			if text != nil && len(info.Other) < 64 {
				info.Other = append(info.Other, TextPair{Name: keyText, Value: *text})
			}
		}
	}
	return info, nil
}

func (l *loader) pageFacts(value Value) (PagesFacts, error) {
	var facts PagesFacts
	seen := make(map[uint32]bool)
	err := l.walkPages(value, 0, seen, &facts)
	return facts, err
}

func (l *loader) walkPages(value Value, depth uint32, seen map[uint32]bool, facts *PagesFacts) error {
	if depth > MaxTreeDepth {
		return limitError("page tree is deeper than %d", MaxTreeDepth)
	}
	facts.Nodes++
	if int(facts.Nodes) > l.limits.MaxTreeNodes {
		return limitError("page tree has more than %d nodes", l.limits.MaxTreeNodes)
	}
	if depth > facts.Depth {
		facts.Depth = depth
	}
	resolved, number, wasReference, err := l.deref(value)
	if err != nil {
		return err
	}
	if wasReference {
		if seen[number] {
			l.noteOnce("page tree references object %d twice; the second visit stopped", number)
			return nil
		}
		seen[number] = true
	}
	dict, ok := resolved.AsDict()
	if !ok {
		return nil
	}
	if depth == 0 {
		if count, ok := dict.GetInt([]byte("Count")); ok && count >= 0 {
			value := uint32(count)
			if count > int64(0xFFFFFFFF) {
				value = 0xFFFFFFFF
			}
			facts.Declared = &value
		}
	}
	if kidsValue, ok := dict.Get([]byte("Kids")); ok {
		kids, _, _, err := l.deref(kidsValue)
		if err != nil {
			return err
		}
		values, ok := kids.AsArray()
		if !ok {
			return nil
		}
		for _, kid := range values {
			if err := l.walkPages(kid, depth+1, seen, facts); err != nil {
				return err
			}
		}
	} else {
		facts.Counted++
		if wasReference {
			facts.Objects = append(facts.Objects, number)
		}
	}
	return nil
}

func (l *loader) openAction(value Value) (*Action, error) {
	resolved, _, _, err := l.deref(value)
	if err != nil {
		return nil, err
	}
	if _, ok := resolved.AsArray(); ok {
		return &Action{Kind: "Destination"}, nil
	}
	actions, err := l.actionList(resolved, nil)
	if err != nil {
		return nil, err
	}
	if len(actions) == 0 {
		return nil, nil
	}
	return &actions[0], nil
}

func (l *loader) additionalActions(dict *Dict) []Action {
	var actions []Action
	for _, item := range dict.Items() {
		event := lossyUTF8(item.Key)
		found, err := l.actionList(item.Value, &event)
		if err != nil {
			continue
		}
		for _, action := range found {
			if len(actions) >= MaxActions {
				l.noteOnce("more than %d actions were not read", MaxActions)
				return actions
			}
			actions = append(actions, action)
		}
	}
	return actions
}

func (l *loader) actionList(value Value, event *string) ([]Action, error) {
	resolved, _, _, err := l.deref(value)
	if err != nil {
		return nil, err
	}
	var out []Action
	switch resolved.kind {
	case KindArray:
		for _, item := range resolved.array {
			found, err := l.actionList(item, event)
			if err != nil {
				return nil, err
			}
			out = append(out, found...)
		}
	case KindDictionary:
		dict := resolved.dict
		kind := "Unknown"
		if name, ok := dict.GetName([]byte("S")); ok {
			kind = lossyUTF8(name)
		}
		script, err := l.textEntry(dict, []byte("JS"))
		if err != nil {
			return nil, err
		}
		uri, err := l.textEntry(dict, []byte("URI"))
		if err != nil {
			return nil, err
		}
		action := Action{Kind: kind, Script: script, URI: uri, Event: event}
		if fileValue, ok := dict.Get([]byte("F")); ok {
			if fileResolved, _, _, err := l.deref(fileValue); err == nil {
				switch fileResolved.kind {
				case KindString:
					if !l.stringsOpaque() {
						text := DecodePDFText(fileResolved.bytes)
						action.File = &text
					}
				case KindDictionary:
					spec := fileResolved.dict
					action.File, err = l.textEntry(spec, []byte("UF"))
					if err != nil {
						return nil, err
					}
					if action.File == nil {
						action.File, err = l.textEntry(spec, []byte("F"))
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}
		if targetValue, ok := dict.Get([]byte("D")); ok {
			switch targetValue.Kind() {
			case KindInteger:
				text := fmt.Sprintf("page %d", targetValue.integer)
				action.Target = &text
			case KindName:
				text := lossyUTF8(targetValue.name)
				action.Target = &text
			case KindReference:
				text := fmt.Sprintf("object %d", targetValue.ref.Number)
				action.Target = &text
			}
		}
		out = append(out, action)
	}
	return out, nil
}

func (l *loader) acroFormFacts(dict *Dict) (*AcroForm, error) {
	form := &AcroForm{}
	_, form.XFA = dict.Get([]byte("XFA"))
	if value, ok := dict.GetInt([]byte("SigFlags")); ok {
		form.SigFlags = &value
	}
	if value, ok := dict.GetBool([]byte("NeedAppearances")); ok {
		form.NeedsAppearances = &value
	}
	if fieldsValue, ok := dict.Get([]byte("Fields")); ok {
		seen := make(map[uint32]bool)
		nodes := 0
		fields, _, _, err := l.deref(fieldsValue)
		if err != nil {
			return nil, err
		}
		if values, ok := fields.AsArray(); ok {
			for _, field := range values {
				if err := l.countFormFields(field, 0, seen, &nodes, form); err != nil {
					return nil, err
				}
			}
		}
	}
	return form, nil
}

func (l *loader) countFormFields(value Value, depth uint32, seen map[uint32]bool, nodes *int, form *AcroForm) error {
	if depth > MaxTreeDepth || *nodes >= l.limits.MaxTreeNodes {
		return limitError("form tree expanded past its limit")
	}
	*nodes = *nodes + 1
	resolved, number, wasReference, err := l.deref(value)
	if err != nil {
		return err
	}
	if wasReference {
		if seen[number] {
			return nil
		}
		seen[number] = true
	}
	dict, ok := resolved.AsDict()
	if !ok {
		return nil
	}
	form.Fields++
	if typeValue, ok := dict.GetName([]byte("FT")); ok && string(typeValue) == "Sig" {
		form.SignatureFields++
	}
	if kidsValue, ok := dict.Get([]byte("Kids")); ok {
		kids, _, _, err := l.deref(kidsValue)
		if err != nil {
			return err
		}
		if values, ok := kids.AsArray(); ok {
			for _, kid := range values {
				if err := l.countFormFields(kid, depth+1, seen, nodes, form); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// nameTree collects key → value pairs from a name tree, bounded by limit.
func (l *loader) nameTree(value Value, limit int) ([]nameTreeEntry, error) {
	var out []nameTreeEntry
	seen := make(map[uint32]bool)
	nodes := 0
	err := l.walkNameTree(value, 0, seen, &nodes, limit, &out)
	return out, err
}

func (l *loader) walkNameTree(value Value, depth uint32, seen map[uint32]bool, nodes *int, limit int, out *[]nameTreeEntry) error {
	if depth > MaxTreeDepth {
		return limitError("name tree is deeper than %d", MaxTreeDepth)
	}
	*nodes = *nodes + 1
	if *nodes > l.limits.MaxTreeNodes {
		return limitError("name tree has more than %d nodes", l.limits.MaxTreeNodes)
	}
	resolved, number, wasReference, err := l.deref(value)
	if err != nil {
		return err
	}
	if wasReference {
		if seen[number] {
			l.noteOnce("name tree references object %d twice; the second visit stopped", number)
			return nil
		}
		seen[number] = true
	}
	dict, ok := resolved.AsDict()
	if !ok {
		return nil
	}
	if namesValue, ok := dict.Get([]byte("Names")); ok {
		names, _, _, err := l.deref(namesValue)
		if err != nil {
			return err
		}
		if values, ok := names.AsArray(); ok {
			for i := 0; i < len(values); i += 2 {
				if len(*out) >= limit {
					l.noteOnce("name tree stopped after %d entries", limit)
					return nil
				}
				if i+1 >= len(values) {
					l.note("name tree has a name without a value")
					continue
				}
				key, err := l.textOf(values[i])
				if err != nil {
					return err
				}
				name := "<" + nameOfValue(values[i]) + ">"
				if key != nil {
					name = *key
				}
				*out = append(*out, nameTreeEntry{Name: name, Value: values[i+1]})
			}
		}
	}
	if kidsValue, ok := dict.Get([]byte("Kids")); ok {
		kids, _, _, err := l.deref(kidsValue)
		if err != nil {
			return err
		}
		if values, ok := kids.AsArray(); ok {
			for _, kid := range values {
				if err := l.walkNameTree(kid, depth+1, seen, nodes, limit, out); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func nameOfValue(value Value) string {
	switch value.kind {
	case KindName:
		return lossyUTF8(value.name)
	case KindString:
		return DecodePDFText(value.bytes)
	default:
		return value.String()
	}
}

func (l *loader) embeddedFile(name string, value Value) (EmbeddedFile, error) {
	dict, err := l.dictOf(value)
	if err != nil {
		return EmbeddedFile{}, err
	}
	if dict == nil {
		return EmbeddedFile{}, corrupt(0, "file specification is not a dictionary")
	}
	file := EmbeddedFile{Name: name}
	file.Filename, err = l.textEntry(dict, []byte("UF"))
	if err != nil {
		return EmbeddedFile{}, err
	}
	if file.Filename == nil {
		file.Filename, err = l.textEntry(dict, []byte("F"))
		if err != nil {
			return EmbeddedFile{}, err
		}
	}
	file.Description, err = l.textEntry(dict, []byte("Desc"))
	if err != nil {
		return EmbeddedFile{}, err
	}
	if subtype, ok := dict.GetName([]byte("Subtype")); ok {
		value := lossyUTF8(subtype)
		file.Subtype = &value
	}
	if params, err := l.dictEntry(dict, []byte("Params")); err != nil {
		return EmbeddedFile{}, err
	} else if params != nil {
		if size, ok := params.GetInt([]byte("Size")); ok {
			file.Size = &size
		}
		if textValue, ok := params.Get([]byte("CreationDate")); ok {
			text, err := l.textOf(textValue)
			if err != nil {
				return EmbeddedFile{}, err
			}
			if text != nil {
				file.CreationDate = ParsePDFDate(*text)
			}
		}
		if textValue, ok := params.Get([]byte("ModDate")); ok {
			text, err := l.textOf(textValue)
			if err != nil {
				return EmbeddedFile{}, err
			}
			if text != nil {
				file.ModifiedDate = ParsePDFDate(*text)
			}
		}
		if value, ok := params.Get([]byte("CheckSum")); ok {
			if bytesValue, ok := value.AsString(); ok {
				checksum := hexLower(bytesValue)
				file.Checksum = &checksum
			}
		}
	}

	ef, err := l.dictEntry(dict, []byte("EF"))
	if err != nil {
		return EmbeddedFile{}, err
	}
	if ef == nil {
		note := "file specification has no /EF stream"
		file.Note = &note
		return file, nil
	}
	streamValue, ok := ef.Get([]byte("UF"))
	if !ok {
		streamValue, ok = ef.Get([]byte("F"))
	}
	if !ok {
		note := "file specification has no /EF stream"
		file.Note = &note
		return file, nil
	}
	resolved, number, wasReference, err := l.deref(streamValue)
	if err != nil {
		note := err.Error()
		file.Note = &note
		return file, nil
	}
	stream, isDict := resolved.AsDict()
	if !isDict || !stream.Contains([]byte("Length")) || !wasReference {
		note := "file specification stream is not a stream"
		file.Note = &note
		return file, nil
	}
	file.streamNumber = number
	file.hasStream = true
	bytesValue, filters, err := l.decodedStreamNumber(number, stream)
	if err != nil {
		note := err.Error()
		file.Note = &note
		return file, nil
	}
	file.Filters = filters
	if len(bytesValue) > l.limits.MaxEmbeddedBytes {
		note := fmt.Sprintf("%d decoded bytes exceed the %d byte hashing limit", len(bytesValue), l.limits.MaxEmbeddedBytes)
		file.Note = &note
	} else if l.hashedEmbeddedBytes+uint64(len(bytesValue)) > l.limits.MaxEmbeddedTotalBytes {
		note := fmt.Sprintf("document hashing budget of %d bytes was exhausted", l.limits.MaxEmbeddedTotalBytes)
		file.Note = &note
	} else {
		l.hashedEmbeddedBytes += uint64(len(bytesValue))
		digest := sha256Hex(bytesValue)
		file.SHA256 = &digest
		count := len(bytesValue)
		file.Bytes = &count
	}
	return file, nil
}

func hexLower(bytesValue []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(bytesValue)*2)
	for _, b := range bytesValue {
		out = append(out, digits[b>>4], digits[b&0x0F])
	}
	return string(out)
}
