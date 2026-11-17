package xar

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// element is the small XML tree the TOC needs: a name, attributes, direct
// text, and children.  It mirrors the Element type of forensic-core's
// foundation/xml.rs, but the tokenizing itself is delegated to encoding/xml.
type element struct {
	name       string
	attributes []xml.Attr
	text       strings.Builder
	children   []*element
}

// trimmedText returns the direct text with surrounding whitespace removed, as
// the reference reader does when it closes an element.
func (e *element) trimmedText() string { return strings.TrimSpace(e.text.String()) }

// attribute returns the value of name from the element's own attributes.
func (e *element) attribute(name string) (string, bool) {
	for _, attr := range e.attributes {
		if attr.Name.Local == name {
			return attr.Value, true
		}
	}
	return "", false
}

// child returns the first direct child named name.
func (e *element) child(name string) *element {
	for _, child := range e.children {
		if child.name == name {
			return child
		}
	}
	return nil
}

// childText returns the direct text of the first child named name, when it has
// any after trimming.
func (e *element) childText(name string) (string, bool) {
	child := e.child(name)
	if child == nil {
		return "", false
	}
	text := child.trimmedText()
	if text == "" {
		return "", false
	}
	return text, true
}

// parseXML parses a whole TOC document.
//
// The reference reader refuses a document type declaration, unknown entities,
// mismatched or unclosed elements, a second root, and trailing content; with
// encoding/xml those are syntax errors (and DTDs are refused explicitly
// below), so nothing is silently skipped.  Comments and processing
// instructions are skipped, and CDATA text is treated as direct text.
func parseXML(data []byte, maxElements int) (*element, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true

	var root *element
	var stack []*element
	elements := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch typed := token.(type) {
		case xml.StartElement:
			elements++
			if maxElements > 0 && elements > maxElements {
				return nil, fmt.Errorf("the document has more than %d elements", maxElements)
			}
			node := &element{name: typed.Name.Local, attributes: typed.Attr}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("a second root element")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("an end tag without a start tag")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(typed)
			} else if strings.TrimSpace(string(typed)) != "" {
				return nil, fmt.Errorf("content after the root element")
			}
		case xml.Comment, xml.ProcInst:
			// Skipped, as in the reference reader.
		case xml.Directive:
			return nil, fmt.Errorf("a document type declaration is not supported (this reader has no DTD)")
		}
	}
	if root == nil {
		return nil, fmt.Errorf("the document has no root element")
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("an element was not closed")
	}
	return root, nil
}
