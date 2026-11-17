package ooxml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// element is one XML element: its local name, attributes in source order,
// direct text (trimmed and concatenated across text and CDATA nodes), and
// children.
//
// The reference reader does not resolve namespaces; it matches element and
// attribute names after splitting off a prefix.  encoding/xml resolves a known
// prefix to its namespace URI and keeps the local part, so matching on Local
// here reproduces the reference's local-name behavior.
type element struct {
	local    string
	attrs    []xml.Attr
	text     string
	children []*element
}

// attribute returns the value of the first attribute with this local name.
func (e *element) attribute(name string) (string, bool) {
	for _, attr := range e.attrs {
		if attr.Name.Local == name {
			return attr.Value, true
		}
	}
	return "", false
}

// attributeLocal is the explicit local-name spelling used where the format
// stores a prefixed attribute such as r:id.
func (e *element) attributeLocal(name string) (string, bool) {
	return e.attribute(name)
}

func (e *element) childLocal(name string) *element {
	for _, child := range e.children {
		if child.local == name {
			return child
		}
	}
	return nil
}

func (e *element) childrenNamed(name string) []*element {
	out := make([]*element, 0)
	for _, child := range e.children {
		if child.local == name {
			out = append(out, child)
		}
	}
	return out
}

// parseXML reads a whole document and returns its root element.
//
// A document type declaration is refused: this reader has no DTD and does not
// resolve external entities.  Unknown entities, mismatched tags, a second root
// element, trailing non-whitespace, excessive nesting, element count and
// direct-text size are all refused by name rather than approximated.
func parseXML(data []byte, limits Limits) (*element, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true

	var root *element
	stack := make([]*element, 0, 16)
	elements := 0

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			elements++
			if elements > limits.MaxXMLElements {
				return nil, fmt.Errorf("the document has more than %d elements", limits.MaxXMLElements)
			}
			if len(stack) >= limits.MaxXMLDepth {
				return nil, fmt.Errorf("nesting is deeper than %d elements", limits.MaxXMLDepth)
			}
			if len(stack) == 0 && root != nil {
				return nil, errors.New("content after the root element")
			}
			seen := make(map[xml.Name]struct{}, len(value.Attr))
			attrs := make([]xml.Attr, 0, len(value.Attr))
			for _, attr := range value.Attr {
				if _, exists := seen[attr.Name]; exists {
					return nil, fmt.Errorf("attribute %q appears twice", attr.Name.Local)
				}
				seen[attr.Name] = struct{}{}
				attrs = append(attrs, attr)
			}
			element := &element{
				local: value.Name.Local,
				attrs: attrs,
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, element)
			} else {
				root = element
			}
			stack = append(stack, element)

		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("end tag without a start tag")
			}
			top := stack[len(stack)-1]
			top.text = strings.TrimSpace(top.text)
			stack = stack[:len(stack)-1]

		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimSpace(value)) != 0 {
					if root == nil {
						return nil, errors.New("content before the root element")
					}
					return nil, errors.New("content after the root element")
				}
				continue
			}
			top := stack[len(stack)-1]
			top.text += string(value)
			if len(top.text) > limits.MaxXMLTextBytes {
				return nil, fmt.Errorf(
					"element <%s> has more than %d bytes of text", top.local, limits.MaxXMLTextBytes)
			}

		case xml.Directive:
			trimmed := bytes.TrimSpace(value)
			if bytes.HasPrefix(trimmed, []byte("DOCTYPE")) {
				return nil, errors.New("a document type declaration is not supported (this reader has no DTD)")
			}
			return nil, errors.New("a declaration is not supported")

		case xml.Comment, xml.ProcInst:
			// Comments and processing instructions are skipped, as in the
			// reference reader.
		}
	}

	if len(stack) != 0 {
		return nil, errors.New("an element is not closed")
	}
	if root == nil {
		return nil, errors.New("the document has no root element")
	}
	return root, nil
}

// countLocal counts elements with this local name anywhere in the subtree.
func countLocal(root *element, name string) int {
	count := 0
	if root.local == name {
		count++
	}
	for _, child := range root.children {
		count += countLocal(child, name)
	}
	return count
}
