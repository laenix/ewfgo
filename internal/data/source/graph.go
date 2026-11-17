package source

import (
	"errors"
	"fmt"
	"sort"
)

// Graph errors. Callers test them with errors.Is.
var (
	// ErrDuplicateSource means a node ID was added twice.
	ErrDuplicateSource = errors.New("graph: duplicate source")
	// ErrMissingParent means a parent edge names a node that is not in the graph.
	ErrMissingParent = errors.New("graph: missing parent")
	// ErrSourceCycle means the parent edges form a cycle.
	ErrSourceCycle = errors.New("graph: source cycle")
	// ErrMissingSource means no byte source is registered for the node.
	ErrMissingSource = errors.New("graph: missing byte source")
	// ErrInvalidNode means a node or parent edge is internally inconsistent.
	ErrInvalidNode = errors.New("graph: invalid node")
)

// SourceKind is what a source node represents.
type SourceKind uint8

const (
	// SourceImage is an image container (raw, E01, VHDX, ...).
	SourceImage SourceKind = iota
	// SourcePartition is a partition table entry.
	SourcePartition
	// SourceVolume is a volume assembled above partitions (LVM, RAID, LDM).
	SourceVolume
	// SourceFileSystem is a formatted volume.
	SourceFileSystem
	// SourceFile is a file or file data stream.
	SourceFile
	// SourceArchive is an archive container.
	SourceArchive
	// SourceArchiveEntry is one member opened from an archive.
	SourceArchiveEntry
	// SourceVirtualDisk is a virtual disk wrapping guest-visible bytes.
	SourceVirtualDisk
	// SourceDecodedStream is a codec or encryption layer's output.
	SourceDecodedStream
	// SourceCarvedRegion is a signature-carved region.
	SourceCarvedRegion
	// SourceMemorySegment is a memory-dump segment.
	SourceMemorySegment
)

// ParentRef is a parent edge. OffsetInParent is in the parent's byte space.
type ParentRef struct {
	Parent         ID
	OffsetInParent uint64
	Len            uint64
}

// FsInfo is the filesystem metadata attached to a source node.
type FsInfo struct {
	Kind          string
	Label         string
	UUID          string
	ClusterSize   uint32
	SectorSize    uint32
	CaseSensitive bool
}

// Provenance answers where a source came from at the node level.
type Provenance struct {
	EvidenceID     *ID
	SourceID       ID
	Offset         uint64
	Len            uint64
	ParserID       string
	ParserVersion  string
	RuleID         string
	RuleVersion    string
	TransformChain []string
	Deleted        bool
}

// NewProvenance creates node-level provenance for a source range.
func NewProvenance(sourceID ID, offset, length uint64) Provenance {
	return Provenance{SourceID: sourceID, Offset: offset, Len: length}
}

// SourceNode describes one node of the provenance DAG. An empty Parents slice
// means a root; multiple parents model RAID/LVM/spanning volumes.
type SourceNode struct {
	ID         ID
	Parents    []ParentRef
	Kind       SourceKind
	Len        uint64
	Label      string
	FS         *FsInfo
	Provenance Provenance
}

// NewSourceNode creates a node without filesystem metadata.
func NewSourceNode(id ID, kind SourceKind, length uint64, parents []ParentRef, label string) *SourceNode {
	return &SourceNode{
		ID:         id,
		Parents:    parents,
		Kind:       kind,
		Len:        length,
		Label:      label,
		Provenance: NewProvenance(id, 0, length),
	}
}

// SourceGraph is the provenance DAG for one evidence item. Nodes describe
// topology and metadata; bytes live in the sources registry, so a graph can be
// serialized for a case database while sources are opened lazily.
type SourceGraph struct {
	nodes   map[ID]*SourceNode
	sources map[ID]ByteSource
}

// NewSourceGraph returns an empty graph.
func NewSourceGraph() *SourceGraph {
	return &SourceGraph{
		nodes:   make(map[ID]*SourceNode),
		sources: make(map[ID]ByteSource),
	}
}

// AddNode adds a node and, optionally, its byte source. Parent existence and
// cycles are checked by Validate, so a graph can be assembled in any order.
func (g *SourceGraph) AddNode(node *SourceNode, src ByteSource) error {
	if node == nil {
		return fmt.Errorf("%w: nil node", ErrInvalidNode)
	}
	if _, ok := g.nodes[node.ID]; ok {
		return fmt.Errorf("%w: %d", ErrDuplicateSource, node.ID)
	}
	if src != nil {
		if src.SourceID() != node.ID {
			return fmt.Errorf("%w: source id %d does not match node id %d",
				ErrInvalidNode, src.SourceID(), node.ID)
		}
		if src.Len() != node.Len {
			return fmt.Errorf("%w: source %d length %d does not match node length %d",
				ErrInvalidNode, node.ID, src.Len(), node.Len)
		}
	}

	g.nodes[node.ID] = node
	if src != nil {
		g.sources[node.ID] = src
	}
	return nil
}

// Node returns a node by ID.
func (g *SourceGraph) Node(id ID) (*SourceNode, bool) {
	node, ok := g.nodes[id]
	return node, ok
}

// Source returns the byte source registered for a node.
func (g *SourceGraph) Source(id ID) (ByteSource, bool) {
	src, ok := g.sources[id]
	return src, ok
}

// Roots returns the IDs of nodes with no parents, in ascending order.
func (g *SourceGraph) Roots() []ID {
	roots := make([]ID, 0, len(g.nodes))
	for id, node := range g.nodes {
		if len(node.Parents) == 0 {
			roots = append(roots, id)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })
	return roots
}

// MapToImage maps a logical range of a registered source to image offsets.
func (g *SourceGraph) MapToImage(id ID, offset, length uint64) ([]ImageRange, error) {
	src, ok := g.sources[id]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrMissingSource, id)
	}
	return src.MapToImage(offset, length)
}

// Validate verifies parent references, parent bounds, and acyclicity.
func (g *SourceGraph) Validate() error {
	for _, node := range g.nodes {
		for _, ref := range node.Parents {
			parent, ok := g.nodes[ref.Parent]
			if !ok {
				return fmt.Errorf("%w: source %d references missing parent %d",
					ErrMissingParent, node.ID, ref.Parent)
			}
			if ref.OffsetInParent > parent.Len || ref.Len > parent.Len-ref.OffsetInParent {
				return fmt.Errorf("%w: source %d parent range [%d, +%d) exceeds parent %d length %d",
					ErrInvalidNode, node.ID, ref.OffsetInParent, ref.Len, parent.ID, parent.Len)
			}
		}
	}

	return g.validateAcyclic()
}

// validateAcyclic runs an iterative three-colour DFS so a crafted deep graph
// cannot overflow the stack.
func (g *SourceGraph) validateAcyclic() error {
	const (
		white = iota
		gray
		black
	)
	state := make(map[ID]int, len(g.nodes))
	type frame struct {
		id   ID
		next int
	}

	for start := range g.nodes {
		if state[start] != white {
			continue
		}
		state[start] = gray
		stack := []frame{{id: start}}

		for len(stack) > 0 {
			f := &stack[len(stack)-1]
			node := g.nodes[f.id]
			if f.next < len(node.Parents) {
				parentID := node.Parents[f.next].Parent
				f.next++
				switch state[parentID] {
				case gray:
					return fmt.Errorf("%w: at source %d", ErrSourceCycle, parentID)
				case white:
					state[parentID] = gray
					stack = append(stack, frame{id: parentID})
				}
				continue
			}
			state[f.id] = black
			stack = stack[:len(stack)-1]
		}
	}
	return nil
}
