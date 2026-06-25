package drawio

import "encoding/xml"

// mxFile is the root of a draw.io / diagrams.net file.
type mxFile struct {
	XMLName  xml.Name    `xml:"mxfile"`
	Diagrams []mxDiagram `xml:"diagram"`
}

// mxDiagram either embeds an <mxGraphModel> (uncompressed XML) or carries a
// compressed (deflate+base64) payload as its character data.
type mxDiagram struct {
	Name    string        `xml:"name,attr"`
	Content string        `xml:",chardata"`
	Model   *mxGraphModel `xml:"mxGraphModel"`
}

type mxGraphModel struct {
	Root mxRoot `xml:"root"`
}

// mxRoot holds the cells. draw.io may also wrap a cell in an <object> element
// (when it carries custom attributes); those contain a nested <mxCell>.
type mxRoot struct {
	Cells   []mxCell   `xml:"mxCell"`
	Objects []mxObject `xml:"object"`
}

type mxObject struct {
	ID    string `xml:"id,attr"`
	Label string `xml:"label,attr"`
	Cell  mxCell `xml:"mxCell"`
}

type mxCell struct {
	ID       string      `xml:"id,attr"`
	Value    string      `xml:"value,attr"`
	Style    string      `xml:"style,attr"`
	Vertex   string      `xml:"vertex,attr"`
	Edge     string      `xml:"edge,attr"`
	Source   string      `xml:"source,attr"`
	Target   string      `xml:"target,attr"`
	Parent   string      `xml:"parent,attr"`
	Geometry *mxGeometry `xml:"mxGeometry"`
}

type mxGeometry struct {
	X      float64 `xml:"x,attr"`
	Y      float64 `xml:"y,attr"`
	Width  float64 `xml:"width,attr"`
	Height float64 `xml:"height,attr"`
}
