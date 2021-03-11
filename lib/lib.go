package pdns2ublib

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kxn/pdnsmodel"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

const (
	// TypeRedirect redirect
	TypeRedirect = "redirect"
	// TypeTransparent do
	TypeTransparent = "TypeTransparent"
	// TypeStatic do
	TypeStatic = "static"
	// TypeNone do
	TypeNone = ""
)

// DNSRecord do
type DNSRecord struct {
	Type string // A AAAA NS etc
	TTL  int
	Data string
}

func reverseSlice(in []string) []string {
	inlen := len(in)
	out := make([]string, inlen)
	for i := 0; i < inlen; i++ {
		out[i] = in[inlen-i-1]
	}
	return out
}

func (r *DNSRecord) toString() string {
	return fmt.Sprintf("%d IN %s %s", r.TTL, r.Type, r.Data)
}

func newRecordFromModel(s pdnsmodel.Record) *DNSRecord {
	r := DNSRecord{
		Type: s.Type.String,
		TTL:  int(s.TTL.Int32),
	}
	switch s.Type.String {
	case "A", "AAAA", "PTR":
		r.Data = s.Content.String
	case "SOA":
		// Do not know why, but some poweradmin instances do not write domain and admin mail to SOA contents, need to handle this properly
		if len(strings.Split(s.Content.String, " ")) == 5 {
			r.Data = fmt.Sprintf("%s admin.%s %s", NormalizeFQDN(s.Domain.Name), NormalizeFQDN(s.Domain.Name), s.Content.String)
		} else {
			r.Data = s.Content.String
		}
	case "MX", "SRV":
		r.Data = fmt.Sprintf("%d %s", s.Prio.Int32, s.Content.String)
	default:
		return nil
	}
	return &r
}

// DNSRecords do
type DNSRecords map[string][]DNSRecord

func (rs DNSRecords) addRecord(r DNSRecord) {
	_, ok := rs[r.Type]
	if !ok {
		rs[r.Type] = []DNSRecord{}
	}
	// dedup
	for _, v := range rs[r.Type] {
		if v.Data == r.Data && v.TTL == r.TTL {
			return
		}
	}
	rs[r.Type] = append(rs[r.Type], r)
}

func (rs DNSRecords) hasType(t string) bool {
	_, ok := rs[t]
	return ok
}

func (rs DNSRecords) keys() []string {
	ret := []string{}
	for k := range rs {
		ret = append(ret, k)
	}
	sort.Strings(ret)
	return ret
}

type dnsNodeChildren map[string]*DNSNode

func (ns dnsNodeChildren) keys() []string {
	ret := []string{}
	for k := range ns {
		ret = append(ret, k)
	}
	sort.Strings(ret)
	return ret
}

// DNSNode Basic information for holding DNS data
type DNSNode struct {
	Name       string
	Children   dnsNodeChildren
	Data       DNSRecords
	Parent     *DNSNode
	DomainType string
}

func newDNSNode(name string, parent *DNSNode) *DNSNode {
	return &DNSNode{
		Name:       name,
		Children:   dnsNodeChildren{},
		Data:       DNSRecords{},
		Parent:     parent,
		DomainType: TypeNone,
	}
}

func (n *DNSNode) outputConfig(f io.Writer) {
	if n.DomainType != TypeNone {
		fmt.Fprintf(f, "\nlocal-zone: \"%s\" %s\n", n.FullPath(), n.DomainType)
		n.outputData(f)
	}
	if n.DomainType != TypeNone {
		for _, k := range n.Children.keys() {
			n.Children[k].outputSubrecords(f)
		}
	}
	for _, k := range n.Children.keys() {
		n.Children[k].outputConfig(f)
	}
}

func (n *DNSNode) outputData(f io.Writer) {
	for _, t := range n.Data.keys() {
		for _, tt := range n.Data[t] {
			fmt.Fprintf(f, "  local-data: \"%s %s\"\n", n.FullPath(), tt.toString())
		}
	}
}

func (n *DNSNode) outputSubrecords(f io.Writer) {
	if n.DomainType != TypeNone {
		return
	}
	n.outputData(f)
	for _, k := range n.Children.keys() {
		n.Children[k].outputSubrecords(f)
	}
}

func (n *DNSNode) addChild(tokens []string, data DNSRecord) {
	c := ""
	if len(tokens) > 0 {
		c = tokens[0]
		if c == "*" {
			c = ""
			tokens = []string{}
			n.DomainType = TypeRedirect
		}
	}
	if c == "" {
		n.Data.addRecord(data)
		return
	}
	_, ok := n.Children[c]
	if !ok {
		n.Children[c] = newDNSNode(c, n)
	}
	n.Children[c].addChild(tokens[1:], data)
}

func (n *DNSNode) findNode(tokens []string, create bool) *DNSNode {
	if len(tokens) == 0 {
		return n
	}
	c := tokens[0]

	_, ok := n.Children[c]
	if !ok {
		if !create {
			return nil
		}
		n.Children[c] = newDNSNode(c, n)
	}
	return n.Children[c].findNode(tokens[1:], create)
}

// FullPath get full path of the node
func (n *DNSNode) FullPath() string {
	tokens := []string{}
	for i := n; i.Parent != nil; i = i.Parent {
		tokens = append(tokens, i.Name)
	}
	return NormalizeFQDN(strings.Join(tokens, "."))
}

// DNSData root data
type DNSData struct {
	Root *DNSNode
}

func newDNSData() *DNSData {
	return &DNSData{
		Root: newDNSNode(".", nil),
	}
}

// AddRecord add the record
func (d *DNSData) AddRecord(name string, data DNSRecord) {
	d.Root.addChild(reverseSlice(strings.Split(strings.Trim(name, "."), ".")), data)
}

// FindNode do
func (d *DNSData) FindNode(name string, create bool) *DNSNode {
	return d.Root.findNode(reverseSlice(strings.Split(strings.Trim(name, "."), ".")), create)
}

// FindDomainNode do
func (d *DNSData) FindDomainNode(name string) *DNSNode {
	nameTokens := reverseSlice(strings.Split(strings.Trim(name, "."), "."))
	for i := 0; i < len(nameTokens); i++ {
		n := d.Root.findNode(nameTokens[i:], false)
		if n != nil {
			return n
		}
	}
	return nil
}

func (d *DNSData) addModel(r pdnsmodel.Record) {
	domainType := ""
	switch r.Domain.Type {
	case "MASTER":
		domainType = TypeStatic
	case "NATIVE":
		domainType = TypeTransparent
	default:
		// do nothing, this is not a domain that we can handle
		return
	}
	if rc := newRecordFromModel(r); rc != nil {
		d.AddRecord(r.Name.String, *rc)
	}
	dm := d.FindNode(r.Domain.Name, true)
	if dm.DomainType == TypeNone {
		dm.DomainType = domainType
	}
}

func (d *DNSData) addTypeTransparentDomain(n *DNSNode, lastType string) {
	if n.DomainType == TypeNone && lastType == TypeRedirect {
		n.DomainType = TypeTransparent
	}
	currentType := n.DomainType
	if currentType == TypeNone {
		currentType = lastType
	}
	for _, k := range n.Children.keys() {
		d.addTypeTransparentDomain(n.Children[k], currentType)
	}
}

// LoadDataFromMySQL db
func LoadDataFromMySQL(dsn string) (*DNSData, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	var records []pdnsmodel.Record
	db.Preload("Domain").Find(&records)
	d := newDNSData()
	for _, i := range records {
		d.addModel(i)
	}
	// find all domains that need to be treated as transparent domain
	d.addTypeTransparentDomain(d.Root, TypeNone)
	return d, nil
}

// OutputConfig output unbound style config
func (d *DNSData) OutputConfig(f io.Writer) {
	d.Root.outputConfig(f)
}

// NormalizeFQDN do
func NormalizeFQDN(name string) string {
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	return strings.ToLower(name)
}
