package gocavv

import (
	"os"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"github.com/beevik/etree"
)

const (
	TDS_MSG_VER_1 string = "1.0.2"
)


func VeReqMarshalMessage() {

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	root := doc.CreateElement("ThreeDSecure")
	msg := root.CreateElement("Message")
	msg.CreateAttr("id", "13")
	vq := msg.CreateElement("VEReq")
	vq.CreateElement("version").SetText(TDS_MSG_VER_1)
	vq.CreateElement("pan").SetText("4015500110472945")
	merch := vq.CreateElement("Merchant")
	merch.CreateElement("acqBIN").SetText("2201380114")
	merch.CreateElement("merID").SetText("07070707")
	brw := vq.CreateElement("Browser")
	brw.CreateElement("deviceCategory").SetText("0")
	brw.CreateElement("accept").SetText("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	brw.CreateElement("userAgent").SetText("Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0")

	doc.Indent(3)
	doc.WriteTo(os.Stdout)
	//doc.WriteToBytes()

/*
	type VeReq struct {
		XMLName   	xml.Name `xml:"ThreeDSecure"`
		//XMLName  xml.Name `xml:"ThreeDSecure>Message"`
		Id        	int      `xml:"id,attr"`
	}

	v := &VeReq{Id:13}

	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("  ", "    ")
	if err := enc.Encode(v); err != nil {
		fmt.Printf("error: %v\n", err)
	}
*/
}

func PaResUnMarshalMessage(paresB64 string) (error) {
	data, err := base64.StdEncoding.DecodeString(paresB64)
	if err != nil {
		return err
	}
	b := bytes.NewReader(data)
	r, err := zlib.NewReader(b)
	if err != nil {
		return err
	}
/*
	doc := etree.NewDocument()
	n, err := doc.ReadFrom(r)
	if err != nil {
		return err
	}
	doc.Indent(3)
	doc.WriteTo(os.Stdout)
*/
	//io.Copy(os.Stdout, r)
	// Output: hello, world
	r.Close()
	return nil
}

