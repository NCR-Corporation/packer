package vsphere

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	var p PostProcessor

	p.config.Username = "me"
	p.config.Password = "notpassword"
	p.config.VCloudURI = "myvlabs.somedc.com:443"
	p.config.VirtualDataCenter = "mydc"
	p.config.Organization = "myorg"
	p.config.TemplateName = "myVM"
	p.config.Insecure = true
	p.config.Overwrite = true
	p.config.Compression = 9

	source := "something.vmx"
	ovftool_uri := fmt.Sprintf("vcloud://%s:%s@%s?org=%s&vAppTemplate=%s&catalog=%s&vdc=%s",
		url.QueryEscape(p.config.Username),
		url.QueryEscape(p.config.Password),
		p.config.VCloudURI,
		p.config.Organization,
		p.config.TemplateName,
		p.config.Catalog,
		p.config.VirtualDataCenter)

	args, err := p.BuildArgs(source, ovftool_uri)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	t.Logf("ovftool %s", strings.Join(args, " "))
}
