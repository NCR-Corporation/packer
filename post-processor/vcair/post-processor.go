package vsphere

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/mitchellh/packer/common"
	"github.com/mitchellh/packer/helper/config"
	"github.com/mitchellh/packer/packer"
	"github.com/mitchellh/packer/template/interpolate"
)

var builtins = map[string]string{
	"mitchellh.vmware":     "vmware",
	"mitchellh.vmware-esx": "vmware",
}

type Config struct {
	common.PackerConfig `mapstructure:",squash"`

	Organization      string   `mapstructure:"organization"`
	VirtualDataCenter string   `mapstructure:"virtual_data_center"`
	Catalog           string   `mapstructure:"catalog"`
	VCloudURI         string   `mapstructure:"vcloud_uri"`
	TemplateName      string   `mapstructure:"template_name"`
	Compression       int      `mapstructure:"compression"`
	Insecure          bool     `mapstructure:"insecure"`
	Options           []string `mapstructure:"options"`
	Overwrite         bool     `mapstructure:"overwrite"`
	Password          string   `mapstructure:"password"`
	Username          string   `mapstructure:"username"`

	ctx interpolate.Context
}

type PostProcessor struct {
	config Config
}

func (p *PostProcessor) Configure(raws ...interface{}) error {
	err := config.Decode(&p.config, &config.DecodeOpts{
		Interpolate:        true,
		InterpolateContext: &p.config.ctx,
		InterpolateFilter: &interpolate.RenderFilter{
			Exclude: []string{},
		},
	}, raws...)
	if err != nil {
		return err
	}

	// If it's out of the range, use the default
	if p.config.Compression > 9 || p.config.Compression < 1 {
		p.config.Compression = 9
	}

	// Accumulate any errors
	errs := new(packer.MultiError)

	if _, err := exec.LookPath("ovftool"); err != nil {
		errs = packer.MultiErrorAppend(
			errs, fmt.Errorf("ovftool not found: %s", err))
	}

	// First define all our templatable parameters that are _required_
	templates := map[string]*string{
		"organization":        &p.config.Organization,
		"catalog":             &p.config.Catalog,
		"virtual_data_center": &p.config.VirtualDataCenter,
		"vcloud_uri":          &p.config.VCloudURI,
		"password":            &p.config.Password,
		"username":            &p.config.Username,
		"template_name":       &p.config.TemplateName,
	}
	for key, ptr := range templates {
		if *ptr == "" {
			errs = packer.MultiErrorAppend(
				errs, fmt.Errorf("%s must be set", key))
		}
	}

	if len(errs.Errors) > 0 {
		return errs
	}

	return nil
}

func (p *PostProcessor) PostProcess(ui packer.Ui, artifact packer.Artifact) (packer.Artifact, bool, error) {
	if _, ok := builtins[artifact.BuilderId()]; !ok {
		return nil, false, fmt.Errorf("Unknown artifact type, can't build box: %s", artifact.BuilderId())
	}

	source := ""
	for _, path := range artifact.Files() {
		if strings.HasSuffix(path, ".vmx") || strings.HasSuffix(path, ".ovf") || strings.HasSuffix(path, ".ova") {
			source = path
			break
		}
	}

	if source == "" {
		return nil, false, fmt.Errorf("VMX, OVF or OVA file not found")
	}

	password := url.QueryEscape(p.config.Password)
	ovftoolURI := fmt.Sprintf("vcloud://%s:%s@%s?org=%s&vAppTemplate=%s&catalog=%s&vdc=%s",
		url.QueryEscape(p.config.Username),
		password,
		p.config.VCloudURI,
		p.config.Organization,
		p.config.TemplateName,
		p.config.Catalog,
		p.config.VirtualDataCenter)

	args, err := p.BuildArgs(source, ovftoolURI)
	if err != nil {
		ui.Message(fmt.Sprintf("Failed: %s\n", err))
	}

	ui.Message(fmt.Sprintf("Uploading %s to vCloud", source))

	log.Printf("Starting ovftool with parameters: %s",
		strings.Replace(
			strings.Join(args, " "),
			password,
			"<password>",
			-1))
	cmd := exec.Command("ovftool", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, false, fmt.Errorf("Failed: %s", err)
	}

	return artifact, false, nil
}

// BuildArgs Build the arguments for the post processor
func (p *PostProcessor) BuildArgs(source, ovftoolURI string) ([]string, error) {
	args := []string{
		"--acceptAllEulas",
		"--vCloudTemplate",
		fmt.Sprintf(`--compress=%d`, p.config.Compression),
	}

	if p.config.Overwrite == true {
		args = append(args, "--overwrite")
	}

	if p.config.Insecure {
		args = append(args, fmt.Sprintf(`--noSSLVerify=%t`, p.config.Insecure))
	}

	if len(p.config.Options) > 0 {
		args = append(args, p.config.Options...)
	}

	args = append(args, fmt.Sprintf(`%s`, source))
	args = append(args, fmt.Sprintf(`%s`, ovftoolURI))

	return args, nil
}
