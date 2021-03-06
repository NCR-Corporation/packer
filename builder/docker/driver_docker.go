package docker

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/go-version"
	"github.com/mitchellh/packer/packer"
	"github.com/mitchellh/packer/template/interpolate"
)

type DockerDriver struct {
	Ui  packer.Ui
	Ctx *interpolate.Context

	l sync.Mutex
}

func (d *DockerDriver) DeleteImage(id string) error {
	var stderr bytes.Buffer
	cmd := exec.Command("docker", "rmi", id)
	cmd.Stderr = &stderr

	log.Printf("Deleting image: %s", id)
	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		err = fmt.Errorf("Error deleting image: %s\nStderr: %s",
			err, stderr.String())
		return err
	}

	return nil
}

func (d *DockerDriver) Commit(id string, author string, changes []string, message string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	args := []string{"commit"}
	if author != "" {
		args = append(args, "--author", author)
	}
	for _, change := range changes {
		args = append(args, "--change", change)
	}
	if message != "" {
		args = append(args, "--message", message)
	}
	args = append(args, id)

	log.Printf("Committing container with args: %v", args)
	cmd := exec.Command("docker", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return "", err
	}

	if err := cmd.Wait(); err != nil {
		err = fmt.Errorf("Error committing container: %s\nStderr: %s",
			err, stderr.String())
		return "", err
	}

	return strings.TrimSpace(stdout.String()), nil
}

func (d *DockerDriver) Export(id string, dst io.Writer) error {
	var stderr bytes.Buffer
	cmd := exec.Command("docker", "export", id)
	cmd.Stdout = dst
	cmd.Stderr = &stderr

	log.Printf("Exporting container: %s", id)
	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		err = fmt.Errorf("Error exporting: %s\nStderr: %s",
			err, stderr.String())
		return err
	}

	return nil
}

func (d *DockerDriver) Import(path string, repo string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", "import", "-", repo)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}

	// There should be only one artifact of the Docker builder
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if err := cmd.Start(); err != nil {
		return "", err
	}

	go func() {
		defer stdin.Close()
		io.Copy(stdin, file)
	}()

	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("Error importing container: %s\n\nStderr: %s", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

func (d *DockerDriver) IPAddress(id string) (string, error) {
	var stderr, stdout bytes.Buffer
	cmd := exec.Command(
		"docker",
		"inspect",
		"--format",
		"{{ .NetworkSettings.IPAddress }}",
		id)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Error: %s\n\nStderr: %s", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

func (d *DockerDriver) Login(repo, email, user, pass string) error {
	d.l.Lock()

	args := []string{"login"}
	if email != "" {
		args = append(args, "-e", email)
	}
	if user != "" {
		args = append(args, "-u", user)
	}
	if pass != "" {
		args = append(args, "-p", pass)
	}
	if repo != "" {
		args = append(args, repo)
	}

	cmd := exec.Command("docker", args...)
	err := runAndStream(cmd, d.Ui)
	if err != nil {
		d.l.Unlock()
	}

	return err
}

func (d *DockerDriver) Logout(repo string) error {
	args := []string{"logout"}
	if repo != "" {
		args = append(args, repo)
	}

	cmd := exec.Command("docker", args...)
	err := runAndStream(cmd, d.Ui)
	d.l.Unlock()
	return err
}

func (d *DockerDriver) Pull(image string) error {
	cmd := exec.Command("docker", "pull", image)
	return runAndStream(cmd, d.Ui)
}

func (d *DockerDriver) Push(name string) error {
	cmd := exec.Command("docker", "push", name)
	return runAndStream(cmd, d.Ui)
}

func (d *DockerDriver) SaveImage(id string, dst io.Writer) error {
	var stderr bytes.Buffer
	cmd := exec.Command("docker", "save", id)
	cmd.Stdout = dst
	cmd.Stderr = &stderr

	log.Printf("Exporting image: %s", id)
	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		err = fmt.Errorf("Error exporting: %s\nStderr: %s",
			err, stderr.String())
		return err
	}

	return nil
}

func (d *DockerDriver) StartContainer(config *ContainerConfig) (string, error) {
	// Build up the template data
	var tplData startContainerTemplate
	tplData.Image = config.Image
	ctx := *d.Ctx
	ctx.Data = &tplData

	// Args that we're going to pass to Docker
	args := []string{"run"}
	if config.Privileged {
		args = append(args, "--privileged")
	}
	for host, guest := range config.Volumes {
		args = append(args, "-v", fmt.Sprintf("%s:%s", host, guest))
	}
	for _, v := range config.RunCommand {
		v, err := interpolate.Render(v, &ctx)
		if err != nil {
			return "", err
		}

		args = append(args, v)
	}
	d.Ui.Message(fmt.Sprintf(
		"Run command: docker %s", strings.Join(args, " ")))

	// Start the container
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("Starting container with args: %v", args)
	if err := cmd.Start(); err != nil {
		return "", err
	}

	log.Println("Waiting for container to finish starting")
	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("Docker exited with a non-zero exit status.\nStderr: %s",
				stderr.String())
		}

		return "", err
	}

	// Capture the container ID, which is alone on stdout
	return strings.TrimSpace(stdout.String()), nil
}

func (d *DockerDriver) StopContainer(id string) error {
	if err := exec.Command("docker", "kill", id).Run(); err != nil {
		return err
	}

	return exec.Command("docker", "rm", id).Run()
}

func (d *DockerDriver) TagImage(id string, repo string, force bool) error {
	args := []string{"tag"}

	// detect running docker version before tagging
	// flag `force` for docker tagging was removed after Docker 1.12.0
	// to keep its backward compatibility, we are not going to remove `force`
	// option, but to ignore it when Docker version >= 1.12.0
	//
	// for more detail, please refer to the following links:
	// - https://docs.docker.com/engine/deprecated/#/f-flag-on-docker-tag
	// - https://github.com/docker/docker/pull/23090
	version_running, err := d.Version()
	if err != nil {
		return err
	}

	version_deprecated, err := version.NewVersion(string("1.12.0"))
	if err != nil {
		// should never reach this line
		return err
	}

	if force {
		if version_running.LessThan(version_deprecated) {
			args = append(args, "-f")
		} else {
			// do nothing if Docker version >= 1.12.0
			log.Printf("[WARN] option: \"force\" will be ignored here")
			log.Printf("since it was removed after Docker 1.12.0 released")
		}
	}
	args = append(args, id, repo)

	var stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		err = fmt.Errorf("Error tagging image: %s\nStderr: %s",
			err, stderr.String())
		return err
	}

	return nil
}

func (d *DockerDriver) Verify() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return err
	}

	return nil
}

func (d *DockerDriver) Version() (*version.Version, error) {
	output, err := exec.Command("docker", "-v").Output()
	if err != nil {
		return nil, err
	}

	match := regexp.MustCompile(version.VersionRegexpRaw).FindSubmatch(output)
	if match == nil {
		return nil, fmt.Errorf("unknown version: %s", output)
	}

	return version.NewVersion(string(match[0]))
}
