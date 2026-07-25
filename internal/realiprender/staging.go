package realiprender

import (
	"fmt"
	"io/fs"
	"lanpanel/internal/assets"
	"lanpanel/internal/realip"
	"lanpanel/internal/realipassets"
	"lanpanel/internal/render"
)

type StagedFile struct {
	SourcePath  string
	HostPath    string
	ContentMode assets.ContentMode
	Mode        fs.FileMode
	Content     []byte
}

func (renderer Renderer) Stage(catalog []realipassets.Asset, data TemplateData) ([]StagedFile, error) {
	staged := make([]StagedFile, 0, len(catalog))
	for _, asset := range catalog {
		if asset.HostPath == "" {
			return nil, fmt.Errorf("realip asset %q has no host path", asset.SourcePath)
		}
		content, err := renderer.Render(asset, data)
		if err != nil {
			return nil, err
		}
		staged = append(staged, StagedFile{
			SourcePath:  asset.SourcePath,
			HostPath:    asset.HostPath,
			ContentMode: asset.ContentMode,
			Mode:        asset.Mode,
			Content:     content,
		})
	}
	return staged, nil
}

func StageRuntime(profile realip.ProfileConfig, state realip.State, reference realip.Reference, appConfigPath string) ([]StagedFile, error) {
	data, err := NewTemplateData(profile, state, reference, appConfigPath)
	if err != nil {
		return nil, err
	}
	catalog, err := realipassets.RuntimeCatalog(profile, reference.AppName)
	if err != nil {
		return nil, err
	}
	return NewRenderer(realipassets.NewLoader()).Stage(catalog, data)
}

func ConvertStagedFiles(files []StagedFile) []render.StagedFile {
	converted := make([]render.StagedFile, 0, len(files))
	for _, file := range files {
		converted = append(converted, render.StagedFile{
			SourcePath:  file.SourcePath,
			HostPath:    file.HostPath,
			ContentMode: file.ContentMode,
			Mode:        file.Mode,
			Content:     file.Content,
		})
	}
	return converted
}
