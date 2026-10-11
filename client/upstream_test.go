package client_test

import (
	"context"
	"slices"
	"testing"

	"github.com/Mic92/niks3/client"
)

const (
	upstreamGlibc = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc"
	upstreamTool  = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-tool"
	upstreamApp   = "/nix/store/cccccccccccccccccccccccccccccccc-app"
)

// glibc comes from cache.nixos.org, tool from some other cache, app is ours.
func upstreamPathInfos(t *testing.T) map[string]*client.PathInfo {
	t.Helper()

	infos, err := client.ParsePathInfoJSON([]byte(`{
		"` + upstreamGlibc + `": {
			"narHash": "sha256-FePFYIlMuycIXPZbWi7LGEiMmZSX9FMbaQenWBzm1Sc=",
			"narSize": 1000,
			"signatures": ["cache.nixos.org-1:sig"]
		},
		"` + upstreamTool + `": {
			"narHash": "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
			"narSize": 200,
			"references": ["` + upstreamGlibc + `"],
			"signatures": ["other-1:sig"]
		},
		"` + upstreamApp + `": {
			"narHash": "sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=",
			"narSize": 30,
			"references": ["` + upstreamTool + `", "` + upstreamGlibc + `"]
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	return infos
}

func TestFilterUpstreamPaths(t *testing.T) {
	t.Parallel()

	t.Run("no keys keeps everything", func(t *testing.T) {
		t.Parallel()

		kept, infos, skipped := client.FilterUpstreamPaths([]string{upstreamApp}, upstreamPathInfos(t), nil)
		if skipped.Paths != 0 || !slices.Equal(kept, []string{upstreamApp}) || len(infos) != 3 {
			t.Errorf("kept = %v, infos = %d, skipped = %+v, want everything", kept, len(infos), skipped)
		}
	})

	t.Run("paths signed by an upstream key are dropped", func(t *testing.T) {
		t.Parallel()

		kept, infos, skipped := client.FilterUpstreamPaths([]string{upstreamApp}, upstreamPathInfos(t), []string{"cache.nixos.org-1"})
		if skipped.Paths != 1 || skipped.NarBytes != 1000 {
			t.Errorf("skipped = %+v, want 1 path / 1000 bytes", skipped)
		}

		if !slices.Equal(kept, []string{upstreamApp}) || len(infos) != 2 || infos[upstreamGlibc] != nil {
			t.Errorf("kept = %v, infos = %v, want app and tool without glibc", kept, infos)
		}

		// The narinfo still names the dropped path; clients fetch it upstream.
		if !slices.Contains(infos[upstreamApp].References, upstreamGlibc) {
			t.Errorf("app lost its reference to %s", upstreamGlibc)
		}
	})

	t.Run("a full public key matches by name", func(t *testing.T) {
		t.Parallel()

		_, infos, _ := client.FilterUpstreamPaths([]string{upstreamApp}, upstreamPathInfos(t),
			[]string{"cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="})
		if infos[upstreamGlibc] != nil {
			t.Errorf("glibc kept: %v", infos)
		}
	})

	t.Run("an upstream top-level path is not pushed", func(t *testing.T) {
		t.Parallel()

		kept, infos, _ := client.FilterUpstreamPaths([]string{upstreamGlibc, upstreamApp}, upstreamPathInfos(t), []string{"cache.nixos.org-1"})
		if !slices.Equal(kept, []string{upstreamApp}) || infos[upstreamGlibc] != nil {
			t.Errorf("kept = %v, infos = %v, want only app", kept, infos)
		}
	})
}

// The server refuses a push whose objects reference objects it doesn't
// have, so the GC references must leave out what the filter dropped.
func TestPrepareClosuresSkipsUpstreamReferences(t *testing.T) {
	t.Parallel()

	kept, infos, _ := client.FilterUpstreamPaths([]string{upstreamApp}, upstreamPathInfos(t), []string{"cache.nixos.org-1"})

	result, err := client.PrepareClosures(context.Background(), kept, infos, nil)
	if err != nil {
		t.Fatal(err)
	}

	const (
		glibcNarinfo = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo"
		toolNarinfo  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.narinfo"
		appNarinfo   = "cccccccccccccccccccccccccccccccc.narinfo"
	)

	var appRefs []string

	for _, obj := range result.Closures[0].Objects {
		if obj.Key == glibcNarinfo || slices.Contains(obj.Refs, glibcNarinfo) {
			t.Errorf("object %s references the dropped glibc: %v", obj.Key, obj.Refs)
		}

		if obj.Key == appNarinfo {
			appRefs = obj.Refs
		}
	}

	if !slices.Contains(appRefs, toolNarinfo) {
		t.Errorf("app refs = %v, want %s kept", appRefs, toolNarinfo)
	}
}
