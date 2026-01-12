// gorun - Fast Go script runner with content-addressed caching
//
// Usage: gorun <path/to/script.go> [args...]
//        gorun <path/to/dir>       [args...]  (runs main.go in dir)
//
// Computes SHA256 of all .go files in the source directory and caches
// the compiled binary. Only recompiles when source files change.
//
// Cache location: $XDG_CACHE_HOME/gorun/ or ~/.cache/gorun/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

// Config represents a gorun wrapper config file
type Config struct {
	Src string `json:"src"` // Path to Go source (supports env vars)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `gorun - Fast Go script runner with content-addressed caching

Usage:
  gorun <script.go> [args...]      Run a Go source file
  gorun <dir/> [args...]           Run main.go in directory
  gorun <config> [args...]         Run from config file (auto-detect)
  gorun --config <file> [args...]  Run from config file (explicit)

Config file format (JSONC with comments):
  #!/path/to/gorun
  # Comment describing the script
  {
    "src": "${SCRIPT_DIR}/../lib/script.go"  // supports env vars
  }

Environment variables in config:
  ${SCRIPT_DIR}  Directory containing the config file
  ${VAR}         Any environment variable

Cache: $XDG_CACHE_HOME/gorun/ or ~/.cache/gorun/`)
}

// parseConfigFile checks if the file is a gorun config (shebang + JSON with comments)
// Returns the config, the directory containing the config file, and success bool
func parseConfigFile(path string) (*Config, string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", false
	}

	content := string(data)

	// Must start with shebang
	if !strings.HasPrefix(content, "#!") {
		return nil, "", false
	}

	// Strip comments and parse as JSONC
	jsonContent := stripComments(content)

	// Must have JSON object
	if !strings.Contains(jsonContent, "{") {
		return nil, "", false
	}

	var cfg Config
	if err := json.Unmarshal([]byte(jsonContent), &cfg); err != nil {
		return nil, "", false
	}

	if cfg.Src == "" {
		return nil, "", false
	}

	absPath, _ := filepath.Abs(path)
	configDir := filepath.Dir(absPath)

	return &cfg, configDir, true
}

// stripComments removes shell-style (#) and C-style (//) comments from JSONC
func stripComments(s string) string {
	var result strings.Builder
	lines := strings.Split(s, "\n")

	inMultiline := false

	for _, line := range lines {
		// Skip shebang
		if strings.HasPrefix(line, "#!") {
			continue
		}

		// Process character by character for proper comment handling
		processed := processLine(line, &inMultiline)

		// Skip pure comment lines (# at start after trimming)
		trimmed := strings.TrimSpace(processed)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		result.WriteString(processed)
		result.WriteString("\n")
	}

	return result.String()
}

// processLine handles // and /* */ comments within a line
func processLine(line string, inMultiline *bool) string {
	var result strings.Builder
	inString := false
	escaped := false

	for i := 0; i < len(line); i++ {
		c := line[i]

		// Handle multiline comment end
		if *inMultiline {
			if c == '*' && i+1 < len(line) && line[i+1] == '/' {
				*inMultiline = false
				i++ // skip the /
			}
			continue
		}

		// Track string state for proper quote handling
		if c == '"' && !escaped {
			inString = !inString
		}
		escaped = c == '\\' && !escaped

		// Only process comments outside strings
		if !inString {
			// Check for // comment
			if c == '/' && i+1 < len(line) && line[i+1] == '/' {
				break // rest of line is comment
			}
			// Check for /* comment start
			if c == '/' && i+1 < len(line) && line[i+1] == '*' {
				*inMultiline = true
				i++ // skip the *
				continue
			}
			// Check for # comment (only if not inside JSON structure)
			if c == '#' {
				break // rest of line is comment
			}
		}

		result.WriteByte(c)
	}

	return result.String()
}

// expandEnvVars expands ${VAR} and $VAR patterns, plus ${SCRIPT_DIR}
func expandEnvVars(s string, scriptDir string) string {
	// First handle ${SCRIPT_DIR} specially
	s = strings.ReplaceAll(s, "${SCRIPT_DIR}", scriptDir)
	s = strings.ReplaceAll(s, "$SCRIPT_DIR", scriptDir)

	// Handle ${VAR} pattern
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	s = re.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[2 : len(match)-1] // strip ${ and }
		if val := os.Getenv(varName); val != "" {
			return val
		}
		return match // keep original if not found
	})

	// Handle $VAR pattern (word boundary)
	re2 := regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	s = re2.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[1:] // strip $
		if val := os.Getenv(varName); val != "" {
			return val
		}
		return match
	})

	// Resolve to absolute path if relative
	if !filepath.IsAbs(s) {
		s = filepath.Join(scriptDir, s)
	}

	return s
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	srcPath := os.Args[1]
	args := os.Args[2:]
	forceConfig := false

	// Handle --config flag
	if srcPath == "--config" || srcPath == "-c" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "gorun: --config requires a path")
			os.Exit(1)
		}
		forceConfig = true
		srcPath = os.Args[2]
		args = os.Args[3:]
	}

	// Handle --help
	if srcPath == "--help" || srcPath == "-h" {
		printUsage()
		os.Exit(0)
	}

	// Check if this is a config file (explicit or auto-detect)
	if forceConfig {
		cfg, configDir, ok := parseConfigFile(srcPath)
		if !ok {
			fmt.Fprintf(os.Stderr, "gorun: invalid config file: %s\n", srcPath)
			os.Exit(1)
		}
		srcPath = expandEnvVars(cfg.Src, configDir)
	} else if cfg, configDir, ok := parseConfigFile(srcPath); ok {
		// Auto-detect config file
		srcPath = expandEnvVars(cfg.Src, configDir)
	}

	src, err := resolvePaths(srcPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gorun: %v\n", err)
		os.Exit(1)
	}

	hash, err := hashSource(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gorun: failed to hash source: %v\n", err)
		os.Exit(1)
	}

	cacheDir := getCacheDir()
	binPath := filepath.Join(cacheDir, fmt.Sprintf("%s-%s", src.binName, hash[:12]))

	// Fast path: binary exists with matching hash
	if _, err := os.Stat(binPath); err == nil {
		execBinary(binPath, args)
	}

	// Slow path: compile
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "gorun: failed to create cache dir: %v\n", err)
		os.Exit(1)
	}

	if err := compile(src, binPath); err != nil {
		fmt.Fprintf(os.Stderr, "gorun: compilation failed: %v\n", err)
		os.Exit(1)
	}

	// Clean old versions of this binary
	cleanOldBinaries(cacheDir, src.binName, hash[:12])

	execBinary(binPath, args)
}

type sourceInfo struct {
	dir      string   // Directory containing source
	binName  string   // Name for the binary
	files    []string // Specific files to compile (nil = all in dir)
	hashPath string   // Path to hash for change detection
}

func resolvePaths(srcPath string) (*sourceInfo, error) {
	absPath, err := filepath.Abs(srcPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		// Directory provided, compile all .go files as a package
		mainGo := filepath.Join(absPath, "main.go")
		if _, err := os.Stat(mainGo); err != nil {
			return nil, fmt.Errorf("no main.go in directory %s", absPath)
		}
		return &sourceInfo{
			dir:      absPath,
			binName:  filepath.Base(absPath),
			files:    nil, // nil means compile all .go files
			hashPath: absPath,
		}, nil
	}

	// Single file provided - compile only that file
	if !strings.HasSuffix(absPath, ".go") {
		return nil, fmt.Errorf("not a .go file: %s", absPath)
	}

	return &sourceInfo{
		dir:      filepath.Dir(absPath),
		binName:  strings.TrimSuffix(filepath.Base(absPath), ".go"),
		files:    []string{filepath.Base(absPath)}, // Only this file
		hashPath: absPath,                          // Hash only this file
	}, nil
}

func hashSource(src *sourceInfo) (string, error) {
	var files []string

	info, err := os.Stat(src.hashPath)
	if err != nil {
		return "", err
	}

	if !info.IsDir() {
		// Single file
		files = []string{src.hashPath}
	} else {
		// Directory - hash all .go files
		err := filepath.Walk(src.hashPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, ".go") {
				files = append(files, path)
			}
			// Don't recurse into subdirectories
			if info.IsDir() && path != src.hashPath {
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}

	// Sort for deterministic hashing
	sort.Strings(files)

	h := sha256.New()
	for _, f := range files {
		// Include filename in hash
		h.Write([]byte(f))

		data, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		h.Write(data)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func getCacheDir() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "gorun")
	}
	return filepath.Join(os.Getenv("HOME"), ".cache", "gorun")
}

func compile(src *sourceInfo, binPath string) error {
	var goFiles []string
	var tempDir string

	if src.files != nil {
		// Specific files provided - check for shebangs
		for _, f := range src.files {
			filePath := filepath.Join(src.dir, f)
			processed, tmpFile, err := stripShebangIfNeeded(filePath)
			if err != nil {
				return err
			}
			if processed {
				if tempDir == "" {
					tempDir, _ = os.MkdirTemp("", "gorun-")
				}
				// Copy processed file to temp dir with same name
				tmpPath := filepath.Join(tempDir, f)
				if err := os.WriteFile(tmpPath, []byte(tmpFile), 0644); err != nil {
					return err
				}
				goFiles = append(goFiles, tmpPath)
			} else {
				goFiles = append(goFiles, filePath)
			}
		}
	} else {
		// Get all .go files in the directory
		entries, err := os.ReadDir(src.dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				goFiles = append(goFiles, entry.Name())
			}
		}
	}

	// Cleanup temp files after compile
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}

	if len(goFiles) == 0 {
		return fmt.Errorf("no .go files in %s", src.dir)
	}

	// Build with explicit file list (works without go.mod)
	args := append([]string{"build", "-o", binPath}, goFiles...)
	cmd := exec.Command("go", args...)
	if tempDir == "" {
		cmd.Dir = src.dir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// stripShebangIfNeeded checks if file starts with #! and returns content without it
func stripShebangIfNeeded(filePath string) (processed bool, content string, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, "", err
	}

	if len(data) < 2 || data[0] != '#' || data[1] != '!' {
		return false, "", nil
	}

	// Find end of shebang line
	idx := 0
	for idx < len(data) && data[idx] != '\n' {
		idx++
	}
	if idx < len(data) {
		idx++ // skip the newline
	}

	return true, string(data[idx:]), nil
}

func cleanOldBinaries(cacheDir, binName, currentHash string) {
	prefix := binName + "-"
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, prefix) && !strings.HasSuffix(name, currentHash) {
			os.Remove(filepath.Join(cacheDir, name))
		}
	}
}

func execBinary(binPath string, args []string) {
	// Use syscall.Exec to replace current process (no fork overhead)
	argv := append([]string{binPath}, args...)
	env := os.Environ()

	err := syscall.Exec(binPath, argv, env)
	// If we get here, exec failed
	fmt.Fprintf(os.Stderr, "gorun: exec failed: %v\n", err)
	os.Exit(1)
}
