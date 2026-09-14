package pack

import (
	"debug/elf"
	"fmt"
	"regexp"
	"strings"
)

// Version-node identity is scoped to its library. A token in another SONAME
// must never satisfy this requirement. Colons delimit the two components and
// are forbidden within either component, keeping the encoding unambiguous.
var elfVersionToken = regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`)

func elfVersionCapability(soname, token string) (string, error) {
	name := "elfver(" + soname + ":" + token + ")"
	if err := ValidateCapabilityName(soname); err != nil || strings.ContainsAny(soname, "():/") || !elfVersionToken.MatchString(token) {
		return "", fmt.Errorf("unrepresentable ELF version capability %q", name)
	}
	if err := ValidateCapabilityName(name); err != nil {
		return "", err
	}
	return name, nil
}

type elfCapabilities struct {
	selected  map[string]bool
	providers map[string]string
	provided  map[string]bool
	needed    map[string]string
	errs      []error
}

func newELFCapabilities(sonames []string) *elfCapabilities {
	c := &elfCapabilities{selected: map[string]bool{}, providers: map[string]string{}, provided: map[string]bool{}, needed: map[string]string{}}
	for _, name := range sonames {
		if _, err := elfVersionCapability(name, "version"); err != nil {
			c.errs = append(c.errs, err)
		}
		c.selected[name] = true
	}
	return c
}

func (c *elfCapabilities) scan(ef *elf.File, dest string) {
	if len(c.selected) == 0 {
		return
	}
	soname := dynSoname(ef)
	if c.selected[soname] {
		if previous, exists := c.providers[soname]; exists {
			c.errs = append(c.errs, fmt.Errorf("multiple payload objects provide selected SONAME %s: %s and %s", soname, previous, dest))
		}
		c.providers[soname] = dest
		if err := validateELFVersionTable(ef, elf.SHT_GNU_VERDEF); err != nil {
			c.errs = append(c.errs, fmt.Errorf("%s: %w", dest, err))
			return
		}
		var definitions []elf.DynamicVersion
		var err error
		if ef.SectionByType(elf.SHT_GNU_VERDEF) != nil {
			definitions, err = ef.DynamicVersions()
		}
		if err != nil {
			c.errs = append(c.errs, fmt.Errorf("%s: reading ELF version definitions: %w", dest, err))
		} else {
			for _, definition := range definitions {
				if definition.Flags&elf.VER_FLG_BASE != 0 {
					continue
				}
				name, err := elfVersionCapability(soname, definition.Name)
				if err != nil {
					c.errs = append(c.errs, fmt.Errorf("%s: %w", dest, err))
					continue
				}
				c.provided[name] = true
			}
		}
	}
	// Only selected runtime dependencies trigger strict requirement parsing.
	// An unversioned provider still supplies its SONAME, but cannot satisfy a
	// versioned consumer. It must not be assigned capabilities it doesn't define.
	libraries, err := ef.ImportedLibraries()
	if err != nil {
		c.errs = append(c.errs, fmt.Errorf("%s: reading ELF library dependencies: %w", dest, err))
		return
	}
	relevant := false
	for _, name := range libraries {
		relevant = relevant || c.selected[name]
	}
	if !relevant {
		return
	}
	if err := validateELFVersionTable(ef, elf.SHT_GNU_VERNEED); err != nil {
		c.errs = append(c.errs, fmt.Errorf("%s: %w", dest, err))
		return
	}
	if ef.SectionByType(elf.SHT_GNU_VERNEED) == nil {
		return
	}
	needs, err := ef.DynamicVersionNeeds()
	if err != nil {
		c.errs = append(c.errs, fmt.Errorf("%s: reading ELF version requirements: %w", dest, err))
		return
	}
	for _, need := range needs {
		if !c.selected[need.Name] {
			continue
		}
		for _, version := range need.Needs {
			// ELF weak version requirements are optional at runtime.
			if version.Flags&elf.VER_FLG_WEAK != 0 {
				continue
			}
			name, err := elfVersionCapability(need.Name, version.Dep)
			if err != nil {
				c.errs = append(c.errs, fmt.Errorf("%s: %w", dest, err))
				continue
			}
			c.needed[name] = need.Name
		}
	}
}
