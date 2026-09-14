package pack

import (
	"bytes"
	"debug/elf"
	"fmt"
)

// debug/elf intentionally tolerates truncated GNU version chains. Package
// dependency derivation must reject them rather than omit ABI requirements.
func validateELFVersionTable(ef *elf.File, kind elf.SectionType) error {
	headerSize, auxSize := uint64(16), uint64(16)
	countOffset, auxOffset, nextOffset, nameOffset := uint64(2), uint64(8), uint64(12), uint64(8)
	pointerTag, countTag := elf.DT_VERNEED, elf.DT_VERNEEDNUM
	if kind == elf.SHT_GNU_VERDEF {
		headerSize, auxSize = 20, 8
		countOffset, auxOffset, nextOffset, nameOffset = 6, 12, 16, 0
		pointerTag, countTag = elf.DT_VERDEF, elf.DT_VERDEFNUM
	}
	pointers, err := ef.DynValue(pointerTag)
	if err != nil {
		return err
	}
	counts, err := ef.DynValue(countTag)
	if err != nil {
		return err
	}
	section := ef.SectionByType(kind)
	if section == nil {
		if len(pointers)+len(counts) != 0 {
			return fmt.Errorf("%s dynamic metadata has no section", kind)
		}
		return nil
	}
	if len(pointers) != 1 || len(counts) != 1 || counts[0] != uint64(section.Info) || pointers[0] != section.Addr {
		return fmt.Errorf("%s section and dynamic metadata disagree", kind)
	}
	data, err := section.Data()
	if err != nil {
		return err
	}
	if int(section.Link) >= len(ef.Sections) || ef.Sections[section.Link].Type != elf.SHT_STRTAB {
		return fmt.Errorf("%s has no valid string table", kind)
	}
	str, err := ef.Sections[section.Link].Data()
	if err != nil {
		return err
	}
	validString := func(offset uint32) bool {
		return uint64(offset) < uint64(len(str)) && bytes.IndexByte(str[offset:], 0) > 0
	}
	size := uint64(len(data))
	if section.Info == 0 || uint64(section.Info) > size/headerSize {
		return fmt.Errorf("%s invalid entry count", kind)
	}
	var offset uint64
	for entry := uint32(0); entry < section.Info; entry++ {
		if offset+headerSize > size {
			return fmt.Errorf("%s truncated header", kind)
		}
		if ef.ByteOrder.Uint16(data[offset:]) != 1 {
			return fmt.Errorf("%s unsupported version", kind)
		}
		count := uint64(ef.ByteOrder.Uint16(data[offset+countOffset:]))
		aux := uint64(ef.ByteOrder.Uint32(data[offset+auxOffset:]))
		next := uint64(ef.ByteOrder.Uint32(data[offset+nextOffset:]))
		limit := size
		if entry+1 < section.Info {
			if next < headerSize || offset+next+headerSize > size {
				return fmt.Errorf("%s truncated header chain", kind)
			}
			limit = offset + next
		} else if next != 0 {
			return fmt.Errorf("%s entry count does not terminate chain", kind)
		}
		if count == 0 || aux < headerSize || count > size/auxSize {
			return fmt.Errorf("%s invalid auxiliary count or offset", kind)
		}
		if kind == elf.SHT_GNU_VERNEED && !validString(ef.ByteOrder.Uint32(data[offset+4:])) {
			return fmt.Errorf("%s invalid library name", kind)
		}
		cursor := offset + aux
		for i := uint64(0); i < count; i++ {
			if cursor+auxSize > limit {
				return fmt.Errorf("%s truncated auxiliary entry", kind)
			}
			if !validString(ef.ByteOrder.Uint32(data[cursor+nameOffset:])) {
				return fmt.Errorf("%s invalid version name", kind)
			}
			step := uint64(ef.ByteOrder.Uint32(data[cursor+auxSize-4:]))
			if i+1 < count {
				if step < auxSize {
					return fmt.Errorf("%s truncated auxiliary chain", kind)
				}
				cursor += step
			} else if step != 0 {
				return fmt.Errorf("%s auxiliary count does not terminate chain", kind)
			}
		}
		offset += next
	}
	return nil
}
