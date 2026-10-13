"""ELF .so metadata via pyelftools."""

from pathlib import Path


def extract_so(path: Path) -> dict:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import P_FLAGS

    meta = {"path": str(path)}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        # pyelftools: elfclass is 32 for 32-bit, 64 for 64-bit
        meta["elf_class"] = "64" if elf.elfclass == 64 else "32"
        meta["machine"] = elf.get_machine_arch()
        meta["needed"] = []
        meta["soname"] = None
        meta["has_jni_exports"] = False
        meta["stripped"] = True

        try:
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_DYNAMIC":
                    for tag in segment.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            meta["needed"].append(tag.needed)
                        if tag.entry.d_tag == "DT_SONAME":
                            meta["soname"] = tag.soname
                    break
        except Exception:
            pass

        try:
            symtab = elf.get_section_by_name(".dynsym") or elf.get_section_by_name(".symtab")
            if symtab:
                meta["stripped"] = elf.get_section_by_name(".symtab") is None
                for sym in symtab.iter_symbols():
                    name = sym.name
                    if name and name.startswith("Java_"):
                        meta["has_jni_exports"] = True
                        break
        except Exception:
            pass

    return meta


def _extract_so_fallback(path: Path) -> dict:
    """No pyelftools: return minimal info."""
    try:
        size = path.stat().st_size
        return {"path": str(path), "size_bytes": size, "note": "Install pyelftools for full ELF metadata"}
    except Exception as e:
        return {"error": str(e)}
