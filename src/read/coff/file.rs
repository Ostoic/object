use alloc::vec::Vec;

use crate::read::{
    self, Architecture, Export, FileFlags, Import, NoDynamicRelocationIterator, Object, ObjectKind,
    ObjectSection, ReadError, ReadRef, Result, SectionIndex, SymbolIndex,
};
use crate::{pe, LittleEndian as LE};

use super::{
    CoffComdat, CoffComdatIterator, CoffSection, CoffSectionIterator, CoffSegment,
    CoffSegmentIterator, CoffSymbol, CoffSymbolIterator, CoffSymbolTable, SectionTable,
    SymbolTable,
};

/// The common parts of `PeFile` and `CoffFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub(crate) struct CoffCommon<'data, R: ReadRef<'data>> {
    pub(crate) sections: SectionTable<'data>,
    // TODO: ImageSymbolExBytes
    pub(crate) symbols: SymbolTable<'data, R>,
    pub(crate) image_base: u64,
}

/// A COFF object file.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct CoffFile<'data, R: ReadRef<'data> = &'data [u8]> {
    pub(super) header: &'data pe::ImageFileHeader,
    pub(super) common: CoffCommon<'data, R>,
    pub(super) data: R,
}

impl<'data, R: ReadRef<'data>> CoffFile<'data, R> {
    /// Parse the raw COFF file data.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse(data: R) -> Result<Self> {
        let mut offset = 0;
        let header = pe::ImageFileHeader::parse(data, &mut offset)?;
        let sections = header.sections(data, offset)?;
        let symbols = header.symbols(data)?;

        Ok(CoffFile {
            header,
            common: CoffCommon {
                sections,
                symbols,
                image_base: 0,
            },
            data,
        })
    }
}

impl<'data, R: ReadRef<'data>> read::private::Sealed for CoffFile<'data, R> {}

impl<'data, 'file, R> Object<'data, 'file> for CoffFile<'data, R>
where
    'data: 'file,
    R: 'file + ReadRef<'data>,
{
    type Segment = CoffSegment<'data, 'file, R>;
    type SegmentIterator = CoffSegmentIterator<'data, 'file, R>;
    type Section = CoffSection<'data, 'file, R>;
    type SectionIterator = CoffSectionIterator<'data, 'file, R>;
    type Comdat = CoffComdat<'data, 'file, R>;
    type ComdatIterator = CoffComdatIterator<'data, 'file, R>;
    type Symbol = CoffSymbol<'data, 'file, R>;
    type SymbolIterator = CoffSymbolIterator<'data, 'file, R>;
    type SymbolTable = CoffSymbolTable<'data, 'file, R>;
    type DynamicRelocationIterator = NoDynamicRelocationIterator;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn architecture(&self) -> Architecture {
        match self.header.machine.get(LE) {
            pe::IMAGE_FILE_MACHINE_ARMNT => Architecture::Arm,
            pe::IMAGE_FILE_MACHINE_ARM64 => Architecture::Aarch64,
            pe::IMAGE_FILE_MACHINE_I386 => Architecture::I386,
            pe::IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
            _ => Architecture::Unknown,
        }
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_little_endian(&self) -> bool {
        true
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_64(&self) -> bool {
        // Windows COFF is always 32-bit, even for 64-bit architectures. This could be confusing.
        false
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> ObjectKind {
        ObjectKind::Relocatable
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segments(&'file self) -> CoffSegmentIterator<'data, 'file, R> {
        CoffSegmentIterator {
            file: self,
            iter: self.common.sections.iter(),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_by_name_bytes(
        &'file self,
        section_name: &[u8],
    ) -> Option<CoffSection<'data, 'file, R>> {
        self.sections()
            .find(|section| section.name_bytes() == Ok(section_name))
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_by_index(&'file self, index: SectionIndex) -> Result<CoffSection<'data, 'file, R>> {
        let section = self.common.sections.section(index.0)?;
        Ok(CoffSection {
            file: self,
            index,
            section,
        })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sections(&'file self) -> CoffSectionIterator<'data, 'file, R> {
        CoffSectionIterator {
            file: self,
            iter: self.common.sections.iter().enumerate(),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn comdats(&'file self) -> CoffComdatIterator<'data, 'file, R> {
        CoffComdatIterator {
            file: self,
            index: 0,
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol_by_index(&'file self, index: SymbolIndex) -> Result<CoffSymbol<'data, 'file, R>> {
        let symbol = self.common.symbols.symbol(index.0)?;
        Ok(CoffSymbol {
            file: &self.common,
            index,
            symbol,
        })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbols(&'file self) -> CoffSymbolIterator<'data, 'file, R> {
        CoffSymbolIterator {
            file: &self.common,
            index: 0,
        }
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol_table(&'file self) -> Option<CoffSymbolTable<'data, 'file, R>> {
        Some(CoffSymbolTable { file: &self.common })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_symbols(&'file self) -> CoffSymbolIterator<'data, 'file, R> {
        CoffSymbolIterator {
            file: &self.common,
            // Hack: don't return any.
            index: self.common.symbols.len(),
        }
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_symbol_table(&'file self) -> Option<CoffSymbolTable<'data, 'file, R>> {
        None
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_relocations(&'file self) -> Option<NoDynamicRelocationIterator> {
        None
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn imports(&self) -> Result<Vec<Import<'data>>> {
        // TODO: this could return undefined symbols, but not needed yet.
        Ok(Vec::new())
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn exports(&self) -> Result<Vec<Export<'data>>> {
        // TODO: this could return global symbols, but not needed yet.
        Ok(Vec::new())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn has_debug_symbols(&self) -> bool {
        self.section_by_name(".debug_info").is_some()
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn relative_address_base(&self) -> u64 {
        0
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn entry(&self) -> u64 {
        0
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> FileFlags {
        FileFlags::Coff {
            characteristics: self.header.characteristics.get(LE),
        }
    }
}

impl pe::ImageFileHeader {
    /// Read the file header.
    ///
    /// `data` must be the entire file data.
    /// `offset` must be the file header offset. It is updated to point after the optional header,
    /// which is where the section headers are located.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse<'data, R: ReadRef<'data>>(data: R, offset: &mut u64) -> read::Result<&'data Self> {
        let header = data
            .read::<pe::ImageFileHeader>(offset)
            .read_error(crate::nosym!("Invalid COFF file header size or alignment"))?;

        // Skip over the optional header.
        *offset = offset
            .checked_add(header.size_of_optional_header.get(LE).into())
            .read_error(crate::nosym!("Invalid COFF optional header size"))?;

        // TODO: maybe validate that the machine is known?
        Ok(header)
    }

    /// Read the section table.
    ///
    /// `data` must be the entire file data.
    /// `offset` must be after the optional file header.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn sections<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        offset: u64,
    ) -> read::Result<SectionTable<'data>> {
        SectionTable::parse(self, data, offset)
    }

    /// Read the symbol table and string table.
    ///
    /// `data` must be the entire file data.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn symbols<'data, R: ReadRef<'data>>(
        &self,
        data: R,
    ) -> read::Result<SymbolTable<'data, R>> {
        SymbolTable::parse(self, data)
    }
}
