use alloc::vec::Vec;
use core::fmt::Debug;
use core::{mem, str};

use core::convert::TryInto;

use crate::read::{
    self, Architecture, ComdatKind, Error, Export, FileFlags, Import, NoDynamicRelocationIterator,
    Object, ObjectComdat, ObjectKind, ReadError, ReadRef, Result, SectionIndex, SymbolIndex,
};
use crate::{pe, ByteString, Bytes, CodeView, LittleEndian as LE, Pod, U32};
use crate::{
    read::coff::{CoffCommon, CoffSymbol, CoffSymbolIterator, CoffSymbolTable, SymbolTable},
    DebugPod,
};

use super::{
    DataDirectories, ExportTable, ImageThunkData, ImportTable, PeSection, PeSectionIterator,
    PeSegment, PeSegmentIterator, RichHeaderInfo, SectionTable,
};

/// A PE32 (32-bit) image file.
pub type PeFile32<'data, R = &'data [u8]> = PeFile<'data, pe::ImageNtHeaders32, R>;
/// A PE32+ (64-bit) image file.
pub type PeFile64<'data, R = &'data [u8]> = PeFile<'data, pe::ImageNtHeaders64, R>;

/// A PE object file.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct PeFile<'data, Pe, R = &'data [u8]>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    pub(super) dos_header: &'data pe::ImageDosHeader,
    pub(super) nt_headers: &'data Pe,
    pub(super) data_directories: DataDirectories<'data>,
    pub(super) common: CoffCommon<'data, R>,
    pub(super) data: R,
}

impl<'data, Pe, R> PeFile<'data, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    /// Parse the raw PE file data.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse(data: R) -> Result<Self> {
        let dos_header = pe::ImageDosHeader::parse(data)?;
        let mut offset = dos_header.nt_headers_offset().into();
        let (nt_headers, data_directories) = Pe::parse(data, &mut offset)?;
        let sections = nt_headers.sections(data, offset)?;
        let coff_symbols = nt_headers.symbols(data);
        let image_base = nt_headers.optional_header().image_base();

        Ok(PeFile {
            dos_header,
            nt_headers,
            data_directories,
            common: CoffCommon {
                sections,
                // The PE file format deprecates the COFF symbol table (https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image)
                // We do not want to prevent parsing the rest of the PE file for a corrupt COFF header, but rather return an empty symbol table
                symbols: coff_symbols.unwrap_or_default(),
                image_base,
            },
            data,
        })
    }

    /// Returns this binary data.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn data(&self) -> R {
        self.data
    }

    /// Return the DOS header of this file.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn dos_header(&self) -> &'data pe::ImageDosHeader {
        self.dos_header
    }

    /// Return the NT Headers of this file.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn nt_headers(&self) -> &'data Pe {
        self.nt_headers
    }

    /// Returns information about the rich header of this file (if any).
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn rich_header_info(&self) -> Option<RichHeaderInfo> {
        RichHeaderInfo::parse(self.data, self.dos_header.nt_headers_offset().into())
    }

    /// Returns the section table of this binary.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn section_table(&self) -> SectionTable<'data> {
        self.common.sections
    }

    /// Returns the data directories of this file.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn data_directories(&self) -> DataDirectories<'data> {
        self.data_directories
    }

    /// Returns the data directory at the given index.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn data_directory(&self, id: usize) -> Option<&'data pe::ImageDataDirectory> {
        self.data_directories.get(id)
    }

    /// Returns the export table of this file.
    ///
    /// The export table is located using the data directory.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn export_table(&self) -> Result<Option<ExportTable<'data>>> {
        self.data_directories
            .export_table(self.data, &self.common.sections)
    }

    /// Returns the import table of this file.
    ///
    /// The import table is located using the data directory.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn import_table(&self) -> Result<Option<ImportTable<'data>>> {
        self.data_directories
            .import_table(self.data, &self.common.sections)
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub(super) fn section_alignment(&self) -> u64 {
        u64::from(self.nt_headers.optional_header().section_alignment())
    }
}

impl<'data, Pe, R> read::private::Sealed for PeFile<'data, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Pe, R> Object<'data, 'file> for PeFile<'data, Pe, R>
where
    'data: 'file,
    Pe: ImageNtHeaders,
    R: 'file + ReadRef<'data>,
{
    type Segment = PeSegment<'data, 'file, Pe, R>;
    type SegmentIterator = PeSegmentIterator<'data, 'file, Pe, R>;
    type Section = PeSection<'data, 'file, Pe, R>;
    type SectionIterator = PeSectionIterator<'data, 'file, Pe, R>;
    type Comdat = PeComdat<'data, 'file, Pe, R>;
    type ComdatIterator = PeComdatIterator<'data, 'file, Pe, R>;
    type Symbol = CoffSymbol<'data, 'file, R>;
    type SymbolIterator = CoffSymbolIterator<'data, 'file, R>;
    type SymbolTable = CoffSymbolTable<'data, 'file, R>;
    type DynamicRelocationIterator = NoDynamicRelocationIterator;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn architecture(&self) -> Architecture {
        match self.nt_headers.file_header().machine.get(LE) {
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
        // Only little endian is supported.
        true
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_64(&self) -> bool {
        self.nt_headers.is_type_64()
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> ObjectKind {
        let characteristics = self.nt_headers.file_header().characteristics.get(LE);
        if characteristics & pe::IMAGE_FILE_DLL != 0 {
            ObjectKind::Dynamic
        } else if characteristics & pe::IMAGE_FILE_SYSTEM != 0 {
            ObjectKind::Unknown
        } else {
            ObjectKind::Executable
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segments(&'file self) -> PeSegmentIterator<'data, 'file, Pe, R> {
        PeSegmentIterator {
            file: self,
            iter: self.common.sections.iter(),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_by_name_bytes(
        &'file self,
        section_name: &[u8],
    ) -> Option<PeSection<'data, 'file, Pe, R>> {
        self.common
            .sections
            .section_by_name(self.common.symbols.strings(), section_name)
            .map(|(index, section)| PeSection {
                file: self,
                index: SectionIndex(index),
                section,
            })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_by_index(
        &'file self,
        index: SectionIndex,
    ) -> Result<PeSection<'data, 'file, Pe, R>> {
        let section = self.common.sections.section(index.0)?;
        Ok(PeSection {
            file: self,
            index,
            section,
        })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sections(&'file self) -> PeSectionIterator<'data, 'file, Pe, R> {
        PeSectionIterator {
            file: self,
            iter: self.common.sections.iter().enumerate(),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn comdats(&'file self) -> PeComdatIterator<'data, 'file, Pe, R> {
        PeComdatIterator { file: self }
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

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_symbol_table(&'file self) -> Option<CoffSymbolTable<'data, 'file, R>> {
        None
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_relocations(&'file self) -> Option<NoDynamicRelocationIterator> {
        None
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn imports(&self) -> Result<Vec<Import<'data>>> {
        let mut imports = Vec::new();
        if let Some(import_table) = self.import_table()? {
            let mut import_descs = import_table.descriptors()?;
            while let Some(import_desc) = import_descs.next()? {
                let library = import_table.name(import_desc.name.get(LE))?;
                let mut first_thunk = import_desc.original_first_thunk.get(LE);
                if first_thunk == 0 {
                    first_thunk = import_desc.first_thunk.get(LE);
                }
                let mut thunks = import_table.thunks(first_thunk)?;
                while let Some(thunk) = thunks.next::<Pe>()? {
                    if !thunk.is_ordinal() {
                        let (_hint, name) = import_table.hint_name(thunk.address())?;
                        imports.push(Import {
                            library: ByteString(library),
                            name: ByteString(name),
                        });
                    }
                }
            }
        }
        Ok(imports)
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn exports(&self) -> Result<Vec<Export<'data>>> {
        let mut exports = Vec::new();
        if let Some(export_table) = self.export_table()? {
            for (name_pointer, address_index) in export_table.name_iter() {
                let name = export_table.name_from_pointer(name_pointer)?;
                let address = export_table.address_by_index(address_index.into())?;
                if !export_table.is_forward(address) {
                    exports.push(Export {
                        name: ByteString(name),
                        address: self.common.image_base.wrapping_add(address.into()),
                    })
                }
            }
        }
        Ok(exports)
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn pdb_info(&self) -> Result<Option<CodeView>> {
        let data_dir = match self.data_directory(pe::IMAGE_DIRECTORY_ENTRY_DEBUG) {
            Some(data_dir) => data_dir,
            None => return Ok(None),
        };
        let debug_data = data_dir.data(self.data, &self.common.sections).map(Bytes)?;
        let debug_data_size = data_dir.size.get(LE) as usize;

        let count = debug_data_size / mem::size_of::<pe::ImageDebugDirectory>();
        let rem = debug_data_size % mem::size_of::<pe::ImageDebugDirectory>();
        if rem != 0 || count < 1 {
            return Err(Error("Invalid PE debug dir size"));
        }

        let debug_dirs = debug_data
            .read_slice_at::<pe::ImageDebugDirectory>(0, count)
            .read_error("Invalid PE debug dir size")?;

        for debug_dir in debug_dirs {
            if debug_dir.typ.get(LE) != pe::IMAGE_DEBUG_TYPE_CODEVIEW {
                continue;
            }

            let info = self
                .data
                .read_slice_at::<u8>(
                    debug_dir.pointer_to_raw_data.get(LE) as u64,
                    debug_dir.size_of_data.get(LE) as usize,
                )
                .read_error("Invalid CodeView Info address")?;

            let mut info = Bytes(info);

            let sig = info
                .read_bytes(4)
                .read_error("Invalid CodeView signature")?;
            if sig.0 != b"RSDS" {
                return Ok(None);
            }

            let guid: [u8; 16] = info
                .read_bytes(16)
                .read_error("Invalid CodeView GUID")?
                .0
                .try_into()
                .unwrap();

            let age = info.read::<U32<LE>>().read_error("Invalid CodeView Age")?;

            let path = info
                .read_string()
                .read_error("Invalid CodeView file path")?;

            return Ok(Some(CodeView {
                path: ByteString(path),
                guid,
                age: age.get(LE),
            }));
        }
        Ok(None)
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn has_debug_symbols(&self) -> bool {
        self.section_by_name(".debug_info").is_some()
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn relative_address_base(&self) -> u64 {
        self.common.image_base
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn entry(&self) -> u64 {
        u64::from(self.nt_headers.optional_header().address_of_entry_point())
            .wrapping_add(self.common.image_base)
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> FileFlags {
        FileFlags::Coff {
            characteristics: self.nt_headers.file_header().characteristics.get(LE),
        }
    }
}

/// An iterator over the COMDAT section groups of a `PeFile32`.
pub type PeComdatIterator32<'data, 'file, R = &'data [u8]> =
    PeComdatIterator<'data, 'file, pe::ImageNtHeaders32, R>;
/// An iterator over the COMDAT section groups of a `PeFile64`.
pub type PeComdatIterator64<'data, 'file, R = &'data [u8]> =
    PeComdatIterator<'data, 'file, pe::ImageNtHeaders64, R>;

/// An iterator over the COMDAT section groups of a `PeFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct PeComdatIterator<'data, 'file, Pe, R = &'data [u8]>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    #[allow(unused)]
    file: &'file PeFile<'data, Pe, R>,
}

impl<'data, 'file, Pe, R> Iterator for PeComdatIterator<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    type Item = PeComdat<'data, 'file, Pe, R>;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// A COMDAT section group of a `PeFile32`.
pub type PeComdat32<'data, 'file, R = &'data [u8]> =
    PeComdat<'data, 'file, pe::ImageNtHeaders32, R>;
/// A COMDAT section group of a `PeFile64`.
pub type PeComdat64<'data, 'file, R = &'data [u8]> =
    PeComdat<'data, 'file, pe::ImageNtHeaders64, R>;

/// A COMDAT section group of a `PeFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct PeComdat<'data, 'file, Pe, R = &'data [u8]>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    #[allow(unused)]
    file: &'file PeFile<'data, Pe, R>,
}

impl<'data, 'file, Pe, R> read::private::Sealed for PeComdat<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Pe, R> ObjectComdat<'data> for PeComdat<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    type SectionIterator = PeComdatSectionIterator<'data, 'file, Pe, R>;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> ComdatKind {
        unreachable!();
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol(&self) -> SymbolIndex {
        unreachable!();
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name_bytes(&self) -> Result<&[u8]> {
        unreachable!();
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<&str> {
        unreachable!();
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sections(&self) -> Self::SectionIterator {
        unreachable!();
    }
}

/// An iterator over the sections in a COMDAT section group of a `PeFile32`.
pub type PeComdatSectionIterator32<'data, 'file, R = &'data [u8]> =
    PeComdatSectionIterator<'data, 'file, pe::ImageNtHeaders32, R>;
/// An iterator over the sections in a COMDAT section group of a `PeFile64`.
pub type PeComdatSectionIterator64<'data, 'file, R = &'data [u8]> =
    PeComdatSectionIterator<'data, 'file, pe::ImageNtHeaders64, R>;

/// An iterator over the sections in a COMDAT section group of a `PeFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct PeComdatSectionIterator<'data, 'file, Pe, R = &'data [u8]>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    #[allow(unused)]
    file: &'file PeFile<'data, Pe, R>,
}

impl<'data, 'file, Pe, R> Iterator for PeComdatSectionIterator<'data, 'file, Pe, R>
where
    Pe: ImageNtHeaders,
    R: ReadRef<'data>,
{
    type Item = SectionIndex;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl pe::ImageDosHeader {
    /// Read the DOS header.
    ///
    /// Also checks that the `e_magic` field in the header is valid.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse<'data, R: ReadRef<'data>>(data: R) -> read::Result<&'data Self> {
        // DOS header comes first.
        let dos_header = data
            .read_at::<pe::ImageDosHeader>(0)
            .read_error(crate::nosym!("Invalid DOS header size or alignment"))?;
        if dos_header.e_magic.get(LE) != pe::IMAGE_DOS_SIGNATURE {
            return Err(Error(crate::nosym!("Invalid DOS magic")));
        }
        Ok(dos_header)
    }

    /// Return the file offset of the nt_headers.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn nt_headers_offset(&self) -> u32 {
        self.e_lfanew.get(LE)
    }
}

/// Find the optional header and read the `optional_header.magic`.
///
/// It can be useful to know this magic value before trying to
/// fully parse the NT headers.
#[cfg_attr(feature = "aggressive-inline", inline(always))]
pub fn optional_header_magic<'data, R: ReadRef<'data>>(data: R) -> Result<u16> {
    let dos_header = pe::ImageDosHeader::parse(data)?;
    // NT headers are at an offset specified in the DOS header.
    let offset = dos_header.nt_headers_offset().into();
    // It doesn't matter which NT header type is used for the purpose
    // of reading the optional header magic.
    let nt_headers = data
        .read_at::<pe::ImageNtHeaders32>(offset)
        .read_error(crate::nosym!(
            "Invalid NT headers offset, size, or alignment"
        ))?;
    if nt_headers.signature() != pe::IMAGE_NT_SIGNATURE {
        return Err(Error(crate::nosym!("Invalid PE magic")));
    }
    Ok(nt_headers.optional_header().magic())
}

/// A trait for generic access to `ImageNtHeaders32` and `ImageNtHeaders64`.
#[allow(missing_docs)]
pub trait ImageNtHeaders: DebugPod {
    type ImageOptionalHeader: ImageOptionalHeader;
    type ImageThunkData: ImageThunkData;

    /// Return true if this type is a 64-bit header.
    ///
    /// This is a property of the type, not a value in the header data.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_type_64(&self) -> bool;

    /// Return true if the magic field in the optional header is valid.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_valid_optional_magic(&self) -> bool;

    /// Return the signature
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn signature(&self) -> u32;

    /// Return the file header.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_header(&self) -> &pe::ImageFileHeader;

    /// Return the optional header.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn optional_header(&self) -> &Self::ImageOptionalHeader;

    // Provided methods.

    /// Read the NT headers, including the data directories.
    ///
    /// `data` must be for the entire file.
    ///
    /// `offset` must be headers offset, which can be obtained from `ImageDosHeader::nt_headers_offset`.
    /// It is updated to point after the optional header, which is where the section headers are located.
    ///
    /// Also checks that the `signature` and `magic` fields in the headers are valid.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn parse<'data, R: ReadRef<'data>>(
        data: R,
        offset: &mut u64,
    ) -> read::Result<(&'data Self, DataDirectories<'data>)> {
        // Note that this does not include the data directories in the optional header.
        let nt_headers = data
            .read::<Self>(offset)
            .read_error(crate::nosym!("Invalid PE headers offset or size"))?;
        if nt_headers.signature() != pe::IMAGE_NT_SIGNATURE {
            return Err(Error(crate::nosym!("Invalid PE magic")));
        }
        if !nt_headers.is_valid_optional_magic() {
            return Err(Error(crate::nosym!("Invalid PE optional header magic")));
        }

        // Read the rest of the optional header, and then read the data directories from that.
        let optional_data_size =
            u64::from(nt_headers.file_header().size_of_optional_header.get(LE))
                .checked_sub(mem::size_of::<Self::ImageOptionalHeader>() as u64)
                .read_error(crate::nosym!("PE optional header size is too small"))?;
        let optional_data = data
            .read_bytes(offset, optional_data_size)
            .read_error(crate::nosym!("Invalid PE optional header size"))?;
        let data_directories = DataDirectories::parse(
            optional_data,
            nt_headers.optional_header().number_of_rva_and_sizes(),
        )?;

        Ok((nt_headers, data_directories))
    }

    /// Read the section table.
    ///
    /// `data` must be for the entire file.
    /// `offset` must be after the optional file header.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sections<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        offset: u64,
    ) -> read::Result<SectionTable<'data>> {
        SectionTable::parse(self.file_header(), data, offset)
    }

    /// Read the COFF symbol table and string table.
    ///
    /// `data` must be the entire file data.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbols<'data, R: ReadRef<'data>>(&self, data: R) -> read::Result<SymbolTable<'data, R>> {
        SymbolTable::parse(self.file_header(), data)
    }
}

/// A trait for generic access to `ImageOptionalHeader32` and `ImageOptionalHeader64`.
#[allow(missing_docs)]
pub trait ImageOptionalHeader: DebugPod {
    // Standard fields.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn magic(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_linker_version(&self) -> u8;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_linker_version(&self) -> u8;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_code(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_initialized_data(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_uninitialized_data(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address_of_entry_point(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn base_of_code(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn base_of_data(&self) -> Option<u32>;

    // NT additional fields.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn image_base(&self) -> u64;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_alignment(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_alignment(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_operating_system_version(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_operating_system_version(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_image_version(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_image_version(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_subsystem_version(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_subsystem_version(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn win32_version_value(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_image(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_headers(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn check_sum(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn subsystem(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dll_characteristics(&self) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_stack_reserve(&self) -> u64;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_stack_commit(&self) -> u64;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_heap_reserve(&self) -> u64;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_heap_commit(&self) -> u64;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn loader_flags(&self) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn number_of_rva_and_sizes(&self) -> u32;
}

impl ImageNtHeaders for pe::ImageNtHeaders32 {
    type ImageOptionalHeader = pe::ImageOptionalHeader32;
    type ImageThunkData = pe::ImageThunkData32;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_type_64(&self) -> bool {
        false
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_valid_optional_magic(&self) -> bool {
        self.optional_header.magic.get(LE) == pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn signature(&self) -> u32 {
        self.signature.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_header(&self) -> &pe::ImageFileHeader {
        &self.file_header
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn optional_header(&self) -> &Self::ImageOptionalHeader {
        &self.optional_header
    }
}

impl ImageOptionalHeader for pe::ImageOptionalHeader32 {
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn magic(&self) -> u16 {
        self.magic.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_linker_version(&self) -> u8 {
        self.major_linker_version
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_linker_version(&self) -> u8 {
        self.minor_linker_version
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_code(&self) -> u32 {
        self.size_of_code.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_initialized_data(&self) -> u32 {
        self.size_of_initialized_data.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_uninitialized_data(&self) -> u32 {
        self.size_of_uninitialized_data.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address_of_entry_point(&self) -> u32 {
        self.address_of_entry_point.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn base_of_code(&self) -> u32 {
        self.base_of_code.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn base_of_data(&self) -> Option<u32> {
        Some(self.base_of_data.get(LE))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn image_base(&self) -> u64 {
        self.image_base.get(LE).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_alignment(&self) -> u32 {
        self.section_alignment.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_alignment(&self) -> u32 {
        self.file_alignment.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_operating_system_version(&self) -> u16 {
        self.major_operating_system_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_operating_system_version(&self) -> u16 {
        self.minor_operating_system_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_image_version(&self) -> u16 {
        self.major_image_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_image_version(&self) -> u16 {
        self.minor_image_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_subsystem_version(&self) -> u16 {
        self.major_subsystem_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_subsystem_version(&self) -> u16 {
        self.minor_subsystem_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn win32_version_value(&self) -> u32 {
        self.win32_version_value.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_image(&self) -> u32 {
        self.size_of_image.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_headers(&self) -> u32 {
        self.size_of_headers.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn check_sum(&self) -> u32 {
        self.check_sum.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn subsystem(&self) -> u16 {
        self.subsystem.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dll_characteristics(&self) -> u16 {
        self.dll_characteristics.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_stack_reserve(&self) -> u64 {
        self.size_of_stack_reserve.get(LE).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_stack_commit(&self) -> u64 {
        self.size_of_stack_commit.get(LE).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_heap_reserve(&self) -> u64 {
        self.size_of_heap_reserve.get(LE).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_heap_commit(&self) -> u64 {
        self.size_of_heap_commit.get(LE).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn loader_flags(&self) -> u32 {
        self.loader_flags.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes.get(LE)
    }
}

impl ImageNtHeaders for pe::ImageNtHeaders64 {
    type ImageOptionalHeader = pe::ImageOptionalHeader64;
    type ImageThunkData = pe::ImageThunkData64;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_type_64(&self) -> bool {
        true
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_valid_optional_magic(&self) -> bool {
        self.optional_header.magic.get(LE) == pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn signature(&self) -> u32 {
        self.signature.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_header(&self) -> &pe::ImageFileHeader {
        &self.file_header
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn optional_header(&self) -> &Self::ImageOptionalHeader {
        &self.optional_header
    }
}

impl ImageOptionalHeader for pe::ImageOptionalHeader64 {
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn magic(&self) -> u16 {
        self.magic.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_linker_version(&self) -> u8 {
        self.major_linker_version
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_linker_version(&self) -> u8 {
        self.minor_linker_version
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_code(&self) -> u32 {
        self.size_of_code.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_initialized_data(&self) -> u32 {
        self.size_of_initialized_data.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_uninitialized_data(&self) -> u32 {
        self.size_of_uninitialized_data.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address_of_entry_point(&self) -> u32 {
        self.address_of_entry_point.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn base_of_code(&self) -> u32 {
        self.base_of_code.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn base_of_data(&self) -> Option<u32> {
        None
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn image_base(&self) -> u64 {
        self.image_base.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_alignment(&self) -> u32 {
        self.section_alignment.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_alignment(&self) -> u32 {
        self.file_alignment.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_operating_system_version(&self) -> u16 {
        self.major_operating_system_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_operating_system_version(&self) -> u16 {
        self.minor_operating_system_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_image_version(&self) -> u16 {
        self.major_image_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_image_version(&self) -> u16 {
        self.minor_image_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn major_subsystem_version(&self) -> u16 {
        self.major_subsystem_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn minor_subsystem_version(&self) -> u16 {
        self.minor_subsystem_version.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn win32_version_value(&self) -> u32 {
        self.win32_version_value.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_image(&self) -> u32 {
        self.size_of_image.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_headers(&self) -> u32 {
        self.size_of_headers.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn check_sum(&self) -> u32 {
        self.check_sum.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn subsystem(&self) -> u16 {
        self.subsystem.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dll_characteristics(&self) -> u16 {
        self.dll_characteristics.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_stack_reserve(&self) -> u64 {
        self.size_of_stack_reserve.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_stack_commit(&self) -> u64 {
        self.size_of_stack_commit.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_heap_reserve(&self) -> u64 {
        self.size_of_heap_reserve.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size_of_heap_commit(&self) -> u64 {
        self.size_of_heap_commit.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn loader_flags(&self) -> u32 {
        self.loader_flags.get(LE)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes.get(LE)
    }
}
