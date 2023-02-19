use core::fmt::Debug;
use core::{fmt, result, slice, str};

use crate::macho;
use crate::pod::Pod;
use crate::read::{
    self, CompressedData, CompressedFileRange, ObjectSection, ReadError, ReadRef, Result,
    SectionFlags, SectionIndex, SectionKind,
};
use crate::{
    endian::{self, Endianness},
    DebugPod,
};

use super::{MachHeader, MachOFile, MachORelocationIterator};

/// An iterator over the sections of a `MachOFile32`.
pub type MachOSectionIterator32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSectionIterator<'data, 'file, macho::MachHeader32<Endian>, R>;
/// An iterator over the sections of a `MachOFile64`.
pub type MachOSectionIterator64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSectionIterator<'data, 'file, macho::MachHeader64<Endian>, R>;

/// An iterator over the sections of a `MachOFile`.

pub struct MachOSectionIterator<'data, 'file, Mach, R = &'data [u8]>
where
    'data: 'file,
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    pub(super) file: &'file MachOFile<'data, Mach, R>,
    pub(super) iter: slice::Iter<'file, MachOSectionInternal<'data, Mach>>,
}

impl<'data, 'file, Mach, R> fmt::Debug for MachOSectionIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // It's painful to do much better than this
        f.debug_struct("MachOSectionIterator").finish()
    }
}

impl<'data, 'file, Mach, R> Iterator for MachOSectionIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    type Item = MachOSection<'data, 'file, Mach, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|&internal| MachOSection {
            file: self.file,
            internal,
        })
    }
}

/// A section of a `MachOFile32`.
pub type MachOSection32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSection<'data, 'file, macho::MachHeader32<Endian>, R>;
/// A section of a `MachOFile64`.
pub type MachOSection64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSection<'data, 'file, macho::MachHeader64<Endian>, R>;

/// A section of a `MachOFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct MachOSection<'data, 'file, Mach, R = &'data [u8]>
where
    'data: 'file,
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    pub(super) file: &'file MachOFile<'data, Mach, R>,
    pub(super) internal: MachOSectionInternal<'data, Mach>,
}

impl<'data, 'file, Mach, R> MachOSection<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn bytes(&self) -> Result<&'data [u8]> {
        let segment_index = self.internal.segment_index;
        let segment = self.file.segment_internal(segment_index)?;
        self.internal
            .section
            .data(self.file.endian, segment.data)
            .read_error(crate::nosym!("Invalid Mach-O section size or offset"))
    }
}

impl<'data, 'file, Mach, R> read::private::Sealed for MachOSection<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Mach, R> ObjectSection<'data> for MachOSection<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    type RelocationIterator = MachORelocationIterator<'data, 'file, Mach, R>;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn index(&self) -> SectionIndex {
        self.internal.index
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        self.internal.section.addr(self.file.endian).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self) -> u64 {
        self.internal.section.size(self.file.endian).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn align(&self) -> u64 {
        let align = self.internal.section.align(self.file.endian);
        if align < 64 {
            1 << align
        } else {
            0
        }
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_range(&self) -> Option<(u64, u64)> {
        self.internal.section.file_range(self.file.endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data(&self) -> Result<&'data [u8]> {
        self.bytes()
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        Ok(read::util::data_range(
            self.bytes()?,
            self.address(),
            address,
            size,
        ))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn compressed_file_range(&self) -> Result<CompressedFileRange> {
        Ok(CompressedFileRange::none(self.file_range()))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        self.data().map(CompressedData::none)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name_bytes(&self) -> Result<&[u8]> {
        Ok(self.internal.section.name())
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<&str> {
        str::from_utf8(self.internal.section.name())
            .ok()
            .read_error(crate::nosym!("Non UTF-8 Mach-O section name"))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segment_name_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(Some(self.internal.section.segment_name()))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segment_name(&self) -> Result<Option<&str>> {
        Ok(Some(
            str::from_utf8(self.internal.section.segment_name())
                .ok()
                .read_error(crate::nosym!("Non UTF-8 Mach-O segment name"))?,
        ))
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> SectionKind {
        self.internal.kind
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn relocations(&self) -> MachORelocationIterator<'data, 'file, Mach, R> {
        MachORelocationIterator {
            file: self.file,
            relocations: self
                .internal
                .section
                .relocations(self.file.endian, self.file.data)
                .unwrap_or(&[])
                .iter(),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> SectionFlags {
        SectionFlags::MachO {
            flags: self.internal.section.flags(self.file.endian),
        }
    }
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy)]
pub(super) struct MachOSectionInternal<'data, Mach: MachHeader> {
    pub index: SectionIndex,
    pub segment_index: usize,
    pub kind: SectionKind,
    pub section: &'data Mach::Section,
}

impl<'data, Mach: MachHeader> MachOSectionInternal<'data, Mach> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub(super) fn parse(
        index: SectionIndex,
        segment_index: usize,
        section: &'data Mach::Section,
    ) -> Self {
        // TODO: we don't validate flags, should we?
        let kind = match (section.segment_name(), section.name()) {
            (b"__TEXT", b"__text") => SectionKind::Text,
            (b"__TEXT", b"__const") => SectionKind::ReadOnlyData,
            (b"__TEXT", b"__cstring") => SectionKind::ReadOnlyString,
            (b"__TEXT", b"__literal4") => SectionKind::ReadOnlyData,
            (b"__TEXT", b"__literal8") => SectionKind::ReadOnlyData,
            (b"__TEXT", b"__literal16") => SectionKind::ReadOnlyData,
            (b"__TEXT", b"__eh_frame") => SectionKind::ReadOnlyData,
            (b"__TEXT", b"__gcc_except_tab") => SectionKind::ReadOnlyData,
            (b"__DATA", b"__data") => SectionKind::Data,
            (b"__DATA", b"__const") => SectionKind::ReadOnlyData,
            (b"__DATA", b"__bss") => SectionKind::UninitializedData,
            (b"__DATA", b"__common") => SectionKind::Common,
            (b"__DATA", b"__thread_data") => SectionKind::Tls,
            (b"__DATA", b"__thread_bss") => SectionKind::UninitializedTls,
            (b"__DATA", b"__thread_vars") => SectionKind::TlsVariables,
            (b"__DWARF", _) => SectionKind::Debug,
            _ => SectionKind::Unknown,
        };
        MachOSectionInternal {
            index,
            segment_index,
            kind,
            section,
        }
    }
}

/// A trait for generic access to `Section32` and `Section64`.
#[allow(missing_docs)]
pub trait Section: DebugPod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sectname(&self) -> &[u8; 16];
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segname(&self) -> &[u8; 16];
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn addr(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn offset(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn align(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn reloff(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn nreloc(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self, endian: Self::Endian) -> u32;

    /// Return the `sectname` bytes up until the null terminator.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> &[u8] {
        let sectname = &self.sectname()[..];
        match memchr::memchr(b'\0', sectname) {
            Some(end) => &sectname[..end],
            None => sectname,
        }
    }

    /// Return the `segname` bytes up until the null terminator.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segment_name(&self) -> &[u8] {
        let segname = &self.segname()[..];
        match memchr::memchr(b'\0', segname) {
            Some(end) => &segname[..end],
            None => segname,
        }
    }

    /// Return the offset and size of the section in the file.
    ///
    /// Returns `None` for sections that have no data in the file.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_range(&self, endian: Self::Endian) -> Option<(u64, u64)> {
        match self.flags(endian) & macho::SECTION_TYPE {
            macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL => None,
            _ => Some((self.offset(endian).into(), self.size(endian).into())),
        }
    }

    /// Return the section data.
    ///
    /// Returns `Ok(&[])` if the section has no data.
    /// Returns `Err` for invalid values.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> result::Result<&'data [u8], ()> {
        if let Some((offset, size)) = self.file_range(endian) {
            data.read_bytes_at(offset, size)
        } else {
            Ok(&[])
        }
    }

    /// Return the relocation array.
    ///
    /// Returns `Err` for invalid values.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn relocations<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> Result<&'data [macho::Relocation<Self::Endian>]> {
        data.read_slice_at(self.reloff(endian).into(), self.nreloc(endian) as usize)
            .read_error(crate::nosym!("Invalid Mach-O relocations offset or number"))
    }
}

impl<Endian: endian::Endian> Section for macho::Section32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sectname(&self) -> &[u8; 16] {
        &self.sectname
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn addr(&self, endian: Self::Endian) -> Self::Word {
        self.addr.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self, endian: Self::Endian) -> Self::Word {
        self.size.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn offset(&self, endian: Self::Endian) -> u32 {
        self.offset.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn align(&self, endian: Self::Endian) -> u32 {
        self.align.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn reloff(&self, endian: Self::Endian) -> u32 {
        self.reloff.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn nreloc(&self, endian: Self::Endian) -> u32 {
        self.nreloc.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> Section for macho::Section64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sectname(&self) -> &[u8; 16] {
        &self.sectname
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn addr(&self, endian: Self::Endian) -> Self::Word {
        self.addr.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self, endian: Self::Endian) -> Self::Word {
        self.size.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn offset(&self, endian: Self::Endian) -> u32 {
        self.offset.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn align(&self, endian: Self::Endian) -> u32 {
        self.align.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn reloff(&self, endian: Self::Endian) -> u32 {
        self.reloff.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn nreloc(&self, endian: Self::Endian) -> u32 {
        self.nreloc.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}
