use core::fmt::Debug;
use core::{result, slice, str};

use crate::macho;
use crate::pod::Pod;
use crate::read::{self, ObjectSegment, ReadError, ReadRef, Result, SegmentFlags};
use crate::{
    endian::{self, Endianness},
    DebugPod,
};

use super::{LoadCommandData, MachHeader, MachOFile, Section};

/// An iterator over the segments of a `MachOFile32`.
pub type MachOSegmentIterator32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSegmentIterator<'data, 'file, macho::MachHeader32<Endian>, R>;
/// An iterator over the segments of a `MachOFile64`.
pub type MachOSegmentIterator64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSegmentIterator<'data, 'file, macho::MachHeader64<Endian>, R>;

/// An iterator over the segments of a `MachOFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct MachOSegmentIterator<'data, 'file, Mach, R = &'data [u8]>
where
    'data: 'file,
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    pub(super) file: &'file MachOFile<'data, Mach, R>,
    pub(super) iter: slice::Iter<'file, MachOSegmentInternal<'data, Mach, R>>,
}

impl<'data, 'file, Mach, R> Iterator for MachOSegmentIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    type Item = MachOSegment<'data, 'file, Mach, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|internal| MachOSegment {
            file: self.file,
            internal,
        })
    }
}

/// A segment of a `MachOFile32`.
pub type MachOSegment32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSegment<'data, 'file, macho::MachHeader32<Endian>, R>;
/// A segment of a `MachOFile64`.
pub type MachOSegment64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSegment<'data, 'file, macho::MachHeader64<Endian>, R>;

/// A segment of a `MachOFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct MachOSegment<'data, 'file, Mach, R = &'data [u8]>
where
    'data: 'file,
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    file: &'file MachOFile<'data, Mach, R>,
    internal: &'file MachOSegmentInternal<'data, Mach, R>,
}

impl<'data, 'file, Mach, R> MachOSegment<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn bytes(&self) -> Result<&'data [u8]> {
        self.internal
            .segment
            .data(self.file.endian, self.file.data)
            .read_error(crate::nosym!("Invalid Mach-O segment size or offset"))
    }
}

impl<'data, 'file, Mach, R> read::private::Sealed for MachOSegment<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Mach, R> ObjectSegment<'data> for MachOSegment<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        self.internal.segment.vmaddr(self.file.endian).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self) -> u64 {
        self.internal.segment.vmsize(self.file.endian).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn align(&self) -> u64 {
        // Page size.
        0x1000
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_range(&self) -> (u64, u64) {
        self.internal.segment.file_range(self.file.endian)
    }

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
    fn name_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(Some(self.internal.segment.name()))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<Option<&str>> {
        Ok(Some(
            str::from_utf8(self.internal.segment.name())
                .ok()
                .read_error(crate::nosym!("Non UTF-8 Mach-O segment name"))?,
        ))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> SegmentFlags {
        let flags = self.internal.segment.flags(self.file.endian);
        let maxprot = self.internal.segment.maxprot(self.file.endian);
        let initprot = self.internal.segment.initprot(self.file.endian);
        SegmentFlags::MachO {
            flags,
            maxprot,
            initprot,
        }
    }
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy)]
pub(super) struct MachOSegmentInternal<'data, Mach: MachHeader, R: ReadRef<'data>> {
    pub data: R,
    pub segment: &'data Mach::Segment,
}

/// A trait for generic access to `SegmentCommand32` and `SegmentCommand64`.
#[allow(missing_docs)]
pub trait Segment: DebugPod {
    type Word: Into<u64>;
    type Endian: endian::Endian;
    type Section: Section<Endian = Self::Endian>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn from_command(command: LoadCommandData<Self::Endian>) -> Result<Option<(&Self, &[u8])>>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn cmd(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn cmdsize(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segname(&self) -> &[u8; 16];
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn vmaddr(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn vmsize(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fileoff(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn filesize(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn maxprot(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn initprot(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn nsects(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self, endian: Self::Endian) -> u32;

    /// Return the `segname` bytes up until the null terminator.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> &[u8] {
        let segname = &self.segname()[..];
        match memchr::memchr(b'\0', segname) {
            Some(end) => &segname[..end],
            None => segname,
        }
    }

    /// Return the offset and size of the segment in the file.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_range(&self, endian: Self::Endian) -> (u64, u64) {
        (self.fileoff(endian).into(), self.filesize(endian).into())
    }

    /// Get the segment data from the file data.
    ///
    /// Returns `Err` for invalid values.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        data: R,
    ) -> result::Result<&'data [u8], ()> {
        let (offset, size) = self.file_range(endian);
        data.read_bytes_at(offset, size)
    }

    /// Get the array of sections from the data following the segment command.
    ///
    /// Returns `Err` for invalid values.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sections<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        section_data: R,
    ) -> Result<&'data [Self::Section]> {
        section_data
            .read_slice_at(0, self.nsects(endian) as usize)
            .read_error(crate::nosym!("Invalid Mach-O number of sections"))
    }
}

impl<Endian: endian::Endian> Segment for macho::SegmentCommand32<Endian> {
    type Word = u32;
    type Endian = Endian;
    type Section = macho::Section32<Self::Endian>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn from_command(command: LoadCommandData<Self::Endian>) -> Result<Option<(&Self, &[u8])>> {
        command.segment_32()
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn cmd(&self, endian: Self::Endian) -> u32 {
        self.cmd.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn cmdsize(&self, endian: Self::Endian) -> u32 {
        self.cmdsize.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn vmaddr(&self, endian: Self::Endian) -> Self::Word {
        self.vmaddr.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn vmsize(&self, endian: Self::Endian) -> Self::Word {
        self.vmsize.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fileoff(&self, endian: Self::Endian) -> Self::Word {
        self.fileoff.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn filesize(&self, endian: Self::Endian) -> Self::Word {
        self.filesize.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn maxprot(&self, endian: Self::Endian) -> u32 {
        self.maxprot.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn initprot(&self, endian: Self::Endian) -> u32 {
        self.initprot.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn nsects(&self, endian: Self::Endian) -> u32 {
        self.nsects.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}

impl<Endian: endian::Endian> Segment for macho::SegmentCommand64<Endian> {
    type Word = u64;
    type Endian = Endian;
    type Section = macho::Section64<Self::Endian>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn from_command(command: LoadCommandData<Self::Endian>) -> Result<Option<(&Self, &[u8])>> {
        command.segment_64()
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn cmd(&self, endian: Self::Endian) -> u32 {
        self.cmd.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn cmdsize(&self, endian: Self::Endian) -> u32 {
        self.cmdsize.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segname(&self) -> &[u8; 16] {
        &self.segname
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn vmaddr(&self, endian: Self::Endian) -> Self::Word {
        self.vmaddr.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn vmsize(&self, endian: Self::Endian) -> Self::Word {
        self.vmsize.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fileoff(&self, endian: Self::Endian) -> Self::Word {
        self.fileoff.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn filesize(&self, endian: Self::Endian) -> Self::Word {
        self.filesize.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn maxprot(&self, endian: Self::Endian) -> u32 {
        self.maxprot.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn initprot(&self, endian: Self::Endian) -> u32 {
        self.initprot.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn nsects(&self, endian: Self::Endian) -> u32 {
        self.nsects.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self, endian: Self::Endian) -> u32 {
        self.flags.get(endian)
    }
}
