use alloc::fmt;
use alloc::vec::Vec;
use core::marker::PhantomData;

#[cfg(feature = "coff")]
use crate::read::coff;
#[cfg(feature = "elf")]
use crate::read::elf;
#[cfg(feature = "macho")]
use crate::read::macho;
#[cfg(feature = "pe")]
use crate::read::pe;
#[cfg(feature = "wasm")]
use crate::read::wasm;
#[cfg(feature = "xcoff")]
use crate::read::xcoff;
use crate::read::{
    self, Architecture, BinaryFormat, CodeView, ComdatKind, CompressedData, CompressedFileRange,
    Error, Export, FileFlags, FileKind, Import, Object, ObjectComdat, ObjectKind, ObjectMap,
    ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, ReadRef, Relocation, Result,
    SectionFlags, SectionIndex, SectionKind, SegmentFlags, SymbolFlags, SymbolIndex, SymbolKind,
    SymbolMap, SymbolMapName, SymbolScope, SymbolSection,
};
#[allow(unused_imports)]
use crate::{AddressSize, Endian, Endianness};

/// Evaluate an expression on the contents of a file format enum.
///
/// This is a hack to avoid virtual calls.
macro_rules! with_inner {
    ($inner:expr, $enum:ident, | $var:ident | $body:expr) => {
        match $inner {
            #[cfg(feature = "coff")]
            $enum::Coff(ref $var) => $body,
            #[cfg(feature = "elf")]
            $enum::Elf32(ref $var) => $body,
            #[cfg(feature = "elf")]
            $enum::Elf64(ref $var) => $body,
            #[cfg(feature = "macho")]
            $enum::MachO32(ref $var) => $body,
            #[cfg(feature = "macho")]
            $enum::MachO64(ref $var) => $body,
            #[cfg(feature = "pe")]
            $enum::Pe32(ref $var) => $body,
            #[cfg(feature = "pe")]
            $enum::Pe64(ref $var) => $body,
            #[cfg(feature = "wasm")]
            $enum::Wasm(ref $var) => $body,
            #[cfg(feature = "xcoff")]
            $enum::Xcoff32(ref $var) => $body,
            #[cfg(feature = "xcoff")]
            $enum::Xcoff64(ref $var) => $body,
        }
    };
}

macro_rules! with_inner_mut {
    ($inner:expr, $enum:ident, | $var:ident | $body:expr) => {
        match $inner {
            #[cfg(feature = "coff")]
            $enum::Coff(ref mut $var) => $body,
            #[cfg(feature = "elf")]
            $enum::Elf32(ref mut $var) => $body,
            #[cfg(feature = "elf")]
            $enum::Elf64(ref mut $var) => $body,
            #[cfg(feature = "macho")]
            $enum::MachO32(ref mut $var) => $body,
            #[cfg(feature = "macho")]
            $enum::MachO64(ref mut $var) => $body,
            #[cfg(feature = "pe")]
            $enum::Pe32(ref mut $var) => $body,
            #[cfg(feature = "pe")]
            $enum::Pe64(ref mut $var) => $body,
            #[cfg(feature = "wasm")]
            $enum::Wasm(ref mut $var) => $body,
            #[cfg(feature = "xcoff")]
            $enum::Xcoff32(ref mut $var) => $body,
            #[cfg(feature = "xcoff")]
            $enum::Xcoff64(ref mut $var) => $body,
        }
    };
}

/// Like `with_inner!`, but wraps the result in another enum.
macro_rules! map_inner {
    ($inner:expr, $from:ident, $to:ident, | $var:ident | $body:expr) => {
        match $inner {
            #[cfg(feature = "coff")]
            $from::Coff(ref $var) => $to::Coff($body),
            #[cfg(feature = "elf")]
            $from::Elf32(ref $var) => $to::Elf32($body),
            #[cfg(feature = "elf")]
            $from::Elf64(ref $var) => $to::Elf64($body),
            #[cfg(feature = "macho")]
            $from::MachO32(ref $var) => $to::MachO32($body),
            #[cfg(feature = "macho")]
            $from::MachO64(ref $var) => $to::MachO64($body),
            #[cfg(feature = "pe")]
            $from::Pe32(ref $var) => $to::Pe32($body),
            #[cfg(feature = "pe")]
            $from::Pe64(ref $var) => $to::Pe64($body),
            #[cfg(feature = "wasm")]
            $from::Wasm(ref $var) => $to::Wasm($body),
            #[cfg(feature = "xcoff")]
            $from::Xcoff32(ref $var) => $to::Xcoff32($body),
            #[cfg(feature = "xcoff")]
            $from::Xcoff64(ref $var) => $to::Xcoff64($body),
        }
    };
}

/// Like `map_inner!`, but the result is a Result or Option.
macro_rules! map_inner_option {
    ($inner:expr, $from:ident, $to:ident, | $var:ident | $body:expr) => {
        match $inner {
            #[cfg(feature = "coff")]
            $from::Coff(ref $var) => $body.map($to::Coff),
            #[cfg(feature = "elf")]
            $from::Elf32(ref $var) => $body.map($to::Elf32),
            #[cfg(feature = "elf")]
            $from::Elf64(ref $var) => $body.map($to::Elf64),
            #[cfg(feature = "macho")]
            $from::MachO32(ref $var) => $body.map($to::MachO32),
            #[cfg(feature = "macho")]
            $from::MachO64(ref $var) => $body.map($to::MachO64),
            #[cfg(feature = "pe")]
            $from::Pe32(ref $var) => $body.map($to::Pe32),
            #[cfg(feature = "pe")]
            $from::Pe64(ref $var) => $body.map($to::Pe64),
            #[cfg(feature = "wasm")]
            $from::Wasm(ref $var) => $body.map($to::Wasm),
            #[cfg(feature = "xcoff")]
            $from::Xcoff32(ref $var) => $body.map($to::Xcoff32),
            #[cfg(feature = "xcoff")]
            $from::Xcoff64(ref $var) => $body.map($to::Xcoff64),
        }
    };
}

macro_rules! map_inner_option_mut {
    ($inner:expr, $from:ident, $to:ident, | $var:ident | $body:expr) => {
        match $inner {
            #[cfg(feature = "coff")]
            $from::Coff(ref mut $var) => $body.map($to::Coff),
            #[cfg(feature = "elf")]
            $from::Elf32(ref mut $var) => $body.map($to::Elf32),
            #[cfg(feature = "elf")]
            $from::Elf64(ref mut $var) => $body.map($to::Elf64),
            #[cfg(feature = "macho")]
            $from::MachO32(ref mut $var) => $body.map($to::MachO32),
            #[cfg(feature = "macho")]
            $from::MachO64(ref mut $var) => $body.map($to::MachO64),
            #[cfg(feature = "pe")]
            $from::Pe32(ref mut $var) => $body.map($to::Pe32),
            #[cfg(feature = "pe")]
            $from::Pe64(ref mut $var) => $body.map($to::Pe64),
            #[cfg(feature = "wasm")]
            $from::Wasm(ref mut $var) => $body.map($to::Wasm),
            #[cfg(feature = "xcoff")]
            $from::Xcoff32(ref mut $var) => $body.map($to::Xcoff32),
            #[cfg(feature = "xcoff")]
            $from::Xcoff64(ref mut $var) => $body.map($to::Xcoff64),
        }
    };
}

/// Call `next` for a file format iterator.
macro_rules! next_inner {
    ($inner:expr, $from:ident, $to:ident) => {
        match $inner {
            #[cfg(feature = "coff")]
            $from::Coff(ref mut iter) => iter.next().map($to::Coff),
            #[cfg(feature = "elf")]
            $from::Elf32(ref mut iter) => iter.next().map($to::Elf32),
            #[cfg(feature = "elf")]
            $from::Elf64(ref mut iter) => iter.next().map($to::Elf64),
            #[cfg(feature = "macho")]
            $from::MachO32(ref mut iter) => iter.next().map($to::MachO32),
            #[cfg(feature = "macho")]
            $from::MachO64(ref mut iter) => iter.next().map($to::MachO64),
            #[cfg(feature = "pe")]
            $from::Pe32(ref mut iter) => iter.next().map($to::Pe32),
            #[cfg(feature = "pe")]
            $from::Pe64(ref mut iter) => iter.next().map($to::Pe64),
            #[cfg(feature = "wasm")]
            $from::Wasm(ref mut iter) => iter.next().map($to::Wasm),
            #[cfg(feature = "xcoff")]
            $from::Xcoff32(ref mut iter) => iter.next().map($to::Xcoff32),
            #[cfg(feature = "xcoff")]
            $from::Xcoff64(ref mut iter) => iter.next().map($to::Xcoff64),
        }
    };
}

/// An object file.
///
/// Most functionality is provided by the `Object` trait implementation.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct File<'data, R: ReadRef<'data> = &'data [u8]> {
    inner: FileInternal<'data, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum FileInternal<'data, R: ReadRef<'data>> {
    #[cfg(feature = "coff")]
    Coff(coff::CoffFile<'data, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfFile32<'data, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfFile64<'data, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOFile32<'data, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOFile64<'data, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeFile32<'data, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeFile64<'data, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmFile<'data, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffFile32<'data, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffFile64<'data, R>),
}

impl<'data, R: ReadRef<'data>> File<'data, R> {
    /// Parse the raw file data.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse(data: R) -> Result<Self> {
        let inner = match FileKind::parse(data)? {
            #[cfg(feature = "elf")]
            FileKind::Elf32 => FileInternal::Elf32(elf::ElfFile32::parse(data)?),
            #[cfg(feature = "elf")]
            FileKind::Elf64 => FileInternal::Elf64(elf::ElfFile64::parse(data)?),
            #[cfg(feature = "macho")]
            FileKind::MachO32 => FileInternal::MachO32(macho::MachOFile32::parse(data)?),
            #[cfg(feature = "macho")]
            FileKind::MachO64 => FileInternal::MachO64(macho::MachOFile64::parse(data)?),
            #[cfg(feature = "wasm")]
            FileKind::Wasm => FileInternal::Wasm(wasm::WasmFile::parse(data)?),
            #[cfg(feature = "pe")]
            FileKind::Pe32 => FileInternal::Pe32(pe::PeFile32::parse(data)?),
            #[cfg(feature = "pe")]
            FileKind::Pe64 => FileInternal::Pe64(pe::PeFile64::parse(data)?),
            #[cfg(feature = "coff")]
            FileKind::Coff => FileInternal::Coff(coff::CoffFile::parse(data)?),
            #[cfg(feature = "xcoff")]
            FileKind::Xcoff32 => FileInternal::Xcoff32(xcoff::XcoffFile32::parse(data)?),
            #[cfg(feature = "xcoff")]
            FileKind::Xcoff64 => FileInternal::Xcoff64(xcoff::XcoffFile64::parse(data)?),
            #[allow(unreachable_patterns)]
            _ => return Err(Error(crate::nosym!("Unsupported file format"))),
        };
        Ok(File { inner })
    }

    /// Parse a Mach-O image from the dyld shared cache.
    #[cfg(feature = "macho")]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse_dyld_cache_image<'cache, E: Endian>(
        image: &macho::DyldCacheImage<'data, 'cache, E, R>,
    ) -> Result<Self> {
        let inner = match image.cache.architecture().address_size() {
            Some(AddressSize::U64) => {
                FileInternal::MachO64(macho::MachOFile64::parse_dyld_cache_image(image)?)
            }
            Some(AddressSize::U32) => {
                FileInternal::MachO32(macho::MachOFile32::parse_dyld_cache_image(image)?)
            }
            _ => return Err(Error(crate::nosym!("Unsupported file format"))),
        };
        Ok(File { inner })
    }

    /// Return the file format.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn format(&self) -> BinaryFormat {
        match self.inner {
            #[cfg(feature = "coff")]
            FileInternal::Coff(_) => BinaryFormat::Coff,
            #[cfg(feature = "elf")]
            FileInternal::Elf32(_) | FileInternal::Elf64(_) => BinaryFormat::Elf,
            #[cfg(feature = "macho")]
            FileInternal::MachO32(_) | FileInternal::MachO64(_) => BinaryFormat::MachO,
            #[cfg(feature = "pe")]
            FileInternal::Pe32(_) | FileInternal::Pe64(_) => BinaryFormat::Pe,
            #[cfg(feature = "wasm")]
            FileInternal::Wasm(_) => BinaryFormat::Wasm,
            #[cfg(feature = "xcoff")]
            FileInternal::Xcoff32(_) | FileInternal::Xcoff64(_) => BinaryFormat::Xcoff,
        }
    }
}

impl<'data, R: ReadRef<'data>> read::private::Sealed for File<'data, R> {}

impl<'data, 'file, R> Object<'data, 'file> for File<'data, R>
where
    'data: 'file,
    R: 'file + ReadRef<'data>,
{
    type Segment = Segment<'data, 'file, R>;
    type SegmentIterator = SegmentIterator<'data, 'file, R>;
    type Section = Section<'data, 'file, R>;
    type SectionIterator = SectionIterator<'data, 'file, R>;
    type Comdat = Comdat<'data, 'file, R>;
    type ComdatIterator = ComdatIterator<'data, 'file, R>;
    type Symbol = Symbol<'data, 'file, R>;
    type SymbolIterator = SymbolIterator<'data, 'file, R>;
    type SymbolTable = SymbolTable<'data, 'file, R>;
    type DynamicRelocationIterator = DynamicRelocationIterator<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn architecture(&self) -> Architecture {
        with_inner!(self.inner, FileInternal, |x| x.architecture())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_little_endian(&self) -> bool {
        with_inner!(self.inner, FileInternal, |x| x.is_little_endian())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_64(&self) -> bool {
        with_inner!(self.inner, FileInternal, |x| x.is_64())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> ObjectKind {
        with_inner!(self.inner, FileInternal, |x| x.kind())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segments(&'file self) -> SegmentIterator<'data, 'file, R> {
        SegmentIterator {
            inner: map_inner!(self.inner, FileInternal, SegmentIteratorInternal, |x| x
                .segments()),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_by_name_bytes(&'file self, section_name: &[u8]) -> Option<Section<'data, 'file, R>> {
        map_inner_option!(self.inner, FileInternal, SectionInternal, |x| x
            .section_by_name_bytes(section_name))
        .map(|inner| Section { inner })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section_by_index(&'file self, index: SectionIndex) -> Result<Section<'data, 'file, R>> {
        map_inner_option!(self.inner, FileInternal, SectionInternal, |x| x
            .section_by_index(index))
        .map(|inner| Section { inner })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sections(&'file self) -> SectionIterator<'data, 'file, R> {
        SectionIterator {
            inner: map_inner!(self.inner, FileInternal, SectionIteratorInternal, |x| x
                .sections()),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn comdats(&'file self) -> ComdatIterator<'data, 'file, R> {
        ComdatIterator {
            inner: map_inner!(self.inner, FileInternal, ComdatIteratorInternal, |x| x
                .comdats()),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol_by_index(&'file self, index: SymbolIndex) -> Result<Symbol<'data, 'file, R>> {
        map_inner_option!(self.inner, FileInternal, SymbolInternal, |x| x
            .symbol_by_index(index)
            .map(|x| (x, PhantomData)))
        .map(|inner| Symbol { inner })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbols(&'file self) -> SymbolIterator<'data, 'file, R> {
        SymbolIterator {
            inner: map_inner!(self.inner, FileInternal, SymbolIteratorInternal, |x| (
                x.symbols(),
                PhantomData
            )),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol_table(&'file self) -> Option<SymbolTable<'data, 'file, R>> {
        map_inner_option!(self.inner, FileInternal, SymbolTableInternal, |x| x
            .symbol_table()
            .map(|x| (x, PhantomData)))
        .map(|inner| SymbolTable { inner })
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_symbols(&'file self) -> SymbolIterator<'data, 'file, R> {
        SymbolIterator {
            inner: map_inner!(self.inner, FileInternal, SymbolIteratorInternal, |x| (
                x.dynamic_symbols(),
                PhantomData
            )),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_symbol_table(&'file self) -> Option<SymbolTable<'data, 'file, R>> {
        map_inner_option!(self.inner, FileInternal, SymbolTableInternal, |x| x
            .dynamic_symbol_table()
            .map(|x| (x, PhantomData)))
        .map(|inner| SymbolTable { inner })
    }

    #[cfg(feature = "elf")]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_relocations(&'file self) -> Option<DynamicRelocationIterator<'data, 'file, R>> {
        let inner = match self.inner {
            FileInternal::Elf32(ref elf) => {
                DynamicRelocationIteratorInternal::Elf32(elf.dynamic_relocations()?)
            }
            FileInternal::Elf64(ref elf) => {
                DynamicRelocationIteratorInternal::Elf64(elf.dynamic_relocations()?)
            }
            #[allow(unreachable_patterns)]
            _ => return None,
        };
        Some(DynamicRelocationIterator { inner })
    }

    #[cfg(not(feature = "elf"))]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn dynamic_relocations(&'file self) -> Option<DynamicRelocationIterator<'data, 'file, R>> {
        None
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol_map(&self) -> SymbolMap<SymbolMapName<'data>> {
        with_inner!(self.inner, FileInternal, |x| x.symbol_map())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn object_map(&self) -> ObjectMap<'data> {
        with_inner!(self.inner, FileInternal, |x| x.object_map())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn imports(&self) -> Result<Vec<Import<'data>>> {
        with_inner!(self.inner, FileInternal, |x| x.imports())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn exports(&self) -> Result<Vec<Export<'data>>> {
        with_inner!(self.inner, FileInternal, |x| x.exports())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn has_debug_symbols(&self) -> bool {
        with_inner!(self.inner, FileInternal, |x| x.has_debug_symbols())
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn mach_uuid(&self) -> Result<Option<[u8; 16]>> {
        with_inner!(self.inner, FileInternal, |x| x.mach_uuid())
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn build_id(&self) -> Result<Option<&'data [u8]>> {
        with_inner!(self.inner, FileInternal, |x| x.build_id())
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn gnu_debuglink(&self) -> Result<Option<(&'data [u8], u32)>> {
        with_inner!(self.inner, FileInternal, |x| x.gnu_debuglink())
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn gnu_debugaltlink(&self) -> Result<Option<(&'data [u8], &'data [u8])>> {
        with_inner!(self.inner, FileInternal, |x| x.gnu_debugaltlink())
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn pdb_info(&self) -> Result<Option<CodeView>> {
        with_inner!(self.inner, FileInternal, |x| x.pdb_info())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn relative_address_base(&self) -> u64 {
        with_inner!(self.inner, FileInternal, |x| x.relative_address_base())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn entry(&self) -> u64 {
        with_inner!(self.inner, FileInternal, |x| x.entry())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> FileFlags {
        with_inner!(self.inner, FileInternal, |x| x.flags())
    }
}

/// An iterator over the segments of a `File`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct SegmentIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: SegmentIteratorInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum SegmentIteratorInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffSegmentIterator<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfSegmentIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfSegmentIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOSegmentIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOSegmentIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeSegmentIterator32<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeSegmentIterator64<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmSegmentIterator<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffSegmentIterator32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffSegmentIterator64<'data, 'file, R>),
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for SegmentIterator<'data, 'file, R> {
    type Item = Segment<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        next_inner!(self.inner, SegmentIteratorInternal, SegmentInternal)
            .map(|inner| Segment { inner })
    }
}

/// A segment of a `File`.

pub struct Segment<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: SegmentInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum SegmentInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffSegment<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfSegment32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfSegment64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOSegment32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOSegment64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeSegment32<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeSegment64<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmSegment<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffSegment32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffSegment64<'data, 'file, R>),
}

impl<'data, 'file, R: ReadRef<'data>> fmt::Debug for Segment<'data, 'file, R> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // It's painful to do much better than this
        let mut s = f.debug_struct("Segment");
        match self.name() {
            Ok(Some(ref name)) => {
                s.field("name", name);
            }
            Ok(None) => {}
            Err(_) => {
                s.field("name", &"<invalid>");
            }
        }
        s.field("address", &self.address())
            .field("size", &self.size())
            .finish()
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for Segment<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for Segment<'data, 'file, R> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        with_inner!(self.inner, SegmentInternal, |x| x.address())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self) -> u64 {
        with_inner!(self.inner, SegmentInternal, |x| x.size())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn align(&self) -> u64 {
        with_inner!(self.inner, SegmentInternal, |x| x.align())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_range(&self) -> (u64, u64) {
        with_inner!(self.inner, SegmentInternal, |x| x.file_range())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data(&self) -> Result<&'data [u8]> {
        with_inner!(self.inner, SegmentInternal, |x| x.data())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        with_inner!(self.inner, SegmentInternal, |x| x.data_range(address, size))
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name_bytes(&self) -> Result<Option<&[u8]>> {
        with_inner!(self.inner, SegmentInternal, |x| x.name_bytes())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<Option<&str>> {
        with_inner!(self.inner, SegmentInternal, |x| x.name())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> SegmentFlags {
        with_inner!(self.inner, SegmentInternal, |x| x.flags())
    }
}

/// An iterator of the sections of a `File`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct SectionIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: SectionIteratorInternal<'data, 'file, R>,
}

// we wrap our enums in a struct so that they are kept private.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum SectionIteratorInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffSectionIterator<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfSectionIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfSectionIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOSectionIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOSectionIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeSectionIterator32<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeSectionIterator64<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmSectionIterator<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffSectionIterator32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffSectionIterator64<'data, 'file, R>),
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for SectionIterator<'data, 'file, R> {
    type Item = Section<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        next_inner!(self.inner, SectionIteratorInternal, SectionInternal)
            .map(|inner| Section { inner })
    }
}

/// A Section of a File

pub struct Section<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: SectionInternal<'data, 'file, R>,
}

enum SectionInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffSection<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfSection32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfSection64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOSection32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOSection64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeSection32<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeSection64<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmSection<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffSection32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffSection64<'data, 'file, R>),
}

#[cfg(not(feature = "nosym"))]
impl<'data, 'file, R: ReadRef<'data>> fmt::Debug for Section<'data, 'file, R> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // It's painful to do much better than this
        let mut s = f.debug_struct("Section");
        match self.segment_name() {
            Ok(Some(ref name)) => {
                s.field("segment", name);
            }
            Ok(None) => {}
            Err(_) => {
                s.field("segment", &"<invalid>");
            }
        }
        s.field("name", &self.name().unwrap_or("<invalid>"))
            .field("address", &self.address())
            .field("size", &self.size())
            .field("align", &self.align())
            .field("kind", &self.kind())
            .field("flags", &self.flags())
            .finish()
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for Section<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSection<'data> for Section<'data, 'file, R> {
    type RelocationIterator = SectionRelocationIterator<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn index(&self) -> SectionIndex {
        with_inner!(self.inner, SectionInternal, |x| x.index())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        with_inner!(self.inner, SectionInternal, |x| x.address())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self) -> u64 {
        with_inner!(self.inner, SectionInternal, |x| x.size())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn align(&self) -> u64 {
        with_inner!(self.inner, SectionInternal, |x| x.align())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn file_range(&self) -> Option<(u64, u64)> {
        with_inner!(self.inner, SectionInternal, |x| x.file_range())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data(&self) -> Result<&'data [u8]> {
        with_inner!(self.inner, SectionInternal, |x| x.data())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        with_inner!(self.inner, SectionInternal, |x| x.data_range(address, size))
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn compressed_file_range(&self) -> Result<CompressedFileRange> {
        with_inner!(self.inner, SectionInternal, |x| x.compressed_file_range())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        with_inner!(self.inner, SectionInternal, |x| x.compressed_data())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name_bytes(&self) -> Result<&[u8]> {
        with_inner!(self.inner, SectionInternal, |x| x.name_bytes())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<&str> {
        with_inner!(self.inner, SectionInternal, |x| x.name())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segment_name_bytes(&self) -> Result<Option<&[u8]>> {
        with_inner!(self.inner, SectionInternal, |x| x.segment_name_bytes())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn segment_name(&self) -> Result<Option<&str>> {
        with_inner!(self.inner, SectionInternal, |x| x.segment_name())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> SectionKind {
        with_inner!(self.inner, SectionInternal, |x| x.kind())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn relocations(&self) -> SectionRelocationIterator<'data, 'file, R> {
        SectionRelocationIterator {
            inner: map_inner!(
                self.inner,
                SectionInternal,
                SectionRelocationIteratorInternal,
                |x| x.relocations()
            ),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> SectionFlags {
        with_inner!(self.inner, SectionInternal, |x| x.flags())
    }
}

/// An iterator of the COMDAT section groups of a `File`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct ComdatIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: ComdatIteratorInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum ComdatIteratorInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffComdatIterator<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfComdatIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfComdatIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOComdatIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOComdatIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeComdatIterator32<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeComdatIterator64<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmComdatIterator<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffComdatIterator32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffComdatIterator64<'data, 'file, R>),
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for ComdatIterator<'data, 'file, R> {
    type Item = Comdat<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        next_inner!(self.inner, ComdatIteratorInternal, ComdatInternal)
            .map(|inner| Comdat { inner })
    }
}

/// A COMDAT section group of a `File`.

pub struct Comdat<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: ComdatInternal<'data, 'file, R>,
}

enum ComdatInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffComdat<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfComdat32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfComdat64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOComdat32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOComdat64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeComdat32<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeComdat64<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmComdat<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffComdat32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffComdat64<'data, 'file, R>),
}

#[cfg(not(feature = "nosym"))]
impl<'data, 'file, R: ReadRef<'data>> fmt::Debug for Comdat<'data, 'file, R> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Comdat");
        s.field("symbol", &self.symbol())
            .field("name", &self.name().unwrap_or("<invalid>"))
            .field("kind", &self.kind())
            .finish()
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for Comdat<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectComdat<'data> for Comdat<'data, 'file, R> {
    type SectionIterator = ComdatSectionIterator<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> ComdatKind {
        with_inner!(self.inner, ComdatInternal, |x| x.kind())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol(&self) -> SymbolIndex {
        with_inner!(self.inner, ComdatInternal, |x| x.symbol())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name_bytes(&self) -> Result<&[u8]> {
        with_inner!(self.inner, ComdatInternal, |x| x.name_bytes())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<&str> {
        with_inner!(self.inner, ComdatInternal, |x| x.name())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn sections(&self) -> ComdatSectionIterator<'data, 'file, R> {
        ComdatSectionIterator {
            inner: map_inner!(
                self.inner,
                ComdatInternal,
                ComdatSectionIteratorInternal,
                |x| x.sections()
            ),
        }
    }
}

/// An iterator over COMDAT section entries.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct ComdatSectionIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: ComdatSectionIteratorInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum ComdatSectionIteratorInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffComdatSectionIterator<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfComdatSectionIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfComdatSectionIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachOComdatSectionIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachOComdatSectionIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeComdatSectionIterator32<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeComdatSectionIterator64<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmComdatSectionIterator<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffComdatSectionIterator32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffComdatSectionIterator64<'data, 'file, R>),
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for ComdatSectionIterator<'data, 'file, R> {
    type Item = SectionIndex;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        with_inner_mut!(self.inner, ComdatSectionIteratorInternal, |x| x.next())
    }
}

/// A symbol table.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct SymbolTable<'data, 'file, R = &'data [u8]>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    inner: SymbolTableInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum SymbolTableInternal<'data, 'file, R>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    #[cfg(feature = "coff")]
    Coff((coff::CoffSymbolTable<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "elf")]
    Elf32(
        (
            elf::ElfSymbolTable32<'data, 'file, Endianness, R>,
            PhantomData<R>,
        ),
    ),
    #[cfg(feature = "elf")]
    Elf64(
        (
            elf::ElfSymbolTable64<'data, 'file, Endianness, R>,
            PhantomData<R>,
        ),
    ),
    #[cfg(feature = "macho")]
    MachO32(
        (
            macho::MachOSymbolTable32<'data, 'file, Endianness, R>,
            PhantomData<()>,
        ),
    ),
    #[cfg(feature = "macho")]
    MachO64(
        (
            macho::MachOSymbolTable64<'data, 'file, Endianness, R>,
            PhantomData<()>,
        ),
    ),
    #[cfg(feature = "pe")]
    Pe32((coff::CoffSymbolTable<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "pe")]
    Pe64((coff::CoffSymbolTable<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "wasm")]
    Wasm((wasm::WasmSymbolTable<'data, 'file>, PhantomData<R>)),
    #[cfg(feature = "xcoff")]
    Xcoff32((xcoff::XcoffSymbolTable32<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "xcoff")]
    Xcoff64((xcoff::XcoffSymbolTable64<'data, 'file, R>, PhantomData<R>)),
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for SymbolTable<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSymbolTable<'data> for SymbolTable<'data, 'file, R> {
    type Symbol = Symbol<'data, 'file, R>;
    type SymbolIterator = SymbolIterator<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbols(&self) -> Self::SymbolIterator {
        SymbolIterator {
            inner: map_inner!(
                self.inner,
                SymbolTableInternal,
                SymbolIteratorInternal,
                |x| (x.0.symbols(), PhantomData)
            ),
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        map_inner_option!(self.inner, SymbolTableInternal, SymbolInternal, |x| x
            .0
            .symbol_by_index(index)
            .map(|x| (x, PhantomData)))
        .map(|inner| Symbol { inner })
    }
}

/// An iterator over symbol table entries.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct SymbolIterator<'data, 'file, R = &'data [u8]>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    inner: SymbolIteratorInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum SymbolIteratorInternal<'data, 'file, R>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    #[cfg(feature = "coff")]
    Coff((coff::CoffSymbolIterator<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "elf")]
    Elf32(
        (
            elf::ElfSymbolIterator32<'data, 'file, Endianness, R>,
            PhantomData<R>,
        ),
    ),
    #[cfg(feature = "elf")]
    Elf64(
        (
            elf::ElfSymbolIterator64<'data, 'file, Endianness, R>,
            PhantomData<R>,
        ),
    ),
    #[cfg(feature = "macho")]
    MachO32(
        (
            macho::MachOSymbolIterator32<'data, 'file, Endianness, R>,
            PhantomData<()>,
        ),
    ),
    #[cfg(feature = "macho")]
    MachO64(
        (
            macho::MachOSymbolIterator64<'data, 'file, Endianness, R>,
            PhantomData<()>,
        ),
    ),
    #[cfg(feature = "pe")]
    Pe32((coff::CoffSymbolIterator<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "pe")]
    Pe64((coff::CoffSymbolIterator<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "wasm")]
    Wasm((wasm::WasmSymbolIterator<'data, 'file>, PhantomData<R>)),
    #[cfg(feature = "xcoff")]
    Xcoff32(
        (
            xcoff::XcoffSymbolIterator32<'data, 'file, R>,
            PhantomData<R>,
        ),
    ),
    #[cfg(feature = "xcoff")]
    Xcoff64(
        (
            xcoff::XcoffSymbolIterator64<'data, 'file, R>,
            PhantomData<R>,
        ),
    ),
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for SymbolIterator<'data, 'file, R> {
    type Item = Symbol<'data, 'file, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        map_inner_option_mut!(self.inner, SymbolIteratorInternal, SymbolInternal, |iter| {
            iter.0.next().map(|x| (x, PhantomData))
        })
        .map(|inner| Symbol { inner })
    }
}

/// A symbol table entry.

pub struct Symbol<'data, 'file, R = &'data [u8]>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    inner: SymbolInternal<'data, 'file, R>,
}

enum SymbolInternal<'data, 'file, R>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    #[cfg(feature = "coff")]
    Coff((coff::CoffSymbol<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "elf")]
    Elf32(
        (
            elf::ElfSymbol32<'data, 'file, Endianness, R>,
            PhantomData<R>,
        ),
    ),
    #[cfg(feature = "elf")]
    Elf64(
        (
            elf::ElfSymbol64<'data, 'file, Endianness, R>,
            PhantomData<R>,
        ),
    ),
    #[cfg(feature = "macho")]
    MachO32(
        (
            macho::MachOSymbol32<'data, 'file, Endianness, R>,
            PhantomData<()>,
        ),
    ),
    #[cfg(feature = "macho")]
    MachO64(
        (
            macho::MachOSymbol64<'data, 'file, Endianness, R>,
            PhantomData<()>,
        ),
    ),
    #[cfg(feature = "pe")]
    Pe32((coff::CoffSymbol<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "pe")]
    Pe64((coff::CoffSymbol<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "wasm")]
    Wasm((wasm::WasmSymbol<'data, 'file>, PhantomData<R>)),
    #[cfg(feature = "xcoff")]
    Xcoff32((xcoff::XcoffSymbol32<'data, 'file, R>, PhantomData<R>)),
    #[cfg(feature = "xcoff")]
    Xcoff64((xcoff::XcoffSymbol64<'data, 'file, R>, PhantomData<R>)),
}

#[cfg(not(feature = "nosym"))]
impl<'data, 'file, R: ReadRef<'data>> fmt::Debug for Symbol<'data, 'file, R> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Symbol")
            .field("name", &self.name().unwrap_or("<invalid>"))
            .field("address", &self.address())
            .field("size", &self.size())
            .field("kind", &self.kind())
            .field("section", &self.section())
            .field("scope", &self.scope())
            .field("weak", &self.is_weak())
            .field("flags", &self.flags())
            .finish()
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for Symbol<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSymbol<'data> for Symbol<'data, 'file, R> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn index(&self) -> SymbolIndex {
        with_inner!(self.inner, SymbolInternal, |x| x.0.index())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name_bytes(&self) -> Result<&'data [u8]> {
        with_inner!(self.inner, SymbolInternal, |x| x.0.name_bytes())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<&'data str> {
        with_inner!(self.inner, SymbolInternal, |x| x.0.name())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        with_inner!(self.inner, SymbolInternal, |x| x.0.address())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self) -> u64 {
        with_inner!(self.inner, SymbolInternal, |x| x.0.size())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> SymbolKind {
        with_inner!(self.inner, SymbolInternal, |x| x.0.kind())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section(&self) -> SymbolSection {
        with_inner!(self.inner, SymbolInternal, |x| x.0.section())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_undefined(&self) -> bool {
        with_inner!(self.inner, SymbolInternal, |x| x.0.is_undefined())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_definition(&self) -> bool {
        with_inner!(self.inner, SymbolInternal, |x| x.0.is_definition())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_common(&self) -> bool {
        with_inner!(self.inner, SymbolInternal, |x| x.0.is_common())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_weak(&self) -> bool {
        with_inner!(self.inner, SymbolInternal, |x| x.0.is_weak())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn scope(&self) -> SymbolScope {
        with_inner!(self.inner, SymbolInternal, |x| x.0.scope())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_global(&self) -> bool {
        with_inner!(self.inner, SymbolInternal, |x| x.0.is_global())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_local(&self) -> bool {
        with_inner!(self.inner, SymbolInternal, |x| x.0.is_local())
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> SymbolFlags<SectionIndex> {
        with_inner!(self.inner, SymbolInternal, |x| x.0.flags())
    }
}

/// An iterator over dynamic relocation entries.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct DynamicRelocationIterator<'data, 'file, R = &'data [u8]>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    inner: DynamicRelocationIteratorInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum DynamicRelocationIteratorInternal<'data, 'file, R>
where
    'data: 'file,
    R: ReadRef<'data>,
{
    #[cfg(feature = "elf")]
    Elf32(elf::ElfDynamicRelocationIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfDynamicRelocationIterator64<'data, 'file, Endianness, R>),
    // We need to always use the lifetime parameters.
    #[allow(unused)]
    None(PhantomData<(&'data (), &'file (), R)>),
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for DynamicRelocationIterator<'data, 'file, R> {
    type Item = (u64, Relocation);

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            #[cfg(feature = "elf")]
            DynamicRelocationIteratorInternal::Elf32(ref mut elf) => elf.next(),
            #[cfg(feature = "elf")]
            DynamicRelocationIteratorInternal::Elf64(ref mut elf) => elf.next(),
            DynamicRelocationIteratorInternal::None(_) => None,
        }
    }
}

/// An iterator over section relocation entries.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct SectionRelocationIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]>
where
    'data: 'file,
{
    inner: SectionRelocationIteratorInternal<'data, 'file, R>,
}

#[cfg_attr(not(feature = "nosym"), derive(Debug))]

enum SectionRelocationIteratorInternal<'data, 'file, R: ReadRef<'data>>
where
    'data: 'file,
{
    #[cfg(feature = "coff")]
    Coff(coff::CoffRelocationIterator<'data, 'file, R>),
    #[cfg(feature = "elf")]
    Elf32(elf::ElfSectionRelocationIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "elf")]
    Elf64(elf::ElfSectionRelocationIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO32(macho::MachORelocationIterator32<'data, 'file, Endianness, R>),
    #[cfg(feature = "macho")]
    MachO64(macho::MachORelocationIterator64<'data, 'file, Endianness, R>),
    #[cfg(feature = "pe")]
    Pe32(pe::PeRelocationIterator<'data, 'file, R>),
    #[cfg(feature = "pe")]
    Pe64(pe::PeRelocationIterator<'data, 'file, R>),
    #[cfg(feature = "wasm")]
    Wasm(wasm::WasmRelocationIterator<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff32(xcoff::XcoffRelocationIterator32<'data, 'file, R>),
    #[cfg(feature = "xcoff")]
    Xcoff64(xcoff::XcoffRelocationIterator64<'data, 'file, R>),
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for SectionRelocationIterator<'data, 'file, R> {
    type Item = (u64, Relocation);

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        with_inner_mut!(self.inner, SectionRelocationIteratorInternal, |x| x.next())
    }
}
