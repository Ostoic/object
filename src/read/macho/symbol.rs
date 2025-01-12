use alloc::vec::Vec;
use core::fmt::Debug;
use core::{fmt, slice, str};

use crate::macho;
use crate::pod::Pod;
use crate::read::util::StringTable;
use crate::read::{
    self, ObjectMap, ObjectMapEntry, ObjectSymbol, ObjectSymbolTable, ReadError, ReadRef, Result,
    SectionIndex, SectionKind, SymbolFlags, SymbolIndex, SymbolKind, SymbolMap, SymbolMapEntry,
    SymbolScope, SymbolSection,
};
use crate::{
    endian::{self, Endianness},
    DebugPod,
};

use super::{MachHeader, MachOFile};

/// A table of symbol entries in a Mach-O file.
///
/// Also includes the string table used for the symbol names.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy)]

pub struct SymbolTable<'data, Mach: MachHeader, R = &'data [u8]>
where
    R: ReadRef<'data>,
{
    symbols: &'data [Mach::Nlist],
    strings: StringTable<'data, R>,
}

impl<'data, Mach: MachHeader, R: ReadRef<'data>> Default for SymbolTable<'data, Mach, R> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn default() -> Self {
        SymbolTable {
            symbols: &[],
            strings: Default::default(),
        }
    }
}

impl<'data, Mach: MachHeader, R: ReadRef<'data>> SymbolTable<'data, Mach, R> {
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub(super) fn new(symbols: &'data [Mach::Nlist], strings: StringTable<'data, R>) -> Self {
        SymbolTable { symbols, strings }
    }

    /// Return the string table used for the symbol names.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn strings(&self) -> StringTable<'data, R> {
        self.strings
    }

    /// Iterate over the symbols.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn iter(&self) -> slice::Iter<'data, Mach::Nlist> {
        self.symbols.iter()
    }

    /// Return true if the symbol table is empty.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// The number of symbols.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Return the symbol at the given index.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn symbol(&self, index: usize) -> Result<&'data Mach::Nlist> {
        self.symbols
            .get(index)
            .read_error(crate::nosym!("Invalid Mach-O symbol index"))
    }

    /// Construct a map from addresses to a user-defined map entry.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn map<Entry: SymbolMapEntry, F: Fn(&'data Mach::Nlist) -> Option<Entry>>(
        &self,
        f: F,
    ) -> SymbolMap<Entry> {
        let mut symbols = Vec::new();
        for nlist in self.symbols {
            if !nlist.is_definition() {
                continue;
            }
            if let Some(entry) = f(nlist) {
                symbols.push(entry);
            }
        }
        SymbolMap::new(symbols)
    }

    /// Construct a map from addresses to symbol names and object file names.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn object_map(&self, endian: Mach::Endian) -> ObjectMap<'data> {
        let mut symbols = Vec::new();
        let mut objects = Vec::new();
        let mut object = None;
        let mut current_function = None;
        // Each module starts with one or two N_SO symbols (path, or directory + filename)
        // and one N_OSO symbol. The module is terminated by an empty N_SO symbol.
        for nlist in self.symbols {
            let n_type = nlist.n_type();
            if n_type & macho::N_STAB == 0 {
                continue;
            }
            // TODO: includes variables too (N_GSYM, N_STSYM). These may need to get their
            // address from regular symbols though.
            match n_type {
                macho::N_SO => {
                    object = None;
                }
                macho::N_OSO => {
                    object = None;
                    if let Ok(name) = nlist.name(endian, self.strings) {
                        if !name.is_empty() {
                            object = Some(objects.len());
                            objects.push(name);
                        }
                    }
                }
                macho::N_FUN => {
                    if let Ok(name) = nlist.name(endian, self.strings) {
                        if !name.is_empty() {
                            current_function = Some((name, nlist.n_value(endian).into()))
                        } else if let Some((name, address)) = current_function.take() {
                            if let Some(object) = object {
                                symbols.push(ObjectMapEntry {
                                    address,
                                    size: nlist.n_value(endian).into(),
                                    name,
                                    object,
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        ObjectMap {
            symbols: SymbolMap::new(symbols),
            objects,
        }
    }
}

/// An iterator over the symbols of a `MachOFile32`.
pub type MachOSymbolTable32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSymbolTable<'data, 'file, macho::MachHeader32<Endian>, R>;
/// An iterator over the symbols of a `MachOFile64`.
pub type MachOSymbolTable64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSymbolTable<'data, 'file, macho::MachHeader64<Endian>, R>;

/// A symbol table of a `MachOFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy)]

pub struct MachOSymbolTable<'data, 'file, Mach, R = &'data [u8]>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    pub(super) file: &'file MachOFile<'data, Mach, R>,
}

impl<'data, 'file, Mach, R> read::private::Sealed for MachOSymbolTable<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Mach, R> ObjectSymbolTable<'data> for MachOSymbolTable<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    type Symbol = MachOSymbol<'data, 'file, Mach, R>;
    type SymbolIterator = MachOSymbolIterator<'data, 'file, Mach, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbols(&self) -> Self::SymbolIterator {
        MachOSymbolIterator {
            file: self.file,
            index: 0,
        }
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        let nlist = self.file.symbols.symbol(index.0)?;
        MachOSymbol::new(self.file, index, nlist)
            .read_error(crate::nosym!("Unsupported Mach-O symbol index"))
    }
}

/// An iterator over the symbols of a `MachOFile32`.
pub type MachOSymbolIterator32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSymbolIterator<'data, 'file, macho::MachHeader32<Endian>, R>;
/// An iterator over the symbols of a `MachOFile64`.
pub type MachOSymbolIterator64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSymbolIterator<'data, 'file, macho::MachHeader64<Endian>, R>;

/// An iterator over the symbols of a `MachOFile`.

pub struct MachOSymbolIterator<'data, 'file, Mach, R = &'data [u8]>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    pub(super) file: &'file MachOFile<'data, Mach, R>,
    pub(super) index: usize,
}

impl<'data, 'file, Mach, R> fmt::Debug for MachOSymbolIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachOSymbolIterator").finish()
    }
}

impl<'data, 'file, Mach, R> Iterator for MachOSymbolIterator<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    type Item = MachOSymbol<'data, 'file, Mach, R>;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let index = self.index;
            let nlist = self.file.symbols.symbols.get(index)?;
            self.index += 1;
            if let Some(symbol) = MachOSymbol::new(self.file, SymbolIndex(index), nlist) {
                return Some(symbol);
            }
        }
    }
}

/// A symbol of a `MachOFile32`.
pub type MachOSymbol32<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSymbol<'data, 'file, macho::MachHeader32<Endian>, R>;
/// A symbol of a `MachOFile64`.
pub type MachOSymbol64<'data, 'file, Endian = Endianness, R = &'data [u8]> =
    MachOSymbol<'data, 'file, macho::MachHeader64<Endian>, R>;

/// A symbol of a `MachOFile`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy)]

pub struct MachOSymbol<'data, 'file, Mach, R = &'data [u8]>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    file: &'file MachOFile<'data, Mach, R>,
    index: SymbolIndex,
    nlist: &'data Mach::Nlist,
}

impl<'data, 'file, Mach, R> MachOSymbol<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub(super) fn new(
        file: &'file MachOFile<'data, Mach, R>,
        index: SymbolIndex,
        nlist: &'data Mach::Nlist,
    ) -> Option<Self> {
        if nlist.n_type() & macho::N_STAB != 0 {
            return None;
        }
        Some(MachOSymbol { file, index, nlist })
    }
}

impl<'data, 'file, Mach, R> read::private::Sealed for MachOSymbol<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
}

impl<'data, 'file, Mach, R> ObjectSymbol<'data> for MachOSymbol<'data, 'file, Mach, R>
where
    Mach: MachHeader,
    R: ReadRef<'data>,
{
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn index(&self) -> SymbolIndex {
        self.index
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name_bytes(&self) -> Result<&'data [u8]> {
        self.nlist.name(self.file.endian, self.file.symbols.strings)
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name(&self) -> Result<&'data str> {
        let name = self.name_bytes()?;
        str::from_utf8(name)
            .ok()
            .read_error(crate::nosym!("Non UTF-8 Mach-O symbol name"))
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        self.nlist.n_value(self.file.endian).into()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn size(&self) -> u64 {
        0
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn kind(&self) -> SymbolKind {
        self.section()
            .index()
            .and_then(|index| self.file.section_internal(index).ok())
            .map(|section| match section.kind {
                SectionKind::Text => SymbolKind::Text,
                SectionKind::Data
                | SectionKind::ReadOnlyData
                | SectionKind::ReadOnlyString
                | SectionKind::UninitializedData
                | SectionKind::Common => SymbolKind::Data,
                SectionKind::Tls | SectionKind::UninitializedTls | SectionKind::TlsVariables => {
                    SymbolKind::Tls
                }
                _ => SymbolKind::Unknown,
            })
            .unwrap_or(SymbolKind::Unknown)
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn section(&self) -> SymbolSection {
        match self.nlist.n_type() & macho::N_TYPE {
            macho::N_UNDF => SymbolSection::Undefined,
            macho::N_ABS => SymbolSection::Absolute,
            macho::N_SECT => {
                let n_sect = self.nlist.n_sect();
                if n_sect != 0 {
                    SymbolSection::Section(SectionIndex(n_sect as usize))
                } else {
                    SymbolSection::Unknown
                }
            }
            _ => SymbolSection::Unknown,
        }
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_undefined(&self) -> bool {
        self.nlist.n_type() & macho::N_TYPE == macho::N_UNDF
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_definition(&self) -> bool {
        self.nlist.is_definition()
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_common(&self) -> bool {
        // Mach-O common symbols are based on section, not symbol
        false
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_weak(&self) -> bool {
        self.nlist.n_desc(self.file.endian) & (macho::N_WEAK_REF | macho::N_WEAK_DEF) != 0
    }

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn scope(&self) -> SymbolScope {
        let n_type = self.nlist.n_type();
        if n_type & macho::N_TYPE == macho::N_UNDF {
            SymbolScope::Unknown
        } else if n_type & macho::N_EXT == 0 {
            SymbolScope::Compilation
        } else if n_type & macho::N_PEXT != 0 {
            SymbolScope::Linkage
        } else {
            SymbolScope::Dynamic
        }
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_global(&self) -> bool {
        self.scope() != SymbolScope::Compilation
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_local(&self) -> bool {
        self.scope() == SymbolScope::Compilation
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn flags(&self) -> SymbolFlags<SectionIndex> {
        let n_desc = self.nlist.n_desc(self.file.endian);
        SymbolFlags::MachO { n_desc }
    }
}

/// A trait for generic access to `Nlist32` and `Nlist64`.
#[allow(missing_docs)]
pub trait Nlist: DebugPod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_strx(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_type(&self) -> u8;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_sect(&self) -> u8;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_desc(&self, endian: Self::Endian) -> u16;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_value(&self, endian: Self::Endian) -> Self::Word;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn name<'data, R: ReadRef<'data>>(
        &self,
        endian: Self::Endian,
        strings: StringTable<'data, R>,
    ) -> Result<&'data [u8]> {
        strings
            .get(self.n_strx(endian))
            .read_error(crate::nosym!("Invalid Mach-O symbol name offset"))
    }

    /// Return true if this is a STAB symbol.
    ///
    /// This determines the meaning of the `n_type` field.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_stab(&self) -> bool {
        self.n_type() & macho::N_STAB != 0
    }

    /// Return true if this is an undefined symbol.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_undefined(&self) -> bool {
        let n_type = self.n_type();
        n_type & macho::N_STAB == 0 && n_type & macho::N_TYPE == macho::N_UNDF
    }

    /// Return true if the symbol is a definition of a function or data object.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_definition(&self) -> bool {
        let n_type = self.n_type();
        n_type & macho::N_STAB == 0 && n_type & macho::N_TYPE != macho::N_UNDF
    }

    /// Return the library ordinal.
    ///
    /// This is either a 1-based index into the dylib load commands,
    /// or a special ordinal.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn library_ordinal(&self, endian: Self::Endian) -> u8 {
        (self.n_desc(endian) >> 8) as u8
    }
}

impl<Endian: endian::Endian> Nlist for macho::Nlist32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_strx(&self, endian: Self::Endian) -> u32 {
        self.n_strx.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_type(&self) -> u8 {
        self.n_type
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_sect(&self) -> u8 {
        self.n_sect
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_desc(&self, endian: Self::Endian) -> u16 {
        self.n_desc.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_value(&self, endian: Self::Endian) -> Self::Word {
        self.n_value.get(endian)
    }
}

impl<Endian: endian::Endian> Nlist for macho::Nlist64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_strx(&self, endian: Self::Endian) -> u32 {
        self.n_strx.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_type(&self) -> u8 {
        self.n_type
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_sect(&self) -> u8 {
        self.n_sect
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_desc(&self, endian: Self::Endian) -> u16 {
        self.n_desc.get(endian)
    }
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_value(&self, endian: Self::Endian) -> Self::Word {
        self.n_value.get(endian)
    }
}
