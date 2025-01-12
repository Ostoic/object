//! Interface for reading object files.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::{fmt, result};

use crate::common::*;

mod read_ref;
pub use read_ref::*;

#[cfg(feature = "std")]
mod read_cache;
#[cfg(feature = "std")]
pub use read_cache::*;

mod util;
pub use util::*;

#[cfg(any(
    feature = "coff",
    feature = "elf",
    feature = "macho",
    feature = "pe",
    feature = "wasm",
    feature = "xcoff"
))]
mod any;
#[cfg(any(
    feature = "coff",
    feature = "elf",
    feature = "macho",
    feature = "pe",
    feature = "wasm",
    feature = "xcoff"
))]
pub use any::*;

#[cfg(feature = "archive")]
pub mod archive;

#[cfg(feature = "coff")]
pub mod coff;

#[cfg(feature = "elf")]
pub mod elf;

#[cfg(feature = "macho")]
pub mod macho;

#[cfg(feature = "pe")]
pub mod pe;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "xcoff")]
pub mod xcoff;

mod traits;
pub use traits::*;

mod private {
    pub trait Sealed {}
}

/// The error type used within the read module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Error(&'static str);

impl fmt::Display for Error {
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The result type used within the read module.
pub type Result<T> = result::Result<T, Error>;

trait ReadError<T> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_error(self, error: &'static str) -> Result<T>;
}

impl<T> ReadError<T> for result::Result<T, ()> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_error(self, error: &'static str) -> Result<T> {
        self.map_err(|()| Error(error))
    }
}

impl<T> ReadError<T> for result::Result<T, Error> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_error(self, error: &'static str) -> Result<T> {
        self.map_err(|_| Error(error))
    }
}

impl<T> ReadError<T> for Option<T> {
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn read_error(self, error: &'static str) -> Result<T> {
        self.ok_or(Error(error))
    }
}

/// The native executable file for the target platform.
#[cfg(all(
    unix,
    not(target_os = "macos"),
    target_pointer_width = "32",
    feature = "elf"
))]
pub type NativeFile<'data, R = &'data [u8]> = elf::ElfFile32<'data, crate::Endianness, R>;

/// The native executable file for the target platform.
#[cfg(all(
    unix,
    not(target_os = "macos"),
    target_pointer_width = "64",
    feature = "elf"
))]
pub type NativeFile<'data, R = &'data [u8]> = elf::ElfFile64<'data, crate::Endianness, R>;

/// The native executable file for the target platform.
#[cfg(all(target_os = "macos", target_pointer_width = "32", feature = "macho"))]
pub type NativeFile<'data, R = &'data [u8]> = macho::MachOFile32<'data, crate::Endianness, R>;

/// The native executable file for the target platform.
#[cfg(all(target_os = "macos", target_pointer_width = "64", feature = "macho"))]
pub type NativeFile<'data, R = &'data [u8]> = macho::MachOFile64<'data, crate::Endianness, R>;

/// The native executable file for the target platform.
#[cfg(all(target_os = "windows", target_pointer_width = "32", feature = "pe"))]
pub type NativeFile<'data, R = &'data [u8]> = pe::PeFile32<'data, R>;

/// The native executable file for the target platform.
#[cfg(all(target_os = "windows", target_pointer_width = "64", feature = "pe"))]
pub type NativeFile<'data, R = &'data [u8]> = pe::PeFile64<'data, R>;

/// The native executable file for the target platform.
#[cfg(all(feature = "wasm", target_arch = "wasm32", feature = "wasm"))]
pub type NativeFile<'data, R = &'data [u8]> = wasm::WasmFile<'data, R>;

/// A file format kind.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileKind {
    /// A Unix archive.
    #[cfg(feature = "archive")]
    Archive,
    /// A COFF object file.
    #[cfg(feature = "coff")]
    Coff,
    /// A dyld cache file containing Mach-O images.
    #[cfg(feature = "macho")]
    DyldCache,
    /// A 32-bit ELF file.
    #[cfg(feature = "elf")]
    Elf32,
    /// A 64-bit ELF file.
    #[cfg(feature = "elf")]
    Elf64,
    /// A 32-bit Mach-O file.
    #[cfg(feature = "macho")]
    MachO32,
    /// A 64-bit Mach-O file.
    #[cfg(feature = "macho")]
    MachO64,
    /// A 32-bit Mach-O fat binary.
    #[cfg(feature = "macho")]
    MachOFat32,
    /// A 64-bit Mach-O fat binary.
    #[cfg(feature = "macho")]
    MachOFat64,
    /// A 32-bit PE file.
    #[cfg(feature = "pe")]
    Pe32,
    /// A 64-bit PE file.
    #[cfg(feature = "pe")]
    Pe64,
    /// A Wasm file.
    #[cfg(feature = "wasm")]
    Wasm,
    /// A 32-bit XCOFF file.
    #[cfg(feature = "xcoff")]
    Xcoff32,
    /// A 64-bit XCOFF file.
    #[cfg(feature = "xcoff")]
    Xcoff64,
}

impl FileKind {
    /// Determine a file kind by parsing the start of the file.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse<'data, R: ReadRef<'data>>(data: R) -> Result<FileKind> {
        Self::parse_at(data, 0)
    }

    /// Determine a file kind by parsing at the given offset.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn parse_at<'data, R: ReadRef<'data>>(data: R, offset: u64) -> Result<FileKind> {
        let magic = data
            .read_bytes_at(offset, 16)
            .read_error(crate::nosym!("Could not read file magic"))?;
        if magic.len() < 16 {
            return Err(Error(crate::nosym!("File too short")));
        }

        let kind = match [magic[0], magic[1], magic[2], magic[3], magic[4], magic[5], magic[6], magic[7]] {
            #[cfg(feature = "archive")]
            [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n'] => FileKind::Archive,
            #[cfg(feature = "macho")]
            [b'd', b'y', b'l', b'd', b'_', b'v', b'1', b' '] => FileKind::DyldCache,
            #[cfg(feature = "elf")]
            [0x7f, b'E', b'L', b'F', 1, ..] => FileKind::Elf32,
            #[cfg(feature = "elf")]
            [0x7f, b'E', b'L', b'F', 2, ..] => FileKind::Elf64,
            #[cfg(feature = "macho")]
            [0xfe, 0xed, 0xfa, 0xce, ..]
            | [0xce, 0xfa, 0xed, 0xfe, ..] => FileKind::MachO32,
            #[cfg(feature = "macho")]
            | [0xfe, 0xed, 0xfa, 0xcf, ..]
            | [0xcf, 0xfa, 0xed, 0xfe, ..] => FileKind::MachO64,
            #[cfg(feature = "macho")]
            [0xca, 0xfe, 0xba, 0xbe, ..] => FileKind::MachOFat32,
            #[cfg(feature = "macho")]
            [0xca, 0xfe, 0xba, 0xbf, ..] => FileKind::MachOFat64,
            #[cfg(feature = "wasm")]
            [0x00, b'a', b's', b'm', ..] => FileKind::Wasm,
            #[cfg(feature = "pe")]
            [b'M', b'Z', ..] => {
                match pe::optional_header_magic(data) {
                    Ok(crate::pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC) => {
                        FileKind::Pe32
                    }
                    Ok(crate::pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC) => {
                        FileKind::Pe64
                    }
                    _ => return Err(Error(crate::nosym!("Unknown MS-DOS file"))),
                }
            }
            // TODO: more COFF machines
            #[cfg(feature = "coff")]
            // COFF arm
            [0xc4, 0x01, ..]
            // COFF arm64
            | [0x64, 0xaa, ..]
            // COFF x86
            | [0x4c, 0x01, ..]
            // COFF x86-64
            | [0x64, 0x86, ..] => FileKind::Coff,
            #[cfg(feature = "xcoff")]
            [0x01, 0xDF, ..] => FileKind::Xcoff32,
            #[cfg(feature = "xcoff")]
            [0x01, 0xF7, ..] => FileKind::Xcoff64,
            _ => return Err(Error("Unknown file magic")),
        };
        Ok(kind)
    }
}

/// An object kind.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectKind {
    /// The object kind is unknown.
    Unknown,
    /// Relocatable object.
    Relocatable,
    /// Executable.
    Executable,
    /// Dynamic shared object.
    Dynamic,
    /// Core.
    Core,
}

/// The index used to identify a section of a file.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct SectionIndex(pub usize);

/// The index used to identify a symbol of a file.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct SymbolIndex(pub usize);

/// The section where a symbol is defined.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymbolSection {
    /// The section is unknown.
    Unknown,
    /// The section is not applicable for this symbol (such as file symbols).
    None,
    /// The symbol is undefined.
    Undefined,
    /// The symbol has an absolute value.
    Absolute,
    /// The symbol is a zero-initialized symbol that will be combined with duplicate definitions.
    Common,
    /// The symbol is defined in the given section.
    Section(SectionIndex),
}

impl SymbolSection {
    /// Returns the section index for the section where the symbol is defined.
    ///
    /// May return `None` if the symbol is not defined in a section.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn index(self) -> Option<SectionIndex> {
        if let SymbolSection::Section(index) = self {
            Some(index)
        } else {
            None
        }
    }
}

/// An entry in a `SymbolMap`.
pub trait SymbolMapEntry {
    /// The symbol address.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64;
}

/// A map from addresses to symbols.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Default, Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct SymbolMap<T: SymbolMapEntry> {
    symbols: Vec<T>,
}

impl<T: SymbolMapEntry> SymbolMap<T> {
    /// Construct a new symbol map.
    ///
    /// This function will sort the symbols by address.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn new(mut symbols: Vec<T>) -> Self {
        symbols.sort_unstable_by_key(|s| s.address());
        SymbolMap { symbols }
    }

    /// Get the symbol before the given address.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn get(&self, address: u64) -> Option<&T> {
        let index = match self
            .symbols
            .binary_search_by_key(&address, |symbol| symbol.address())
        {
            Ok(index) => index,
            Err(index) => index.checked_sub(1)?,
        };
        self.symbols.get(index)
    }

    /// Get all symbols in the map.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn symbols(&self) -> &[T] {
        &self.symbols
    }
}

/// A `SymbolMap` entry for symbol names.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct SymbolMapName<'data> {
    address: u64,
    name: &'data str,
}

impl<'data> SymbolMapName<'data> {
    /// Construct a `SymbolMapName`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn new(address: u64, name: &'data str) -> Self {
        SymbolMapName { address, name }
    }

    /// The symbol address.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The symbol name.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn name(&self) -> &'data str {
        self.name
    }
}

impl<'data> SymbolMapEntry for SymbolMapName<'data> {
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        self.address
    }
}

/// A map from addresses to symbol names and object files.
///
/// This is derived from STAB entries in Mach-O files.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Default, Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct ObjectMap<'data> {
    symbols: SymbolMap<ObjectMapEntry<'data>>,
    objects: Vec<&'data [u8]>,
}

impl<'data> ObjectMap<'data> {
    /// Get the entry containing the given address.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn get(&self, address: u64) -> Option<&ObjectMapEntry<'data>> {
        self.symbols
            .get(address)
            .filter(|entry| entry.size == 0 || address.wrapping_sub(entry.address) < entry.size)
    }

    /// Get all symbols in the map.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn symbols(&self) -> &[ObjectMapEntry<'data>] {
        self.symbols.symbols()
    }

    /// Get all objects in the map.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn objects(&self) -> &[&'data [u8]] {
        &self.objects
    }
}

/// A `ObjectMap` entry.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct ObjectMapEntry<'data> {
    address: u64,
    size: u64,
    name: &'data [u8],
    object: usize,
}

impl<'data> ObjectMapEntry<'data> {
    /// Get the symbol address.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the symbol size.
    ///
    /// This may be 0 if the size is unknown.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the symbol name.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn name(&self) -> &'data [u8] {
        self.name
    }

    /// Get the index of the object file name.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn object_index(&self) -> usize {
        self.object
    }

    /// Get the object file name.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn object(&self, map: &ObjectMap<'data>) -> &'data [u8] {
        map.objects[self.object]
    }
}

impl<'data> SymbolMapEntry for ObjectMapEntry<'data> {
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn address(&self) -> u64 {
        self.address
    }
}

/// An imported symbol.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Import<'data> {
    library: ByteString<'data>,
    // TODO: or ordinal
    name: ByteString<'data>,
}

impl<'data> Import<'data> {
    /// The symbol name.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn name(&self) -> &'data [u8] {
        self.name.0
    }

    /// The name of the library to import the symbol from.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn library(&self) -> &'data [u8] {
        self.library.0
    }
}

/// An exported symbol.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Export<'data> {
    // TODO: and ordinal?
    name: ByteString<'data>,
    address: u64,
}

impl<'data> Export<'data> {
    /// The symbol name.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn name(&self) -> &'data [u8] {
        self.name.0
    }

    /// The virtual address of the symbol.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn address(&self) -> u64 {
        self.address
    }
}

/// PDB Information
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct CodeView<'data> {
    guid: [u8; 16],
    path: ByteString<'data>,
    age: u32,
}

impl<'data> CodeView<'data> {
    /// The path to the PDB as stored in CodeView
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn path(&self) -> &'data [u8] {
        self.path.0
    }

    /// The age of the PDB
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn age(&self) -> u32 {
        self.age
    }

    /// The GUID of the PDB.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn guid(&self) -> [u8; 16] {
        self.guid
    }
}

/// The target referenced by a relocation.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelocationTarget {
    /// The target is a symbol.
    Symbol(SymbolIndex),
    /// The target is a section.
    Section(SectionIndex),
    /// The offset is an absolute address.
    Absolute,
}

/// A relocation entry.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Relocation {
    kind: RelocationKind,
    encoding: RelocationEncoding,
    size: u8,
    target: RelocationTarget,
    addend: i64,
    implicit_addend: bool,
}

impl Relocation {
    /// The operation used to calculate the result of the relocation.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn kind(&self) -> RelocationKind {
        self.kind
    }

    /// Information about how the result of the relocation operation is encoded in the place.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn encoding(&self) -> RelocationEncoding {
        self.encoding
    }

    /// The size in bits of the place of the relocation.
    ///
    /// If 0, then the size is determined by the relocation kind.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn size(&self) -> u8 {
        self.size
    }

    /// The target of the relocation.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn target(&self) -> RelocationTarget {
        self.target
    }

    /// The addend to use in the relocation calculation.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn addend(&self) -> i64 {
        self.addend
    }

    /// Set the addend to use in the relocation calculation.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn set_addend(&mut self, addend: i64) {
        self.addend = addend
    }

    /// Returns true if there is an implicit addend stored in the data at the offset
    /// to be relocated.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn has_implicit_addend(&self) -> bool {
        self.implicit_addend
    }
}

/// A data compression format.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompressionFormat {
    /// The data is uncompressed.
    None,
    /// The data is compressed, but the compression format is unknown.
    Unknown,
    /// ZLIB/DEFLATE.
    ///
    /// Used for ELF compression and GNU compressed debug information.
    Zlib,
}

/// A range in a file that may be compressed.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct CompressedFileRange {
    /// The data compression format.
    pub format: CompressionFormat,
    /// The file offset of the compressed data.
    pub offset: u64,
    /// The compressed data size.
    pub compressed_size: u64,
    /// The uncompressed data size.
    pub uncompressed_size: u64,
}

impl CompressedFileRange {
    /// Data that is uncompressed.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn none(range: Option<(u64, u64)>) -> Self {
        if let Some((offset, size)) = range {
            CompressedFileRange {
                format: CompressionFormat::None,
                offset,
                compressed_size: size,
                uncompressed_size: size,
            }
        } else {
            CompressedFileRange {
                format: CompressionFormat::None,
                offset: 0,
                compressed_size: 0,
                uncompressed_size: 0,
            }
        }
    }

    /// Convert to `CompressedData` by reading from the file.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn data<'data, R: ReadRef<'data>>(self, file: R) -> Result<CompressedData<'data>> {
        let data = file
            .read_bytes_at(self.offset, self.compressed_size)
            .read_error(crate::nosym!("Invalid compressed data size or offset"))?;
        Ok(CompressedData {
            format: self.format,
            data,
            uncompressed_size: self.uncompressed_size,
        })
    }
}

/// Data that may be compressed.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct CompressedData<'data> {
    /// The data compression format.
    pub format: CompressionFormat,
    /// The compressed data.
    pub data: &'data [u8],
    /// The uncompressed data size.
    pub uncompressed_size: u64,
}

impl<'data> CompressedData<'data> {
    /// Data that is uncompressed.
    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn none(data: &'data [u8]) -> Self {
        CompressedData {
            format: CompressionFormat::None,
            data,
            uncompressed_size: data.len() as u64,
        }
    }

    /// Return the uncompressed data.
    ///
    /// Returns an error for invalid data or unsupported compression.
    /// This includes if the data is compressed but the `compression` feature
    /// for this crate is disabled.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn decompress(self) -> Result<Cow<'data, [u8]>> {
        match self.format {
            CompressionFormat::None => Ok(Cow::Borrowed(self.data)),
            #[cfg(feature = "compression")]
            CompressionFormat::Zlib => {
                use core::convert::TryInto;
                let size = self
                    .uncompressed_size
                    .try_into()
                    .ok()
                    .read_error(crate::nosym!("Uncompressed data size is too large."))?;
                let mut decompressed = Vec::with_capacity(size);
                let mut decompress = flate2::Decompress::new(true);
                decompress
                    .decompress_vec(
                        self.data,
                        &mut decompressed,
                        flate2::FlushDecompress::Finish,
                    )
                    .ok()
                    .read_error(crate::nosym!("Invalid zlib compressed data"))?;
                Ok(Cow::Owned(decompressed))
            }
            _ => Err(Error("Unsupported compressed data.")),
        }
    }
}
