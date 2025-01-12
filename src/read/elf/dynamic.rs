use core::convert::TryInto;
use core::fmt::Debug;

use crate::endian;
use crate::pod::Pod;
use crate::read::{ReadError, Result, StringTable};
use crate::{elf, DebugPod};

/// A trait for generic access to `Dyn32` and `Dyn64`.
#[allow(missing_docs)]
pub trait Dyn: DebugPod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn d_tag(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn d_val(&self, endian: Self::Endian) -> Self::Word;

    /// Try to convert the tag to a `u32`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn tag32(&self, endian: Self::Endian) -> Option<u32> {
        self.d_tag(endian).into().try_into().ok()
    }

    /// Try to convert the value to a `u32`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn val32(&self, endian: Self::Endian) -> Option<u32> {
        self.d_val(endian).into().try_into().ok()
    }

    /// Return true if the value is an offset in the dynamic string table.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_string(&self, endian: Self::Endian) -> bool {
        if let Some(tag) = self.tag32(endian) {
            match tag {
                elf::DT_NEEDED
                | elf::DT_SONAME
                | elf::DT_RPATH
                | elf::DT_RUNPATH
                | elf::DT_AUXILIARY
                | elf::DT_FILTER => true,
                _ => false,
            }
        } else {
            false
        }
    }

    /// Use the value to get a string in a string table.
    ///
    /// Does not check for an appropriate tag.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn string<'data>(
        &self,
        endian: Self::Endian,
        strings: StringTable<'data>,
    ) -> Result<&'data [u8]> {
        self.val32(endian)
            .and_then(|val| strings.get(val).ok())
            .read_error(crate::nosym!("Invalid ELF dyn string"))
    }

    /// Return true if the value is an address.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn is_address(&self, endian: Self::Endian) -> bool {
        if let Some(tag) = self.tag32(endian) {
            match tag {
                elf::DT_PLTGOT
                | elf::DT_HASH
                | elf::DT_STRTAB
                | elf::DT_SYMTAB
                | elf::DT_RELA
                | elf::DT_INIT
                | elf::DT_FINI
                | elf::DT_SYMBOLIC
                | elf::DT_REL
                | elf::DT_DEBUG
                | elf::DT_JMPREL
                | elf::DT_FINI_ARRAY
                | elf::DT_INIT_ARRAY
                | elf::DT_PREINIT_ARRAY
                | elf::DT_SYMTAB_SHNDX
                | elf::DT_VERDEF
                | elf::DT_VERNEED
                | elf::DT_VERSYM
                | elf::DT_ADDRRNGLO..=elf::DT_ADDRRNGHI => true,
                _ => false,
            }
        } else {
            false
        }
    }
}

impl<Endian: endian::Endian> Dyn for elf::Dyn32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn d_tag(&self, endian: Self::Endian) -> Self::Word {
        self.d_tag.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn d_val(&self, endian: Self::Endian) -> Self::Word {
        self.d_val.get(endian)
    }
}

impl<Endian: endian::Endian> Dyn for elf::Dyn64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn d_tag(&self, endian: Self::Endian) -> Self::Word {
        self.d_tag.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn d_val(&self, endian: Self::Endian) -> Self::Word {
        self.d_val.get(endian)
    }
}
