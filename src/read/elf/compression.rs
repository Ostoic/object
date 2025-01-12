use core::fmt::Debug;

use crate::endian;
use crate::pod::Pod;
use crate::{elf, DebugPod};

/// A trait for generic access to `CompressionHeader32` and `CompressionHeader64`.
#[allow(missing_docs)]
pub trait CompressionHeader: DebugPod {
    type Word: Into<u64>;
    type Endian: endian::Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_type(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_size(&self, endian: Self::Endian) -> Self::Word;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_addralign(&self, endian: Self::Endian) -> Self::Word;
}

impl<Endian: endian::Endian> CompressionHeader for elf::CompressionHeader32<Endian> {
    type Word = u32;
    type Endian = Endian;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_type(&self, endian: Self::Endian) -> u32 {
        self.ch_type.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_size(&self, endian: Self::Endian) -> Self::Word {
        self.ch_size.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.ch_addralign.get(endian)
    }
}

impl<Endian: endian::Endian> CompressionHeader for elf::CompressionHeader64<Endian> {
    type Word = u64;
    type Endian = Endian;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_type(&self, endian: Self::Endian) -> u32 {
        self.ch_type.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_size(&self, endian: Self::Endian) -> Self::Word {
        self.ch_size.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn ch_addralign(&self, endian: Self::Endian) -> Self::Word {
        self.ch_addralign.get(endian)
    }
}
