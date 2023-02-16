use core::fmt::Debug;
use core::mem;

use crate::endian;
use crate::pod::Pod;
use crate::read::util;
use crate::read::{self, Bytes, Error, ReadError};
use crate::{elf, DebugPod};

use super::FileHeader;

/// An iterator over the notes in an ELF section or segment.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct NoteIterator<'data, Elf>
where
    Elf: FileHeader,
{
    endian: Elf::Endian,
    align: usize,
    data: Bytes<'data>,
}

impl<'data, Elf> NoteIterator<'data, Elf>
where
    Elf: FileHeader,
{
    /// Returns `Err` if `align` is invalid.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub(super) fn new(
        endian: Elf::Endian,
        align: Elf::Word,
        data: &'data [u8],
    ) -> read::Result<Self> {
        let align = match align.into() {
            0u64..=4 => 4,
            8 => 8,
            _ => return Err(Error(crate::nosym!("Invalid ELF note alignment"))),
        };
        // TODO: check data alignment?
        Ok(NoteIterator {
            endian,
            align,
            data: Bytes(data),
        })
    }

    /// Returns the next note.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn next(&mut self) -> read::Result<Option<Note<'data, Elf>>> {
        let mut data = self.data;
        if data.is_empty() {
            return Ok(None);
        }

        let header = data
            .read_at::<Elf::NoteHeader>(0)
            .read_error(crate::nosym!("ELF note is too short"))?;

        // The name has no alignment requirement.
        let offset = mem::size_of::<Elf::NoteHeader>();
        let namesz = header.n_namesz(self.endian) as usize;
        let name = data
            .read_bytes_at(offset, namesz)
            .read_error(crate::nosym!("Invalid ELF note namesz"))?
            .0;

        // The descriptor must be aligned.
        let offset = util::align(offset + namesz, self.align);
        let descsz = header.n_descsz(self.endian) as usize;
        let desc = data
            .read_bytes_at(offset, descsz)
            .read_error(crate::nosym!("Invalid ELF note descsz"))?
            .0;

        // The next note (if any) must be aligned.
        let offset = util::align(offset + descsz, self.align);
        if data.skip(offset).is_err() {
            data = Bytes(&[]);
        }
        self.data = data;

        Ok(Some(Note { header, name, desc }))
    }
}

/// A parsed `NoteHeader`.
#[cfg_attr(not(feature = "nosym"), derive(Debug))]

pub struct Note<'data, Elf>
where
    Elf: FileHeader,
{
    header: &'data Elf::NoteHeader,
    name: &'data [u8],
    desc: &'data [u8],
}

impl<'data, Elf: FileHeader> Note<'data, Elf> {
    /// Return the `n_type` field of the `NoteHeader`.
    ///
    /// The meaning of this field is determined by `name`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn n_type(&self, endian: Elf::Endian) -> u32 {
        self.header.n_type(endian)
    }

    /// Return the `n_namesz` field of the `NoteHeader`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn n_namesz(&self, endian: Elf::Endian) -> u32 {
        self.header.n_namesz(endian)
    }

    /// Return the `n_descsz` field of the `NoteHeader`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn n_descsz(&self, endian: Elf::Endian) -> u32 {
        self.header.n_descsz(endian)
    }

    /// Return the bytes for the name field following the `NoteHeader`,
    /// excluding any null terminator.
    ///
    /// This field is usually a string including a null terminator
    /// (but it is not required to be).
    ///
    /// The length of this field (including any null terminator) is given by
    /// `n_namesz`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn name(&self) -> &'data [u8] {
        if let Some((last, name)) = self.name.split_last() {
            if *last == 0 {
                return name;
            }
        }
        self.name
    }

    /// Return the bytes for the desc field following the `NoteHeader`.
    ///
    /// The length of this field is given by `n_descsz`. The meaning
    /// of this field is determined by `name` and `n_type`.
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    pub fn desc(&self) -> &'data [u8] {
        self.desc
    }
}

/// A trait for generic access to `NoteHeader32` and `NoteHeader64`.
#[allow(missing_docs)]
pub trait NoteHeader: DebugPod {
    type Endian: endian::Endian;

    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_namesz(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_descsz(&self, endian: Self::Endian) -> u32;
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_type(&self, endian: Self::Endian) -> u32;
}

impl<Endian: endian::Endian> NoteHeader for elf::NoteHeader32<Endian> {
    type Endian = Endian;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_namesz(&self, endian: Self::Endian) -> u32 {
        self.n_namesz.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_descsz(&self, endian: Self::Endian) -> u32 {
        self.n_descsz.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_type(&self, endian: Self::Endian) -> u32 {
        self.n_type.get(endian)
    }
}

impl<Endian: endian::Endian> NoteHeader for elf::NoteHeader64<Endian> {
    type Endian = Endian;

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_namesz(&self, endian: Self::Endian) -> u32 {
        self.n_namesz.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_descsz(&self, endian: Self::Endian) -> u32 {
        self.n_descsz.get(endian)
    }

    #[cfg_attr(not(feature = "aggressive-inline"), inline)]
    #[cfg_attr(feature = "aggressive-inline", inline(always))]
    fn n_type(&self, endian: Self::Endian) -> u32 {
        self.n_type.get(endian)
    }
}
