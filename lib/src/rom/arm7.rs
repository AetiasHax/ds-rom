use std::borrow::Cow;

pub struct Arm7<'a> {
    data: Cow<'a, [u8]>,
    base_address: u32,
    entry_function: u32,
}

impl<'a> Arm7<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T, base_address: u32, entry_function: u32) -> Self {
        Self { data: data.into(), base_address, entry_function }
    }

    pub fn full_data(&self) -> &[u8] {
        &self.data
    }

    pub fn base_address(&self) -> u32 {
        self.base_address
    }

    pub fn entry_function(&self) -> u32 {
        self.entry_function
    }
}
