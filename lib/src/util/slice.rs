pub trait SliceExt {
    type Element;

    /// Returns the first M elements as an array.
    fn head_array<const M: usize>(&self) -> Option<&[Self::Element; M]>;
}

impl<const N: usize, T> SliceExt for [T; N] {
    type Element = T;

    fn head_array<const M: usize>(&self) -> Option<&[Self::Element; M]> {
        self.get(0..M).and_then(|x| x.as_array::<M>())
    }
}

impl<T> SliceExt for &[T] {
    type Element = T;

    fn head_array<const M: usize>(&self) -> Option<&[Self::Element; M]> {
        self.get(0..M).and_then(|x| x.as_array::<M>())
    }
}
