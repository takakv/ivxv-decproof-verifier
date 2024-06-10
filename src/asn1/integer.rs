use rasn::prelude::Constraints;
use rasn::{Decoder, Encoder, Tag};
use std::ops::Sub;

#[derive(Clone)]
pub struct Integer {
    inner: rug::Integer,
}

impl Integer {
    pub(crate) fn pow_mod(self, p0: &Integer, p1: &Integer) -> rug::Integer {
        self.inner.pow_mod(&p0.inner, &p1.inner).unwrap().clone()
    }
}

impl Sub for Integer {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        Self {
            inner: self.integer - other.x,
            y: self.y - other.y,
        }
    }
}

impl rasn::AsnType for Integer {
    const TAG: Tag = Tag::INTEGER;
}

impl rasn::Decode for Integer {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        // let inner = rug::Integer::from_digits(parse_primitive_value(tag)?.1);
        // rug::Integer::from_digits(i.to_signed_bytes_be().deref(), BYTE_ORDER);
        let tmp = decoder.decode_integer(tag, constraints)?;
        let inner = rug::Integer::from_digits(
            tmp.to_signed_bytes_be().as_slice(),
            rug::integer::Order::Msf,
        );

        Ok(Integer { inner })
    }
}

impl rasn::Encode for Integer {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<(), E::Error> {
        let bytes: Vec<u8> = self.inner.to_digits(rug::integer::Order::Msf);
        let tmp = rasn::types::Integer::from_signed_bytes_be(&bytes);
        encoder.encode_integer(tag, constraints, &tmp)?;

        Ok(())
    }
}
