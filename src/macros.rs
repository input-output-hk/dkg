//! Internal macros

macro_rules! std_ops_gen {
    ($lty: ident, $groupelem: ident, $class: ident, $rty: ident, $out: ident, $f: ident) => {
        impl<'a, G: $groupelem> $class<$rty<G>> for &'a $lty<G> {
            type Output = $out<G>;

            fn $f(self, other: $rty<G>) -> Self::Output {
                self.$f(&other)
            }
        }

        impl<'b, G: $groupelem> $class<&'b $rty<G>> for $lty<G> {
            type Output = $out<G>;

            fn $f(self, other: &'b $rty<G>) -> Self::Output {
                (&self).$f(other)
            }
        }

        impl<G: $groupelem> $class<$rty<G>> for $lty<G> {
            type Output = $out<G>;

            fn $f(self, other: $rty<G>) -> Self::Output {
                (&self).$f(&other)
            }
        }
    };
}

// Some operations are not symmetric in the trait bounds of the types of the elements where the
// binary operation is applied. We create a different macro for it
macro_rules! std_ops_gen_nsym {
    ($lty: ident, $groupelem: ident, $class: ident, $out: ident, $f: ident) => {
        impl<'b, G: $groupelem> $class<&'b G::CorrespondingScalar> for $lty<G> {
            type Output = $out<G>;

            fn $f(self, other: &'b G::CorrespondingScalar) -> Self::Output {
                (&self).$f(other)
            }
        }
    };
}
