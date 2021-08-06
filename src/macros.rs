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
