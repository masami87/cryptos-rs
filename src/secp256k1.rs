#![allow(unused)]
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_integer::{ExtendedGcd, Integer};
use num_traits::{Num, One, Signed, Zero};
use rand::{thread_rng, Rng};
use std::{
    borrow::Borrow,
    ops::{Add, Mul, Rem},
};

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
const A_HEX: &str = "0";
const B_HEX: &str = "7";
const GX_HEX: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const GY_HEX: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

lazy_static! {
    static ref SECP256K1: Curve = Curve {
        p: BigInt::from_str_radix(P_HEX, 16).unwrap(),
        a: BigInt::from_str_radix(A_HEX, 16).unwrap(),
        b: BigInt::from_str_radix(B_HEX, 16).unwrap(),
        gx: BigInt::from_str_radix(GX_HEX, 16).unwrap(),
        gy: BigInt::from_str_radix(GY_HEX, 16).unwrap(),
        n: BigInt::from_str_radix(N_HEX, 16).unwrap(),
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Point {
    x: BigInt,
    y: BigInt,
}

impl Point {
    fn new(x: BigInt, y: BigInt) -> Self {
        Self { x, y }
    }
    fn infinity() -> Self {
        Self {
            x: BigInt::zero(),
            y: BigInt::zero(),
        }
    }
    fn is_infinity(&self) -> bool {
        self.x == BigInt::zero() && self.y == BigInt::zero()
    }
}

impl Add for Point {
    type Output = Point;

    fn add(self, rhs: Self) -> Self::Output {
        SECP256K1.add(&self, &rhs)
    }
}

impl<'a, 'b, U> Add<&'a U> for Point
where
    U: Borrow<Point>,
{
    type Output = Point;

    fn add(self, rhs: &'a U) -> Self::Output {
        SECP256K1.add(&self, rhs.borrow())
    }
}

impl<'a, 'b, U> Add<&'a U> for &'b Point
where
    U: Borrow<Point>,
{
    type Output = Point;

    fn add(self, rhs: &'a U) -> Self::Output {
        SECP256K1.add(self, rhs.borrow())
    }
}

impl<'a> Mul<&'a Point> for BigInt {
    type Output = Point;

    fn mul(self, rhs: &Point) -> Self::Output {
        SECP256K1.multiply(rhs, &self)
    }
}

impl Mul<Point> for BigInt {
    type Output = Point;

    fn mul(self, rhs: Point) -> Self::Output {
        SECP256K1.multiply(&rhs, &self)
    }
}

impl Mul<BigInt> for Point {
    type Output = Point;

    fn mul(self, rhs: BigInt) -> Self::Output {
        SECP256K1.multiply(&self, &rhs)
    }
}

impl<'a> Mul<BigInt> for &'a Point {
    type Output = Point;

    fn mul(self, rhs: BigInt) -> Self::Output {
        SECP256K1.multiply(self, &rhs)
    }
}

#[derive(Debug)]
struct Curve {
    p: BigInt,
    a: BigInt,
    b: BigInt,
    gx: BigInt,
    gy: BigInt,
    n: BigInt,
}

/// Using mod_floor() instead of %
impl Curve {
    fn new(p: &str, a: &str, b: &str, gx: &str, gy: &str, n: &str) -> Self {
        Self {
            p: BigInt::from_str_radix(p, 16).unwrap(),
            a: BigInt::from_str_radix(a, 16).unwrap(),
            b: BigInt::from_str_radix(b, 16).unwrap(),
            gx: BigInt::from_str_radix(gx, 16).unwrap(),
            gy: BigInt::from_str_radix(gy, 16).unwrap(),
            n: BigInt::from_str_radix(n, 16).unwrap(),
        }
    }

    fn is_on_curve(&self, point: &Point) -> bool {
        let (x, y) = (&point.x, &point.y);
        ((y.pow(2) - x.pow(3) - &self.a * x - &self.b).mod_floor(&self.p)).is_zero()
    }

    fn add(&self, p: &Point, q: &Point) -> Point {
        // handle special case of P + 0 = 0 + P = 0
        if p.is_infinity() {
            q.clone()
        } else if q.is_infinity() {
            p.clone()
        // handle special case of P + (-P) = 0
        } else if p.x == q.x && p.y != q.y {
            Point::infinity()
        } else {
            // compute the scope
            let lambda = if p.x == q.x {
                // two points are same
                (BigInt::from(3u32) * &p.x.pow(2u32) + &self.a)
                    * inv(&(BigInt::from(2u32) * &p.y), &self.p)
            } else {
                // normal condition
                (&p.y - &q.y) * inv(&(&p.x - &q.x), &self.p)
            };
            let x = (&lambda.pow(2u32) - &p.x - &q.x).mod_floor(&self.p);
            let y = (&lambda * (&p.x - &x) - &p.y).mod_floor(&self.p);
            assert!(self.is_on_curve(&Point::new(x.clone(), y.clone())));
            Point::new(x, y)
        }
    }

    fn double(&self, p: &Point) -> Point {
        if p.is_infinity() {
            Point::infinity()
        } else {
            p + p
        }
    }

    fn multiply(&self, p: &Point, n: &BigInt) -> Point {
        let mut q = Point::infinity();
        let mut m = p.clone();
        for i in n.to_str_radix(2).chars().rev() {
            if i == '1' {
                q = self.add(&q, &m);
            }

            m = &m + &m;
        }
        q
    }
    fn generator(&self) -> Point {
        Point::new(self.gx.clone(), self.gy.clone())
    }
}
/// Returns (gcd, x, y) s.t. a * x + b * y == gcd
fn extended_eucidean_algorithm(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (a.clone(), b.clone());
    let (mut old_s, mut s) = (One::one(), Zero::zero());
    let (mut old_t, mut t) = (Zero::zero(), One::one());
    while !r.is_zero() {
        let quotient = &old_r / &r;
        let tmp_r = &old_r - &quotient * &r;
        old_r = r;
        r = tmp_r;
        let tmp_s = &old_s - &quotient * &s;
        old_s = s;
        s = tmp_s;
        let tmp_t = &old_t - &quotient * &t;
        old_t = t;
        t = tmp_t;
    }
    if old_r >= Zero::zero() {
        (old_r, old_s, old_t)
    } else {
        // (old_r, old_s, old_t)
        (-old_r, -old_s, -old_t)
    }
}

/// Returns modular multiplicate inverse m s.t. (n * m) % p == 1
fn inv(n: &BigInt, p: &BigInt) -> BigInt {
    // let (gcd, x, _) = extended_eucidean_algorithm(&n, &p);
    let ExtendedGcd { gcd, x, y } = n.extended_gcd(p);
    assert!(gcd.is_one());
    // let mut inverse = x % p;
    let mut inverse = x.mod_floor(p);

    inverse
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_valid() {
        let curve = &SECP256K1;
        let g = curve.generator();
        assert!(curve.is_on_curve(&g));
    }

    #[test]
    fn test_extended_eucidean_algorithm() {
        let test_cases = [
            (13, 17),
            (17, 123456789),
            (123456789, 987654321),
            (99999, 999),
            (105, 252),
            (2, 5),
        ];

        for (a, b) in test_cases {
            let a = BigInt::from(a);
            let b = BigInt::from(b);
            let (gcd, x, y) = extended_eucidean_algorithm(&a, &b);

            assert!((a.clone() % gcd.clone()).is_zero());
            assert!((b.clone() % gcd.clone()).is_zero());
            assert_eq!(x.clone() * a.clone() + y.clone() * b.clone(), gcd)
        }
    }

    #[test]
    fn test_inv() {
        let test_cases = [(13, 17), (2, 5)];
        for (n, p) in test_cases {
            let a = BigInt::from(n);
            let b = BigInt::from(p);

            let inverse = inv(&a, &b);
            assert_eq!((inverse * a) % b, BigInt::from(1));
        }
    }

    #[test]
    fn test_public_key_is_on_the_curve() {
        let g = SECP256K1.generator();
        let (pk1, pk2, pk3) = (&g + &g, &g + &g + &g, &g + &g + &g + &g);
        assert!(SECP256K1.is_on_curve(&pk1));
        assert!(SECP256K1.is_on_curve(&pk2));
        assert!(SECP256K1.is_on_curve(&pk3));
    }

    #[test]
    #[should_panic]
    fn test_add_invalid_point() {
        let g = SECP256K1.generator();
        g + &Point {
            x: One::one(),
            y: One::one(),
        };
    }

    #[test]
    fn test_multiply() {
        let g = SECP256K1.generator();

        assert_eq!(BigInt::from(2u32) * &g, &g + &g);
        assert_eq!(BigInt::from(3u32) * &g, &g + &g + &g);
        assert_eq!(&g * BigInt::from(4u32), &g + &g + &g + &g);
        assert_eq!(&g + &(BigInt::from(3u32) * &g), &g + &g + &g + &g);
        assert_eq!(
            BigInt::from(2u32) * (BigInt::from(2u32) * &g),
            &g + &g + &g + &g
        );
    }
}