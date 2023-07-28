//! The `weighted_shuffle` module provides an iterator over shuffled weights.

use {
    itertools::Itertools,
    num_traits::{CheckedAdd, FromPrimitive, ToPrimitive},
    rand::{
        distributions::uniform::{SampleUniform, UniformSampler},
        Rng, SeedableRng,
    },
    rand_chacha::ChaChaRng,
    std::{
        borrow::Borrow,
        iter,
        ops::{AddAssign, Div, Sub, SubAssign},
    },
};

/// Implements an iterator where indices are shuffled according to their
/// weights:
///   - Returned indices are unique in the range [0, weights.len()).
///   - Higher weighted indices tend to appear earlier proportional to their
///     weight.
///   - Zero weighted indices are shuffled and appear only at the end, after
///     non-zero weighted indices.
#[derive(Clone)]
pub struct WeightedShuffle<T> {
    arr: Vec<T>,       // Underlying array implementing binary indexed tree.
    sum: T,            // Current sum of weights, excluding already selected indices.
    zeros: Vec<usize>, // Indices of zero weighted entries.
}

// The implementation uses binary indexed tree:
// https://en.wikipedia.org/wiki/Fenwick_tree
// to maintain cumulative sum of weights excluding already selected indices
// over self.arr.
impl<T> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + CheckedAdd,
{
    /// If weights are negative or overflow the total sum
    /// they are treated as zero.
    pub fn new(name: &'static str, weights: &[T]) -> Self {
        let size = weights.len() + 1;
        let zero = <T as Default>::default();
        let mut arr = vec![zero; size];
        let mut sum = zero;
        let mut zeros = Vec::default();
        let mut num_negative = 0;
        let mut num_overflow = 0;
        for (mut k, &weight) in (1usize..).zip(weights) {
            #[allow(clippy::neg_cmp_op_on_partial_ord)]
            // weight < zero does not work for NaNs.
            if !(weight >= zero) {
                zeros.push(k - 1);
                num_negative += 1;
                continue;
            }
            if weight == zero {
                zeros.push(k - 1);
                continue;
            }
            sum = match sum.checked_add(&weight) {
                Some(val) => val,
                None => {
                    zeros.push(k - 1);
                    num_overflow += 1;
                    continue;
                }
            };
            while k < size {
                arr[k] += weight;
                k += k & k.wrapping_neg();
            }
        }
        if num_negative > 0 {
            datapoint_error!("weighted-shuffle-negative", (name, num_negative, i64));
        }
        if num_overflow > 0 {
            datapoint_error!("weighted-shuffle-overflow", (name, num_overflow, i64));
        }
        Self { arr, sum, zeros }
    }
}

impl<T> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + SubAssign + Sub<Output = T>,
{
    // Returns cumulative sum of current weights upto index k (inclusive).
    fn cumsum(&self, mut k: usize) -> T {
        let mut out = <T as Default>::default();
        while k != 0 {
            out += self.arr[k];
            k ^= k & k.wrapping_neg();
        }
        out
    }

    // Removes given weight at index k.
    fn remove(&mut self, mut k: usize, weight: T) {
        self.sum -= weight;
        let size = self.arr.len();
        while k < size {
            self.arr[k] -= weight;
            k += k & k.wrapping_neg();
        }
    }

    // Returns smallest index such that self.cumsum(k) > val,
    // along with its respective weight.
    fn search(&self, val: T) -> (/*index:*/ usize, /*weight:*/ T) {
        let zero = <T as Default>::default();
        debug_assert!(val >= zero);
        debug_assert!(val < self.sum);
        let mut lo = (/*index:*/ 0, /*cumsum:*/ zero);
        let mut hi = (self.arr.len() - 1, self.sum);
        while lo.0 + 1 < hi.0 {
            let k = lo.0 + (hi.0 - lo.0) / 2;
            let sum = self.cumsum(k);
            if sum <= val {
                lo = (k, sum);
            } else {
                hi = (k, sum);
            }
        }
        debug_assert!(lo.1 <= val);
        debug_assert!(hi.1 > val);
        (hi.0, hi.1 - lo.1)
    }

    pub fn remove_index(&mut self, index: usize) {
        let zero = <T as Default>::default();
        let weight = self.cumsum(index + 1) - self.cumsum(index);
        if weight != zero {
            self.remove(index + 1, weight);
        } else if let Some(index) = self.zeros.iter().position(|ix| *ix == index) {
            self.zeros.remove(index);
        }
    }
}

impl<T> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + SampleUniform + SubAssign + Sub<Output = T>,
{
    // Equivalent to weighted_shuffle.shuffle(&mut rng).next()
    pub fn first<R: Rng>(&self, rng: &mut R) -> Option<usize> {
        let zero = <T as Default>::default();
        if self.sum > zero {
            let sample = <T as SampleUniform>::Sampler::sample_single(zero, self.sum, rng);
            let (index, _weight) = WeightedShuffle::search(self, sample);
            return Some(index - 1);
        }
        if self.zeros.is_empty() {
            return None;
        }
        let index = <usize as SampleUniform>::Sampler::sample_single(0usize, self.zeros.len(), rng);
        self.zeros.get(index).copied()
    }
}

impl<'a, T: 'a> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + SampleUniform + SubAssign + Sub<Output = T>,
{
    pub fn shuffle<R: Rng>(mut self, rng: &'a mut R) -> impl Iterator<Item = usize> + 'a {
        std::iter::from_fn(move || {
            let zero = <T as Default>::default();
            if self.sum > zero {
                let sample = <T as SampleUniform>::Sampler::sample_single(zero, self.sum, rng);
                let (index, weight) = WeightedShuffle::search(&self, sample);
                self.remove(index, weight);
                return Some(index - 1);
            }
            if self.zeros.is_empty() {
                return None;
            }
            let index =
                <usize as SampleUniform>::Sampler::sample_single(0usize, self.zeros.len(), rng);
            Some(self.zeros.swap_remove(index))
        })
    }
}

/// Returns a list of indexes shuffled based on the input weights
/// Note - The sum of all weights must not exceed `u64::MAX`
pub fn weighted_shuffle<T, B, F>(weights: F, seed: [u8; 32]) -> Vec<usize>
where
    T: Copy + PartialOrd + iter::Sum + Div<T, Output = T> + FromPrimitive + ToPrimitive,
    B: Borrow<T>,
    F: Iterator<Item = B> + Clone,
{
    let total_weight: T = weights.clone().map(|x| *x.borrow()).sum();
    let mut rng = ChaChaRng::from_seed(seed);
    weights
        .enumerate()
        .map(|(i, weight)| {
            let weight = weight.borrow();
            // This generates an "inverse" weight but it avoids floating point math
            let x = (total_weight / *weight)
                .to_u64()
                .expect("values > u64::max are not supported");
            (
                i,
                // capture the u64 into u128s to prevent overflow
                rng.gen_range(1, u128::from(std::u16::MAX)) * u128::from(x),
            )
        })
        // sort in ascending order
        .sorted_by(|(_, l_val), (_, r_val)| l_val.cmp(r_val))
        .map(|x| x.0)
        .collect()
}

/// Returns the highest index after computing a weighted shuffle.
/// Saves doing any sorting for O(n) max calculation.
// TODO: Remove in favor of rand::distributions::WeightedIndex.
pub fn weighted_best(weights_and_indexes: &[(u64, usize)], seed: [u8; 32]) -> usize {
    if weights_and_indexes.is_empty() {
        return 0;
    }
    let mut rng = ChaChaRng::from_seed(seed);
    let total_weight: u64 = weights_and_indexes.iter().map(|x| x.0).sum();
    let mut lowest_weight = std::u128::MAX;
    let mut best_index = 0;
    for v in weights_and_indexes {
        // This generates an "inverse" weight but it avoids floating point math
        let x = (total_weight / v.0)
            .to_u64()
            .expect("values > u64::max are not supported");
        // capture the u64 into u128s to prevent overflow
        let computed_weight = rng.gen_range(1, u128::from(std::u16::MAX)) * u128::from(x);
        // The highest input weight maps to the lowest computed weight
        if computed_weight < lowest_weight {
            lowest_weight = computed_weight;
            best_index = v.1;
        }
    }

    best_index
}