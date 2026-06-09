use std::sync::atomic::{AtomicU64, Ordering};

pub struct ReadyByBits<'a, T, const CHUNK_SIZE: usize> {
    items: &'a mut [Option<T>],
    ready_bits: [u64; CHUNK_SIZE],
    current_chunk: usize,
}
impl<'a, T, const CHUNK_SIZE: usize> ReadyByBits<'a, T, CHUNK_SIZE> {
    const FULL_LENGTH: usize = CHUNK_SIZE * u64::BITS as usize;

    pub fn new(items: &'a mut [Option<T>], ready_bits: [u64; CHUNK_SIZE]) -> Self {
        assert_eq!(Self::FULL_LENGTH, items.len());

        ReadyByBits {
            items,
            ready_bits,
            current_chunk: 0,
        }
    }
}

impl<'a, T, const CHUNK_SIZE: usize> Iterator for ReadyByBits<'a, T, CHUNK_SIZE> {
    type Item = &'a mut T;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_chunk >= self.ready_bits.len() {
                return None;
            }
            let chunk_ready_bits = self.ready_bits[self.current_chunk];
            if chunk_ready_bits == 0 {
                self.current_chunk += 1;
                continue;
            }

            // Count the number of trailing zeros to get the index of the next ready index
            // This lets us skip strait to that ready index
            let next_ready = chunk_ready_bits.trailing_zeros() as usize;

            // We just need to reset that bit to zero now we are handling it
            self.ready_bits[self.current_chunk] &= chunk_ready_bits - 1;

            // Convert the local bit index into an absolute index for our Senders array
            let current = next_ready + (u64::BITS as usize * self.current_chunk);
            // Then remove the consumed count
            let current = current - (Self::FULL_LENGTH - self.items.len());

            // Somehow we were informed that a non-existent sender is ready
            if self.items[current].is_none() {
                continue;
            }

            // Grab a local copy of senders so we can split it up and get access to just the part containing the sender
            let local_copy = std::mem::take(&mut self.items);

            // Split the slice down to be just the item we care about, and everything after that
            // We need to adjust out bit index by the number of items we ahve already consumed
            let (_, rest) = local_copy.split_at_mut(current);

            // Split
            if let Some((item, rest)) = rest.split_first_mut() {
                // Return the remaining items to senders
                self.items = rest;

                return item.as_mut();
            }
        }
    }
}

pub trait IterReadyByBits<'a, T> {
    fn iter_by_ready_bits<const CHUNK_SIZE: usize>(
        &'a mut self,
        ready_bits: &[AtomicU64; CHUNK_SIZE],
    ) -> ReadyByBits<'a, T, CHUNK_SIZE>;
}

impl<'a, T> IterReadyByBits<'a, T> for [Option<T>] {
    fn iter_by_ready_bits<const CHUNK_SIZE: usize>(
        &'a mut self,
        ready_bits: &[AtomicU64; CHUNK_SIZE],
    ) -> ReadyByBits<'a, T, CHUNK_SIZE> {
        ReadyByBits::new(self, capture_and_reset_ready_atomic(ready_bits))
    }
}

fn capture_and_reset_ready_atomic<const SIZE: usize>(
    ready_bits: &[AtomicU64; SIZE],
) -> [u64; SIZE] {
    let mut result = [0u64; SIZE];
    for i in 0..SIZE {
        result[i] = ready_bits[i].swap(0, Ordering::Acquire);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// Helper to generate a slice of options populated with their own indices
    fn create_test_items(size: usize) -> Vec<Option<usize>> {
        (0..size).map(Some).collect()
    }

    #[test]
    fn test_all_inputs_not_ready() {
        const CHUNK_SIZE: usize = 1;
        let mut items = create_test_items(CHUNK_SIZE * 64);
        let ready_bits = [0u64; CHUNK_SIZE];

        let mut iter = ReadyByBits::new(&mut items, ready_bits);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_very_first_item_ready() {
        const CHUNK_SIZE: usize = 1;
        let mut items = create_test_items(CHUNK_SIZE * 64);
        // Bit 0 set (index 0)
        let ready_bits = [1u64; CHUNK_SIZE];

        let mut iter = ReadyByBits::new(&mut items, ready_bits);

        assert_eq!(iter.next(), Some(&mut 0));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_very_last_item_ready() {
        const CHUNK_SIZE: usize = 2;
        let mut items = create_test_items(CHUNK_SIZE * 64); // 128 items

        // Set only the 63rd bit of the 2nd chunk (Absolute index 127)
        let mut ready_bits = [0u64; CHUNK_SIZE];
        ready_bits[1] = 1u64 << 63;

        let mut iter = ReadyByBits::new(&mut items, ready_bits);

        assert_eq!(iter.next(), Some(&mut 127));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_single_item_in_multiple_chunks() {
        const CHUNK_SIZE: usize = 3;
        let mut items = create_test_items(CHUNK_SIZE * 64); // 192 items

        let mut ready_bits = [0u64; CHUNK_SIZE];
        ready_bits[0] = 1u64 << 5; // Index 5
        ready_bits[1] = 1u64 << 10; // Index 64 + 10 = 74
        ready_bits[2] = 1u64 << 0; // Index 128 + 0 = 128

        let mut iter = ReadyByBits::new(&mut items, ready_bits);

        assert_eq!(iter.next(), Some(&mut 5));
        assert_eq!(iter.next(), Some(&mut 74));
        assert_eq!(iter.next(), Some(&mut 128));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_multiple_items_in_single_chunk() {
        const CHUNK_SIZE: usize = 1;
        let mut items = create_test_items(CHUNK_SIZE * 64);

        // Set bits 2, 3, and 5 (Binary: ...00101100 = 44)
        let ready_bits = [44u64; CHUNK_SIZE];

        let mut iter = ReadyByBits::new(&mut items, ready_bits);

        assert_eq!(iter.next(), Some(&mut 2));
        assert_eq!(iter.next(), Some(&mut 3));
        assert_eq!(iter.next(), Some(&mut 5));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_spurious_readiness_skipped() {
        const CHUNK_SIZE: usize = 1;
        let mut items = create_test_items(CHUNK_SIZE * 64);

        // Simulate a closed/dropped connection or spurious wake:
        // Mark index 2 as None even though the bitmask says it's ready.
        items[2] = None;

        // Bits 2 and 4 set
        let ready_bits = [(1u64 << 2) | (1u64 << 4)];

        let mut iter = ReadyByBits::new(&mut items, ready_bits);

        // Index 2 should be skipped entirely, immediately proceeding to index 4
        assert_eq!(iter.next(), Some(&mut 4));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_completely_full_chunks() {
        const CHUNK_SIZE: usize = 2;
        let mut items = create_test_items(CHUNK_SIZE * 64);

        // Every single bit is set across both chunks (128 items total)
        let ready_bits = [u64::MAX; CHUNK_SIZE];

        let mut iter = ReadyByBits::new(&mut items, ready_bits);

        for mut expected_idx in 0..128 {
            assert_eq!(iter.next(), Some(&mut expected_idx));
        }
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_integration_with_atomic_trait() {
        // Verification test ensuring the trait implementation works with atomic swaps
        let mut items = create_test_items(64);
        let atomics = [AtomicU64::new((1 << 1) | (1 << 10))];

        // Use the trait on the slice directly
        let mut iter = items.iter_by_ready_bits(&atomics);

        assert_eq!(iter.next(), Some(&mut 1));
        assert_eq!(iter.next(), Some(&mut 10));
        assert!(iter.next().is_none());

        // Verify the atomic was cleared by the swap operation
        assert_eq!(atomics[0].load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn test_input_collection_unaffected_and_retains_all_elements() {
        const CHUNK_SIZE: usize = 1;
        // Create a collection of 64 items: [Some(0), Some(1), ..., Some(63)]
        let mut original_items = create_test_items(CHUNK_SIZE * 64);
        let atomics = [AtomicU64::new((1 << 2) | (1 << 5))];

        // Scope block to control the lifetime of the iterator borrow
        {
            let mut iter = original_items.iter_by_ready_bits(&atomics);

            // Pull the ready items out and mutate them to prove we have real access
            if let Some(item) = iter.next() {
                *item = 999; // Modify index 2
            }
            if let Some(item) = iter.next() {
                *item = 888; // Modify index 5
            }
            assert!(iter.next().is_none());
        } // Iterator is dropped here, releasing the mutable borrow on `original_items`

        // --- VERIFICATION ---
        // 1. The total length of the caller's collection is completely unchanged
        assert_eq!(original_items.len(), 64);

        // 2. Unvisited elements are completely intact and in their original positions
        assert_eq!(original_items[0], Some(0));
        assert_eq!(original_items[1], Some(1));
        assert_eq!(original_items[3], Some(3));
        assert_eq!(original_items[4], Some(4));
        assert_eq!(original_items[63], Some(63));

        // 3. Elements we retrieved and mutated are successfully modified in place
        assert_eq!(original_items[2], Some(999));
        assert_eq!(original_items[5], Some(888));
    }

    #[test]
    fn test_partial_iteration_leaves_remaining_collection_intact() {
        const CHUNK_SIZE: usize = 1;
        let mut original_items = create_test_items(CHUNK_SIZE * 64);
        let atomics = [AtomicU64::new((1 << 1) | (1 << 10) | (1 << 20))];

        {
            let mut iter = original_items.iter_by_ready_bits(&atomics);

            // We only pull ONE item out and abandon the iterator early
            let first_ready = iter.next();
            assert_eq!(first_ready, Some(&mut 1));
        } // Iterator gets dropped prematurely

        // --- VERIFICATION ---
        // Even though the iterator was mid-flight and slicing things up internally,
        // the underlying collection is perfectly preserved when the borrow ends.
        assert_eq!(original_items.len(), 64);
        assert_eq!(original_items[0], Some(0));
        assert_eq!(original_items[1], Some(1));
        assert_eq!(original_items[10], Some(10)); // Bit was flagged, but item is still safe
        assert_eq!(original_items[20], Some(20)); // Bit was flagged, but item is still safe
    }
}
