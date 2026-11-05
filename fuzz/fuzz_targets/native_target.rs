//! Any D-Bus client picks an item's attributes. Distinct attributes must name distinct
//! credentials even to the Credential Manager, which compares targets regardless of case, and
//! listing a credential must give back the attributes it was stored under.

#![no_main]

use credrelay_client::fuzzing::{Attributes, NATIVE_PREFIX, Native, Scheme};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|pair: (Attributes, Attributes)| {
    let (first, second) = pair;
    let scheme = Native::default();
    let stored = scheme.credential(&first).expect("native claims every item");
    let other = scheme.credential(&second).expect("native claims every item");

    assert_eq!(scheme.attributes(&stored).as_ref(), Some(&first));
    assert_eq!(
        first == second,
        stored.target.eq_ignore_ascii_case(&other.target),
        "{:?} and {:?}",
        stored.target,
        other.target
    );
    let encoded = &stored.target[NATIVE_PREFIX.len()..];
    assert!(!encoded.contains(['=', ':']), "{encoded:?}");
});
