use der::Enumerated;

///
/// ```der
/// Root ::= ENUMERATED {root    (0),
//                       timestamp   (1),
//                       snapshot   (2),
//                       target (3)}
/// ```
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Root = 0,
    Timestamp = 1,
    Snapshot = 2,
    Target = 3,
}
