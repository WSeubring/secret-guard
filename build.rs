//! Precompiles the context-rule patterns into dense DFAs so the hook never compiles a regex that cannot match.

use regex_automata::dfa::dense;
use regex_automata::util::syntax;
use std::fmt::Write;
use std::path::PathBuf;

include!("src/patterns.rs");

fn main() {
    println!("cargo::rerun-if-changed=src/patterns.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let mut code = String::from("pub static GATES: &[(&str, &Aligned<[u8]>)] = &[\n");
    for (id, pattern) in GATED {
        let dfa = dense::Builder::new()
            .syntax(syntax::Config::new().unicode(false).utf8(false))
            .configure(dense::Config::new().minimize(true))
            .build(pattern)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        let (buf, pad) = dfa.to_bytes_little_endian();
        std::fs::write(out.join(format!("{id}.dfa")), &buf[pad..]).unwrap();
        writeln!(code, "    ({id:?}, &Aligned(*include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{id}.dfa\")))),").unwrap();
    }
    code.push_str("];\n");
    std::fs::write(out.join("gates.rs"), code).unwrap();
}
